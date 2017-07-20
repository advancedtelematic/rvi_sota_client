use chrono::{DateTime, Utc};
use json;
use std::fs::{self, File};
use std::io::{BufReader, ErrorKind};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::time::Duration;
use net2::{UdpBuilder, UdpSocketExt};
use net2::unix::UnixUdpBuilderExt;
use uuid::Uuid;

use datatype::{Error, TufSigned, Util};
use images::{ImageReader, ImageWriter};


const BUFFER_SIZE: usize = 64*1024;

lazy_static! {
    static ref VALID_TRANSITIONS: HashMap<State, Vec<State>> = hashmap! {
        State::Idle   => vec![State::Ready],
        State::Ready  => vec![State::Abort, State::Ready, State::Verify],
        State::Verify => vec![State::Abort, State::Verify, State::Fetch],
        State::Fetch  => vec![State::Abort, State::Fetch, State::Commit],
        State::Commit => vec![State::Abort],
        State::Abort  => vec![],
    };
}


/// Define the interface for communication between `Primary` and `Secondary` ECUs.
pub trait Bus: Send {
    fn read_wake_up(&mut self) -> Result<(String, Uuid), Error>;
    fn write_wake_up(&self, serial: String, txid: Uuid) -> Result<(), Error>;

    fn read_message(&mut self) -> Result<Message, Error>;
    fn write_message(&self, msg: &Message) -> Result<(), Error>;
}

/// Define the interface for transitioning a `Secondary` to the next state.
pub trait Step: Send {
    fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error>;
}


/// All possible states for a `Primary` or `Secondary`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Idle,
    Ready,
    Verify,
    Fetch,
    Commit,
    Abort,
}

/// A `Bus` message to be picked up by either a `Primary` or a `Secondary`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    Next { txid: Uuid, serial: String, state: State, payload: Option<Payload> },
    Ack  { txid: Uuid, serial: String, state: State, report: Option<TufSigned> },

    Req  { txid: Uuid, serial: String, image: String, index: u64 },
    Resp { txid: Uuid, serial: String, image: String, index: u64, chunk: Vec<u8> },
}

/// A fallback manifest per ECU that will be sent in case of a timeout.
pub type Manifests = HashMap<String, TufSigned>;

/// A mapping from serials to the payloads to be delivered at each state.
pub type Payloads = HashMap<String, HashMap<State, Payload>>;

/// Data that may be delivered to a `Secondary` before executing state transition.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Payload {
    Blob(Vec<u8>),
    ImageMeta(Vec<u8>),
    OstreePackage(Vec<u8>),
    UptaneMetadata(Vec<u8>),
}

impl Payload {
    pub fn len(&self) -> usize {
        match *self {
            Payload::Blob(ref bytes) => bytes.len(),
            Payload::ImageMeta(ref bytes) => bytes.len(),
            Payload::OstreePackage(ref bytes) => bytes.len(),
            Payload::UptaneMetadata(ref bytes) => bytes.len(),
        }
    }
}

/// Data that may be passed to a `Secondary` following a state transition.
pub enum StepData {
    ImageWriter(ImageWriter),
    TufReport(TufSigned),
}


/// A `Primary` is responsible for coordinating state changes with all
/// `Secondary` ECUs referenced in the payload data.
#[derive(Serialize, Deserialize)]
pub struct Primary {
    txid:  Uuid,
    state: State,

    payloads:  Payloads,
    images:    HashMap<String, ImageReader>,
    manifests: Manifests,

    acks:    HashMap<State, HashSet<String>>,
    started: DateTime<Utc>,
    timeout: Duration,
    recover: Option<String>,
    signed:  HashMap<String, TufSigned>,

    #[serde(skip_serializing, skip_deserializing)]
    bus: Option<Box<Bus>>,
}

impl Primary {
    /// Create a new `Primary` that will wake up the transactional secondaries.
    pub fn new(payloads:  Payloads,
               images:    HashMap<String, ImageReader>,
               manifests: HashMap<String, TufSigned>,
               bus:       Box<Bus>,
               timeout:   Duration,
               recover:   Option<String>) -> Self {
        Primary {
            txid:  Uuid::new_v4(),
            state: State::Idle,

            payloads:  payloads,
            images:    images,
            manifests: manifests,

            acks: hashmap! {
                State::Ready  => HashSet::new(),
                State::Verify => HashSet::new(),
                State::Fetch  => HashSet::new(),
                State::Commit => HashSet::new(),
                State::Abort  => HashSet::new(),
            },
            started: Utc::now(),
            timeout: timeout,
            recover: recover,
            signed:  HashMap::new(),

            bus: Some(bus),
        }
    }

    /// Recover from a crash by requesting an update on missing `Secondary` acks.
    pub fn recover<P: AsRef<Path>>(path: P, bus: Box<Bus>) -> Result<Self, Error> {
        let mut primary: Primary = json::from_reader(BufReader::new(File::open(&path)?))?;
        info!("Primary state recovered from `{}`", path.as_ref().display());
        primary.bus = Some(bus);
        primary.started = Utc::now();
        primary.send_request(primary.state)?;
        Ok(primary)
    }

    /// Ensure each `Secondary` is awake then execute the three-phase commit process.
    pub fn commit(&mut self) -> Result<(), Error> {
        self.transition(State::Ready)?;
        self.transition(State::Verify)?;
        self.transition(State::Fetch)?;
        self.transition(State::Commit)?;
        info!("Transaction {} complete.", self.txid);
        if let Some(ref path) = self.recover { let _ = fs::remove_file(path); }

        if self.aborted().len() > 0 {
            Err(Error::AtomicAbort(format!("Secondary aborts: {:?}", self.aborted())))
        } else if self.committed().len() < self.payloads.len() {
            Err(Error::AtomicTimeout)
        } else {
            Ok(())
        }
    }

    /// A list of all acknowledged `Secondary` commits.
    pub fn committed(&self) -> &HashSet<String> {
        self.acks.get(&State::Commit).expect("commit acks")
    }

    /// A list of all acknowledged `Secondary` aborts.
    pub fn aborted(&self) -> &HashSet<String> {
        self.acks.get(&State::Abort).expect("abort acks")
    }

    /// Convert the completed transaction into a list of signed ECU reports.
    pub fn into_signed(mut self) -> Vec<TufSigned> {
        let mut signed = Vec::new();
        for (serial, _) in &self.payloads {
            self.signed
                .remove(serial)
                .or_else(|| self.manifests.get(serial).cloned())
                .map(|report| signed.push(report));
        }
        signed
    }

    /// Transition all secondaries to the next state.
    fn transition(&mut self, state: State) -> Result<(), Error> {
        if ! is_valid(self.state, state) { return Ok(()) }
        info!("Transaction {} moving to {:?}.", self.txid, state);
        self.checkpoint(state)?;
        self.send_request(state)?;

        while self.state == state && self.acks(state).len() < self.payloads.len() {
            self.read_message()
                .and_then(|msg| match msg {
                    Message::Ack { txid, serial, state, report } => {
                        if txid != self.txid { return Ok(()) }
                        debug!("ack from {}: {:?}", serial, state);
                        let _ = self.acks.get_mut(&state).expect("acks").insert(serial.clone());
                        if let Some(signed) = report { self.signed.insert(serial.clone(), signed); }
                        if state == State::Abort && ! is_terminal(self.state) {
                            self.transition(State::Abort)?;
                            Err(Error::AtomicAbort(serial))
                        } else {
                            Ok(())
                        }
                    }

                    Message::Req { txid, serial, image, index } => {
                        if txid != self.txid { return Ok(()) }
                        debug!("request from {} for {} chunk {}", serial, image, index);
                        let chunk = self.images.get_mut(&image)
                            .ok_or_else(|| Error::Image(format!("not found: {}", image)))
                            .and_then(|reader| reader.read_chunk(index))?.into();
                        self.write_message(&Message::Resp {
                            txid: txid,
                            serial: serial,
                            image: image,
                            index: index,
                            chunk: chunk,
                        })
                    }
                    _ => Ok(())
                })
                .or_else(|err| {
                    if ! is_waiting(&err) {
                        let _ = self.transition(State::Abort);
                        Err(err)
                    } else if self.is_timeout() {
                        Err(Error::AtomicTimeout)
                    } else {
                        self.send_request(self.state)
                    }
                })?;
        }
        Ok(())
    }

    fn checkpoint(&mut self, state: State) -> Result<(), Error> {
        self.started = Utc::now();
        self.state = state;
        if let Some(ref path) = self.recover {
            Util::write_file(path, &json::to_vec(self)?)?;
        }
        Ok(())
    }

    fn send_request(&self, state: State) -> Result<(), Error> {
        for (serial, states) in &self.payloads {
            if state == State::Ready {
                self.bus.as_ref().expect("bus").write_wake_up(serial.clone(), self.txid)?;
            } else if self.acks(state).get(serial).is_none() {
                self.write_message(&Message::Next {
                    txid:    self.txid,
                    serial:  serial.clone(),
                    state:   state,
                    payload: states.get(&state).cloned()
                })?;
            }
        }
        Ok(())
    }

    fn acks(&self, state: State) -> &HashSet<String> {
        self.acks.get(&state).expect("acks")
    }

    fn is_timeout(&self) -> bool {
        Utc::now().signed_duration_since(self.started).to_std().expect("duration") > self.timeout
    }

    fn read_message(&mut self) -> Result<Message, Error> {
        self.bus.as_mut().expect("bus").read_message()
    }

    fn write_message(&self, msg: &Message) -> Result<(), Error> {
        //FIXME: udp/tcp buffer sizes
        self.bus.as_ref().expect("bus").write_message(msg)
    }
}


/// A `Secondary` awaits instructions from a `Primary` to transition between states.
#[derive(Serialize, Deserialize)]
pub struct Secondary {
    txid:   Option<Uuid>,
    serial: String,
    state:  State,
    next:   State,

    started: DateTime<Utc>,
    timeout: Duration,
    recover: Option<String>,
    payload: Option<Payload>,
    writers: HashMap<String, ImageWriter>,
    report:  Option<TufSigned>,

    #[serde(skip_serializing, skip_deserializing)]
    bus: Option<Box<Bus>>,
    #[serde(skip_serializing, skip_deserializing)]
    step: Option<Box<Step>>,
}

impl Secondary {
    /// Create a `Secondary` that listens on the bus for state transitions messages.
    pub fn new(serial: String, bus: Box<Bus>, step: Box<Step>, timeout: Duration, recover: Option<String>)
               -> Self
    {
        Secondary {
            txid:   None,
            serial: serial,
            state:  State::Idle,
            next:   State::Idle,

            started: Utc::now(),
            timeout: timeout,
            recover: recover,
            payload: None,
            writers: HashMap::new(),
            report:  None,

            bus: Some(bus),
            step: Some(step),
        }
    }

    /// Recover from a crash while a transaction was in progress.
    pub fn recover<P: AsRef<Path>>(path: P, bus: Box<Bus>, step: Box<Step>) -> Result<Self, Error> {
        let mut follower: Secondary = json::from_reader(BufReader::new(File::open(&path)?))?;
        info!("Secondary `{}` state recovered from `{}`", follower.serial, path.as_ref().display());
        follower.bus = Some(bus);
        follower.step = Some(step);
        follower.started = Utc::now();
        Ok(follower)
    }

    /// Block until a wake-up signal is received then read new transaction
    /// messages until we reach a terminating state or time-out.
    pub fn listen(&mut self) -> Result<(), Error> {
        info!("Starting a Secondary ECU listener for serial `{}`", self.serial);
        while self.state == State::Idle {
            self.read_wake_up()
                .and_then(|(serial, txid)| {
                    if serial != self.serial { return Ok(()) }
                    self.txid = Some(txid);
                    self.transition(State::Ready, None)
                })
                .or_else(|err| if is_waiting(&err) { Ok(()) } else { Err(err) })?
        }

        while ! is_terminal(self.state) {
            self.read_message()
                .and_then(|msg| match msg {
                    Message::Next { txid, serial, state, payload } => {
                        if txid != self.txid() || serial != self.serial { return Ok(()) }
                        self.transition(state, payload)
                    }

                    Message::Resp { txid, serial, image, index, chunk } => {
                        if txid != self.txid() || serial != self.serial { return Ok(()) }
                        let next_index = self.writers.get_mut(&image)
                            .ok_or_else(|| Error::Image(format!("writer not found: {}", image)))
                            .and_then(|writer| {
                                writer.write_chunk(&chunk, index)?;
                                if writer.is_complete() {
                                    Ok(writer.assemble_chunks().map(|_| None)?)
                                } else {
                                    Ok(Some(index+1))
                                }
                            })?;
                        if let Some(index) = next_index {
                            self.request_chunk(image, index)
                        } else {
                            self.state = self.next;
                            self.write_ack()
                        }
                    }
                    _ => Ok(())
                })
                .or_else(|err| {
                    if ! is_waiting(&err) {
                        self.transition(State::Abort, None)?;
                        Err(err)
                    } else if self.is_timeout() && ! is_terminal(self.state) {
                        self.transition(State::Abort, None)?;
                        Err(Error::AtomicTimeout)
                    } else {
                        Ok(())
                    }
                })?;
        }

        if let Some(ref path) = self.recover { fs::remove_file(path)?; }
        if self.state == State::Abort {
            Err(Error::AtomicAbort(format!("{}", self.serial)))
        } else {
            Ok(())
        }
    }

    fn transition(&mut self, state: State, payload: Option<Payload>) -> Result<(), Error> {
        if self.state == state {
            return self.write_ack();
        } else if ! is_valid(self.state, state) {
            return Err(Error::AtomicState(self.state, state));
        }

        debug!("serial {} moving to {:?}", self.serial, state);
        self.checkpoint(state, payload.clone())?;
        self.step(state, payload)
            .map(|step_data| {
                let step_done = match step_data {
                    None => true,
                    Some(StepData::ImageWriter(writer)) => {
                        if let None = self.writers.get(&writer.meta.image_name) {
                            let image = writer.meta.image_name.clone();
                            let _ = self.writers.insert(image.clone(), writer);
                            let _ = self.request_chunk(image, 0);
                        }
                        false
                    }
                    Some(StepData::TufReport(report)) => {
                        self.report = Some(report);
                        true
                    }
                };
                if step_done {
                    self.state = self.next;
                    let _ = self.write_ack();
                }
            })
            .map_err(|err| {
                error!("serial {}: {}", self.serial, err);
                let _ = self.transition(State::Abort, None);
                Error::AtomicAbort(err.to_string())
            })
    }

    fn checkpoint(&mut self, state: State, payload: Option<Payload>) -> Result<(), Error> {
        self.started = Utc::now();
        self.next = state;
        self.payload = payload;
        if let Some(ref path) = self.recover {
            Util::write_file(path, &json::to_vec(self)?)?;
        }
        Ok(())
    }

    fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
        self.step.as_mut().expect("step").step(state, payload)
    }

    fn txid(&self) -> Uuid {
        self.txid.expect("txid")
    }

    fn is_timeout(&self) -> bool {
        Utc::now().signed_duration_since(self.started).to_std().expect("duration") > self.timeout
    }

    fn read_wake_up(&mut self) -> Result<(String, Uuid), Error> {
        self.bus.as_mut().expect("bus").read_wake_up()
    }

    fn read_message(&mut self) -> Result<Message, Error> {
        self.bus.as_mut().expect("bus").read_message()
    }

    fn write_message(&self, msg: &Message) -> Result<(), Error> {
        self.bus.as_ref().expect("bus").write_message(msg)
    }

    fn request_chunk(&self, image: String, index: u64) -> Result<(), Error> {
        self.write_message(&Message::Req  {
            txid: self.txid(),
            serial: self.serial.clone(),
            image: image,
            index: index,
        })
    }

    fn write_ack(&self) -> Result<(), Error> {
        if let None = self.report {
            if is_terminal(self.state) { return Err(Error::AtomicSigned); }
        }

        self.write_message(&Message::Ack {
            txid: self.txid(),
            serial: self.serial.clone(),
            state: self.state,
            report: self.report.clone()
        })
    }
}

fn is_valid(from: State, to: State) -> bool {
    VALID_TRANSITIONS.get(&from).expect("transitions").contains(&to)
}

fn is_terminal(state: State) -> bool {
    match state {
        State::Commit | State::Abort => true,
        _ => false
    }
}

fn is_waiting(err: &Error) -> bool {
    match *err {
        Error::Io(ref err) if err.kind() == ErrorKind::TimedOut => true,
        Error::Io(ref err) if err.kind() == ErrorKind::WouldBlock => true,
        _ => false
    }
}


/// Listens for and sends UDP multicast messages.
pub struct Multicast {
    wake_up: UdpSocket,
    message: UdpSocket,
    wake_addr: SocketAddrV4,
    msg_addr:  SocketAddrV4,
    msg_buf: [u8; BUFFER_SIZE],
}

impl Multicast {
    pub fn new(wake_addr: SocketAddrV4, msg_addr: SocketAddrV4) -> Result<Self, Error> {
        Ok(Multicast {
            wake_up: Multicast::new_socket(wake_addr)?,
            message: Multicast::new_socket(msg_addr)?,
            wake_addr: wake_addr,
            msg_addr: msg_addr,
            msg_buf: [0; BUFFER_SIZE],
        })
    }

    fn new_socket(addr: SocketAddrV4) -> Result<UdpSocket, Error> {
        let any = Ipv4Addr::new(0,0,0,0);
        let socket = UdpBuilder::new_v4()?
            .reuse_address(true)?
            .reuse_port(true)?
            .bind((any, addr.port()))?;
        socket.set_broadcast(true)?;
        socket.set_send_buffer_size(BUFFER_SIZE)?;
        socket.set_recv_buffer_size(BUFFER_SIZE)?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        socket.join_multicast_v4(&addr.ip(), &any)?;
        Ok(socket)
    }
}


impl Bus for Multicast {
    fn read_wake_up(&mut self) -> Result<(String, Uuid), Error> {
        let (len, _) = self.wake_up.recv_from(&mut self.msg_buf).map_err(Error::Io)?;
        trace!("received wake_up: {:?}", &self.msg_buf[..len]);
        Ok(json::from_slice(&self.msg_buf[..len])?)
    }

    fn write_wake_up(&self, serial: String, txid: Uuid) -> Result<(), Error> {
        trace!("writing wake_up: ({}, {})", serial, txid);
        let _ = self.wake_up.send_to(&json::to_vec(&(serial, txid))?, self.wake_addr)?;
        Ok(())
    }

    fn read_message(&mut self) -> Result<Message, Error> {
        let (len, _) = self.message.recv_from(&mut self.msg_buf).map_err(Error::Io)?;
        trace!("received message: {:?}", &self.msg_buf[..len]);
        Ok(json::from_slice(&self.msg_buf[..len])?)
    }

    fn write_message(&self, msg: &Message) -> Result<(), Error> {
        trace!("writing message: {:?}", msg);
        let _ = self.message.send_to(&json::to_vec(msg)?, self.msg_addr)?;
        Ok(())
    }
}


#[cfg(all(test, not(feature = "docker")))]
mod tests {
    use super::*;
    use base64;
    use ring::rand::SystemRandom;
    use std::{panic, thread};
    use time;

    use datatype::{PrivateKey, SignatureType};


    lazy_static! {
        static ref PRIVATE_KEY: PrivateKey = PrivateKey {
            keyid: "keyid".into(),
            der_key: base64::decode("0wm+qYNKH2v7VUMy0lEz0ZfOEtEbdbDNwklW5PPLs4WpCLVDpXuapnO3XZQ9i1wV3aiIxi1b5TxVeVeulbyUyw==").expect("pri_key")
        };
    }

    fn step_data(state: State) -> Option<StepData> {
        if is_terminal(state) {
            let report = PRIVATE_KEY.sign_data(json::from_str("{}").expect("json"), SignatureType::Ed25519).expect("signed");
            Some(StepData::TufReport(report))
        } else {
            None
        }
    }


    struct Success;
    impl Step for Success {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            Ok(step_data(state))
        }
    }

    struct VerifyPayload;
    impl Step for VerifyPayload {
        fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
            match (state, payload) {
                (State::Verify, Some(Payload::Blob(ref b))) if b == b"verify payload" => Ok(None),
                (State::Verify, _) => Err(Error::AtomicPayload),
                _ => Ok(step_data(state))
            }
        }
    }

    struct FetchPayload;
    impl Step for FetchPayload {
        fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
            match (state, payload) {
                (State::Fetch, Some(Payload::Blob(ref b))) if b == b"fetch payload" => Ok(None),
                (State::Fetch, _) => Err(Error::AtomicPayload),
                _ => Ok(step_data(state))
            }
        }
    }

    struct CommitPayload;
    impl Step for CommitPayload {
        fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
            match (state, payload) {
                (State::Commit, Some(Payload::Blob(ref b))) if b == b"commit payload" => Ok(step_data(state)),
                (State::Commit, _) => Err(Error::AtomicPayload),
                _ => Ok(step_data(state))
            }
        }
    }

    struct VerifyFail;
    impl Step for VerifyFail {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Verify { return Err(Error::AtomicAbort("verify failed".into())) }
            Ok(step_data(state))
        }
    }

    struct FetchFail;
    impl Step for FetchFail {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Fetch { return Err(Error::AtomicAbort("fetch failed".into())) }
            Ok(step_data(state))
        }
    }

    struct CommitFail;
    impl Step for CommitFail {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Commit {
                thread::sleep(Duration::from_secs(1));
                Err(Error::AtomicAbort("commit failed".into()))
            } else {
                Ok(step_data(state))
            }
        }
    }

    struct VerifyTimeout;
    impl Step for VerifyTimeout {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Verify { thread::sleep(Duration::from_secs(99)) }
            Ok(step_data(state))
        }
    }

    struct FetchTimeout;
    impl Step for FetchTimeout {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Fetch { thread::sleep(Duration::from_secs(99)) }
            Ok(step_data(state))
        }
    }

    struct CommitTimeout;
    impl Step for CommitTimeout {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Commit { thread::sleep(Duration::from_secs(99)) }
            Ok(step_data(state))
        }
    }

    struct VerifyCrash;
    impl Step for VerifyCrash {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Verify { panic!("verify crashed") }
            Ok(step_data(state))
        }
    }

    struct FetchCrash;
    impl Step for FetchCrash {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Fetch { panic!("fetch crashed") }
            Ok(step_data(state))
        }
    }

    struct CommitCrash;
    impl Step for CommitCrash {
        fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
            if state == State::Commit { panic!("commit crashed") }
            Ok(step_data(state))
        }
    }

    struct FetchImage;
    impl Step for FetchImage {
        fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
            match (state, payload) {
                (State::Fetch, Some(Payload::ImageMeta(ref bytes))) => {
                    let meta = json::from_slice(bytes).expect("read ImageMeta");
                    let writer = ImageWriter::new(meta, "/tmp/sota-test-images".into());
                    Ok(Some(StepData::ImageWriter(writer)))
                }
                _ => Ok(step_data(state))
            }
        }
    }


    fn bus() -> Box<Bus> {
        Box::new(Multicast::new(
            SocketAddrV4::new(Ipv4Addr::new(232,0,0,101), 23201),
            SocketAddrV4::new(Ipv4Addr::new(232,0,0,102), 23202),
        ).expect("multicast"))
    }

    fn serials(prefix: &str) -> (String, String, String) {
        let now = time::precise_time_ns().to_string();
        (format!("{}_{}_a", prefix, now), format!("{}_{}_b", prefix, now), format!("{}_{}_c", prefix, now))
    }

    fn payloads(a: &str, b: &str, c: &str) -> Payloads {
        hashmap!{a.into() => hashmap!{}, b.into() => hashmap!{}, c.into() => hashmap!{} }
    }

    fn timeout(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }


    #[test]
    fn atomic_ok() {
        let (a, b, c) = serials("ok");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(1), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(1), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(Success), timeout(1), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_ok()));

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(3), None);
        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_payloads() {
        let (a, b, c) = serials("verify_payload");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(VerifyPayload), timeout(1), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(FetchPayload), timeout(1), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(CommitPayload), timeout(1), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_ok()));

        let payloads = hashmap!{
            a.clone() => hashmap!{ State::Verify => Payload::Blob(b"verify payload".to_vec()) },
            b.clone() => hashmap!{ State::Fetch  => Payload::Blob(b"fetch payload".to_vec()) },
            c.clone() => hashmap!{ State::Commit => Payload::Blob(b"commit payload".to_vec()) },
        };
        let mut primary = Primary::new(payloads, hashmap!{}, hashmap!{}, bus(), timeout(3), None);
        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_verify_fail() {
        let (a, b, c) = serials("verify_fail");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(2), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(2), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(VerifyFail), timeout(2), None);
        thread::spawn(move || assert!(sa.listen().is_err()));
        thread::spawn(move || assert!(sb.listen().is_err()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(6), None);
        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{});
        assert_eq!(primary.aborted(), &hashset!{a, b, c});
    }

    #[test]
    fn atomic_fetch_fail() {
        let (a, b, c) = serials("fetch_fail");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(2), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(2), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(FetchFail), timeout(2), None);
        thread::spawn(move || assert!(sa.listen().is_err()));
        thread::spawn(move || assert!(sb.listen().is_err()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(6), None);
        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{});
        assert_eq!(primary.aborted(), &hashset!{a, b, c});
    }

    #[test]
    fn atomic_commit_fail() {
        let (a, b, c) = serials("commit_fail");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(2), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(2), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(CommitFail), timeout(2), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(6), None);
        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{a, b});
        assert_eq!(primary.aborted(), &hashset!{c});
    }

    #[test]
    fn atomic_verify_timeout() {
        let (a, b, c) = serials("verify_timeout");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(1), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(1), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(VerifyTimeout), timeout(1), None);
        thread::spawn(move || assert!(sa.listen().is_err()));
        thread::spawn(move || assert!(sb.listen().is_err()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(5), None);
        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{});
        assert_eq!(primary.aborted(), &hashset!{a, b});
    }

    #[test]
    fn atomic_fetch_timeout() {
        let (a, b, c) = serials("fetch_timeout");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(1), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(1), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(FetchTimeout), timeout(1), None);
        thread::spawn(move || assert!(sa.listen().is_err()));
        thread::spawn(move || assert!(sb.listen().is_err()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(5), None);
        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{});
        assert_eq!(primary.aborted(), &hashset!{a, b});
    }

    #[test]
    fn atomic_commit_timeout() {
        let (a, b, c) = serials("commit_timeout");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(1), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(1), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(CommitTimeout), timeout(1), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_ok()));

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(5), None);
        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{a, b});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_verify_crash() {
        let (a, b, c) = serials("verify_crash");
        let c2 = c.clone();
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(9), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(9), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || {
            let path = format!("/tmp/sota-atomic-verify-crash-{}", time::precise_time_ns().to_string());
            let outcome = panic::catch_unwind(|| {
                let mut sc = Secondary::new(c2, bus(), Box::new(VerifyCrash), timeout(9), Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(sc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut sc = Secondary::recover(path, bus(), Box::new(Success)).expect("recover");
            assert!(sc.listen().is_ok());
        });

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(10), None);
        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_fetch_crash() {
        let (a, b, c) = serials("fetch_crash");
        let c2 = c.clone();
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(9), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(9), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || {
            let path = format!("/tmp/sota-atomic-fetch-crash-{}", time::precise_time_ns().to_string());
            let outcome = panic::catch_unwind(|| {
                let mut sc = Secondary::new(c2, bus(), Box::new(FetchCrash), timeout(9), Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(sc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut sc = Secondary::recover(path, bus(), Box::new(Success)).expect("recover");
            assert!(sc.listen().is_ok());
        });

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(10), None);
        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_commit_crash() {
        let (a, b, c) = serials("commit_crash");
        let c2 = c.clone();
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(9), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(9), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || {
            let path = format!("/tmp/sota-atomic-commit-crash-{}", time::precise_time_ns().to_string());
            let outcome = panic::catch_unwind(|| {
                let mut sc = Secondary::new(c2, bus(), Box::new(CommitCrash), timeout(9), Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(sc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut sc = Secondary::recover(path, bus(), Box::new(Success)).expect("recover");
            assert!(sc.listen().is_ok());
        });

        let mut primary = Primary::new(payloads(&a, &b, &c), hashmap!{}, hashmap!{}, bus(), timeout(10), None);
        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_fetch_image() {
        let (a, b, c) = serials("fetch_image");
        let mut sa = Secondary::new(a.clone(), bus(), Box::new(Success), timeout(9), None);
        let mut sb = Secondary::new(b.clone(), bus(), Box::new(Success), timeout(9), None);
        let mut sc = Secondary::new(c.clone(), bus(), Box::new(FetchImage), timeout(9), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_ok()));

        let mut buf = [0; 123];
        SystemRandom::new().fill(&mut buf).expect("fill buf");
        let image_name = "test-image";
        let image_dir = format!("/tmp/sota-test-image-{}", Utc::now().timestamp());
        fs::create_dir_all(&image_dir).expect("create dir");
        Util::write_file(&format!("{}/{}", image_dir, image_name), &buf).expect("write buf");
        let mut reader = ImageReader::new(image_name.into(), image_dir).expect("reader");
        let meta = reader.image_meta().expect("meta");

        let payloads = hashmap!{
            a.clone() => hashmap!{},
            b.clone() => hashmap!{},
            c.clone() => hashmap!{ State::Fetch => Payload::ImageMeta(json::to_vec(&meta).expect("json")) }
        };
        let images = hashmap!{image_name.into() => reader};
        let mut primary = Primary::new(payloads, images, hashmap!{}, bus(), timeout(10), None);
        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }
}
