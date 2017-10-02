use bincode::{self, Infinite};
use bytes::Bytes;
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use json;
use libc;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::str;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

use datatype::{Error, Manifests, TufSigned, Util};
use images::{ImageReader, ImageWriter};


lazy_static! {
    static ref VALID_TRANSITIONS: HashMap<State, Vec<State>> = hashmap! {
        State::Idle   => vec![State::Start],
        State::Start  => vec![State::Abort, State::Verify],
        State::Verify => vec![State::Abort, State::Fetch],
        State::Fetch  => vec![State::Abort, State::Commit],
        State::Commit => vec![State::Abort],
        State::Abort  => vec![],
    };
}


/// All possible states for a `Primary` or `Secondary`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Idle,
    Start,
    Verify,
    Fetch,
    Commit,
    Abort,
}

/// A message to be picked up by a `Primary`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PrimaryMessage {
    /// New TCP Connection.
    Connect { serial: String },
    /// Acknowledgement of a state transition.
    Ack { txid: Uuid, state: State, payload: Option<Payload> },
    /// Request for an image chunk.
    Chunk { txid: Uuid, image: String, index: u64 },
}

/// A message to be picked up by a `Secondary`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SecondaryMessage {
    /// A new transaction has started.
    Start { txid: Uuid },
    /// Move to the next state.
    Step { txid: Uuid, state: State, payload: Option<Payload> },
    /// A specific image chunk.
    Chunk { txid: Uuid, image: String, index: u64, chunk: Bytes },
}


/// A mapping from serials to the payloads to be delivered at each state.
pub type Payloads = HashMap<String, HashMap<State, Payload>>;

/// Data that may be delivered to a `Secondary` before executing state transition.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Payload {
    Generic(Bytes),
    ImageMeta(Bytes),
    OstreePackage(Bytes),
    SignedReport(Bytes),
    UptaneMetadata(Bytes),
}


/// The interface for transitioning a `Secondary` to the next state.
pub trait Step: Send {
    fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error>;
}

/// Data that may be returned following a state transition.
pub enum StepData {
    ImageWriter(ImageWriter),
    TufReport(TufSigned),
}


/// A `Primary` is responsible for coordinating state changes with all
/// `Secondary` ECUs referenced in the payload data.
#[derive(Serialize, Deserialize)]
pub struct Primary<'s> {
    txid:  Uuid,
    state: State,

    payloads: Payloads,
    images:   HashMap<String, ImageReader>,

    acks:    HashMap<State, HashSet<String>>,
    started: DateTime<Utc>,
    timeout: Duration,
    recover: Option<String>,
    signed:  HashMap<String, TufSigned>,

    #[serde(skip_serializing, skip_deserializing)]
    server: Option<&'s TcpServer>,
}

impl<'s> Primary<'s> {
    /// Create a new `Primary` that will coordinate the transactional secondaries.
    pub fn new(payloads: Payloads,
               images:   HashMap<String, ImageReader>,
               server:   &'s TcpServer,
               timeout:  Duration,
               recover:  Option<String>) -> Self {
        Primary {
            txid:  Uuid::new_v4(),
            state: State::Idle,

            payloads: payloads,
            images:   images,
            server:   Some(server),

            acks: hashmap! {
                State::Start  => HashSet::new(),
                State::Verify => HashSet::new(),
                State::Fetch  => HashSet::new(),
                State::Commit => HashSet::new(),
                State::Abort  => HashSet::new(),
            },
            started: Utc::now(),
            timeout: timeout,
            recover: recover,
            signed:  HashMap::new(),
        }
    }

    /// Recover from a crash by requesting an update on missing `Secondary` acks.
    pub fn recover<P: AsRef<Path>>(path: P, server: &'s TcpServer) -> Result<Self, Error> {
        let mut primary: Primary = json::from_reader(BufReader::new(File::open(&path)?))?;
        info!("Primary state recovered from `{}`", path.as_ref().display());
        primary.server = Some(server);
        primary.started = Utc::now();
        primary.send_request(primary.state)?;
        Ok(primary)
    }

    /// Wake each `Secondary` then execute the three-phase commit process.
    pub fn commit(&mut self) -> Result<(), Error> {
        self.transition(State::Start)?;
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

    /// A list of the acknowledged `Secondary` commits.
    pub fn committed(&self) -> &HashSet<String> {
        self.acks.get(&State::Commit).expect("commit acks")
    }

    /// A list of the acknowledged `Secondary` aborts.
    pub fn aborted(&self) -> &HashSet<String> {
        self.acks.get(&State::Abort).expect("abort acks")
    }

    /// Convert the completed transaction into a list of signed ECU reports.
    pub fn into_manifests(self) -> Manifests {
        self.payloads
            .iter()
            .filter_map(|(serial, _)| {
                self.signed
                    .get(serial)
                    .map(|manifest| (serial.clone(), manifest.clone()))
            })
            .collect()
    }

    /// Transition all secondaries to the next state.
    fn transition(&mut self, state: State) -> Result<(), Error> {
        if ! is_valid(self.state, state) { return Ok(()) }
        info!("Transaction {} moving to {:?}.", self.txid, state);
        self.checkpoint(state)?;
        self.send_request(state)?;

        while self.state == state && self.acks(state).len() < self.payloads.len() {
            match self.read_message() {
                Some((serial, msg)) => match msg {
                    PrimaryMessage::Connect { serial } => Ok(trace!("connect: {}", serial)),

                    PrimaryMessage::Ack { txid, state, payload } => {
                        if txid != self.txid { continue }
                        debug!("ACK from {}: {:?}", serial, state);
                        let _ = self.acks.get_mut(&state).expect("acks").insert(serial.clone());
                        if let Some(Payload::SignedReport(ref data)) = payload {
                            self.signed.insert(serial.clone(), json::from_slice(data)?);
                        }
                        if state == State::Abort && in_progress(self.state) {
                            self.transition(State::Abort)?;
                            Err(Error::AtomicAbort(serial))
                        } else {
                            Ok(())
                        }
                    }

                    PrimaryMessage::Chunk { txid, image, index } => {
                        if txid != self.txid { continue }
                        trace!("request from {} for {} chunk {}", serial, image, index);
                        let chunk = self.images.get_mut(&image)
                            .ok_or_else(|| Error::Image(format!("not found: {}", image)))
                            .and_then(|reader| reader.read_chunk(index))?.into();
                        self.write_message(&serial, &SecondaryMessage::Chunk {
                            txid: txid,
                            image: image,
                            index: index,
                            chunk: chunk,
                        })
                    }
                },

                None => {
                    if self.is_timeout() {
                        Err(Error::AtomicTimeout)
                    } else {
                        self.send_request(self.state)?;
                        Ok(thread::sleep(Duration::from_millis(100)))
                    }
                }
            }?;
        }

        Ok(())
    }

    /// Set a new `State` and persist the decision to disk.
    fn checkpoint(&mut self, state: State) -> Result<(), Error> {
        self.started = Utc::now();
        self.state = state;
        if let Some(ref path) = self.recover {
            Util::write_file(path, &json::to_vec(self)?)?;
        }
        Ok(())
    }

    /// Request each transactional `Secondary` move to the next `State`.
    fn send_request(&self, state: State) -> Result<(), Error> {
        for (serial, states) in &self.payloads {
            if state == State::Start {
                self.write_message(serial, &SecondaryMessage::Start { txid: self.txid })?;
            } else if self.acks(state).get(serial).is_none() {
                self.write_message(serial, &SecondaryMessage::Step {
                    txid: self.txid,
                    state: state,
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

    fn read_message(&mut self) -> Option<(String, PrimaryMessage)> {
        self.server.as_mut().expect("tcp server").read_message()
    }

    fn write_message(&self, serial: &str, msg: &SecondaryMessage) -> Result<(), Error> {
        match self.server.as_ref().expect("tcp server").write_message(serial, msg) {
            Ok(()) => Ok(()),
            Err(ref err) if should_retry(&err) => Ok(()),
            Err(err) => Err(err)
        }
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
    client: Option<TcpClient>,
    #[serde(skip_serializing, skip_deserializing)]
    step: Option<Box<Step>>,
}

impl Secondary {
    /// Create a `Secondary` that listens on the bus for state transitions messages.
    pub fn new(client: TcpClient, step: Box<Step>, timeout: Duration, recover: Option<String>) -> Self {
        Secondary {
            txid:   None,
            serial: client.serial.clone(),
            state:  State::Idle,
            next:   State::Idle,

            started: Utc::now(),
            timeout: timeout,
            recover: recover,
            payload: None,
            writers: HashMap::new(),
            report:  None,

            client: Some(client),
            step: Some(step),
        }
    }

    /// Recover from a crash while a transaction was in progress.
    pub fn recover<P: AsRef<Path>>(path: P, client: TcpClient, step: Box<Step>) -> Result<Self, Error> {
        let mut follower: Secondary = json::from_reader(BufReader::new(File::open(&path)?))?;
        info!("Secondary `{}` state recovered from `{}`", follower.serial, path.as_ref().display());
        follower.client = Some(client);
        follower.step = Some(step);
        follower.started = Utc::now();
        Ok(follower)
    }

    /// Block until a new transaction is started then read new messages until we
    /// reach a terminating state or time-out.
    pub fn listen(&mut self) -> Result<(), Error> {
        info!("Starting a Secondary ECU listener for serial `{}`", self.serial);

        while ! is_terminal(self.state) {
            self.read_message()
                .and_then(|msg| match msg {
                    SecondaryMessage::Start { txid } => {
                        self.txid = Some(txid);
                        self.transition(State::Start, None)
                    }

                    SecondaryMessage::Step { txid, state, payload } => {
                        if txid != self.txid() { return Ok(()) }
                        self.transition(state, payload)
                    }

                    SecondaryMessage::Chunk { txid, image, index, chunk } => {
                        if txid != self.txid() { return Ok(()) }
                        let next_index = {
                            let writer = self.writers.get_mut(&image)
                                .ok_or_else(|| Error::Image(format!("writer not found: {}", image)))?;
                            writer.write_direct(&chunk, index)?;
                            if let Some(index) = writer.next_chunk() {
                                Some(index)
                            } else {
                                writer.verify_direct()?;
                                None
                            }
                        };
                        match next_index {
                            Some(index) => self.request_chunk(image, index),
                            None => {
                                self.state = self.next;
                                self.write_ack()
                            }
                        }
                   }
                })
                .or_else(|err| {
                    if ! should_retry(&err) {
                        debug!("{} moving to abort: {}", self.serial, err);
                        let _ = self.transition(State::Abort, None);
                        Err(err)
                    } else if self.is_timeout() && in_progress(self.state) {
                        debug!("{} timed out", self.serial);
                        let _ = self.transition(State::Abort, None);
                        Err(Error::AtomicTimeout)
                    } else {
                        Ok(thread::sleep(Duration::from_millis(100)))
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

    /// Move to the next `State` by calling the `self.step` function.
    fn transition(&mut self, state: State, payload: Option<Payload>) -> Result<(), Error> {
        if self.state == state {
            return self.write_ack();
        } else if ! is_valid(self.state, state) {
            return Err(Error::AtomicState(self.state, state));
        }

        debug!("serial {} moving to {:?}", self.serial, state);
        self.checkpoint(state, payload.clone())?;
        self.step(state, payload)
            .and_then(|step_data| match step_data {
                None => {
                    self.state = self.next;
                    self.write_ack()
                }

                Some(StepData::ImageWriter(writer)) => {
                    if let None = self.writers.get(&writer.meta.image_name) {
                        let image = writer.meta.image_name.clone();
                        let _ = self.writers.insert(image.clone(), writer);
                        self.request_chunk(image, 0)
                    } else {
                        Ok(trace!("skipping existing writer: {}", writer.meta.image_name))
                    }
                }

                Some(StepData::TufReport(report)) => {
                    self.report = Some(report);
                    self.state = self.next;
                    self.write_ack()
                }
            })
            .or_else(|err| {
                error!("serial {} aborting: {}", self.serial, err);
                let _ = self.transition(State::Abort, None);
                Err(err)
            })
    }

    /// Set a new `State` and persist the decision to disk.
    fn checkpoint(&mut self, state: State, payload: Option<Payload>) -> Result<(), Error> {
        self.started = Utc::now();
        self.next = state;
        self.payload = payload;
        if let Some(ref path) = self.recover {
            Util::write_file(path, &json::to_vec(self)?)?;
        }
        Ok(())
    }

    /// Send a request to the `Primary` for a new image chunk.
    fn request_chunk(&mut self, image: String, index: u64) -> Result<(), Error> {
        let txid = self.txid();
        self.write_message(&PrimaryMessage::Chunk { txid: txid, image: image, index: index })
    }

    /// Send an acknowledgement to the `Primary` of a state transition.
    fn write_ack(&mut self) -> Result<(), Error> {
        let txid = self.txid();
        let state = self.state;
        let payload = match self.report {
            Some(ref report) => Some(Payload::SignedReport(Bytes::from(json::to_vec(&report)?))),
            None if is_terminal(self.state) => return Err(Error::AtomicSigned),
            None => None
        };
        self.write_message(&PrimaryMessage::Ack { txid: txid, state: state, payload: payload })
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

    fn read_message(&mut self) -> Result<SecondaryMessage, Error> {
        self.client.as_mut().expect("tcp client").read_message()
    }

    fn write_message(&mut self, msg: &PrimaryMessage) -> Result<(), Error> {
        match self.client.as_mut().expect("tcp server").write_message(msg) {
            Ok(()) => Ok(()),
            Err(ref err) if should_retry(err) => Ok(()),
            Err(err) => Err(err)
        }
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

fn in_progress(state: State) -> bool {
    match state {
        State::Start | State::Verify | State::Fetch => true,
        _ => false
    }
}

fn should_retry(err: &Error) -> bool {
    match *err {
        Error::AtomicOffline(_) => true,
        Error::Io(ref err) => match err.kind() {
            ErrorKind::ConnectionReset |
            ErrorKind::Interrupted |
            ErrorKind::TimedOut |
            ErrorKind::UnexpectedEof |
            ErrorKind::WouldBlock => true,
            _ => match err.raw_os_error() {
                Some(libc::EPROTOTYPE) |
                Some(libc::EDEADLK) => true,
                _ => false
            }
        },
        _ => false
    }
}


/// A `TcpServer` will read `PrimaryMessage`s from each connected `TcpClient`.
pub struct TcpServer {
    clients:  Arc<Mutex<HashMap<String, TcpStream>>>,
    messages: Arc<Mutex<VecDeque<(String, PrimaryMessage)>>>,
    _addr:    SocketAddr,
}

impl Default for TcpServer {
    fn default() -> Self {
        TcpServer::new("127.0.0.1:0").expect("bind local")
    }
}

impl TcpServer {
    /// Start a `TcpServer` and accept new connections in a background thread.
    pub fn new<A: ToSocketAddrs>(addr: A) -> Result<Self, Error> {
        let listener = TcpListener::bind(&addr)?;
        let server = TcpServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            messages: Arc::new(Mutex::new(VecDeque::new())),
            _addr: listener.local_addr()?,
        };

        let clients = server.clients.clone();
        let messages = server.messages.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                stream.map_err(Error::Io)
                    .and_then(|s| Self::accept_stream(s, clients.clone(), messages.clone()))
                    .unwrap_or_else(|err| warn!("Unable to open TCP connection: {}", err))
            }
        });

        Ok(server)
    }

    /// Accept a new TCP connection and push incoming messages into a queue.
    fn accept_stream(
        mut stream: TcpStream,
        clients: Arc<Mutex<HashMap<String, TcpStream>>>,
        messages: Arc<Mutex<VecDeque<(String, PrimaryMessage)>>>,
    ) -> Result<(), Error> {
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.set_write_timeout(Some(Duration::from_millis(500)))?;

        let msg = read_stream(&mut stream)?;
        if let PrimaryMessage::Connect { serial: s } = msg {
            debug!("serial {} connected", s);
            let client_stream = stream.try_clone()?;
            clients.lock().unwrap().insert(s.clone(), client_stream);

            let messages = messages.clone();
            thread::spawn(move || loop {
                match read_stream(&mut stream) {
                    Ok(msg) => messages.lock().unwrap().push_back((s.clone(), msg)),
                    Err(ref err) if should_retry(err) => thread::sleep(Duration::from_millis(500)),
                    Err(err) => warn!("Unable to read message from {}: {}", s, err)
                }
            });
        } else {
            error!("Rejecting TCP connect message: {:?}", msg);
        }

        Ok(())
    }

    /// Read the next `PrimaryMessage`.
    pub fn read_message(&self) -> Option<(String, PrimaryMessage)> {
        self.messages.lock().unwrap().pop_front()
    }

    /// Write a `SecondaryMessage` to a specific serial.
    pub fn write_message(&self, serial: &str, msg: &SecondaryMessage) -> Result<(), Error> {
        let mut clients = self.clients.lock().unwrap();
        let outcome = {
            let mut stream = clients.get(serial).ok_or_else(|| Error::AtomicOffline(serial.into()))?;
            trace!("writing message to {}: {:?}", serial, msg);
            write_stream(&mut stream, msg)
        };
        match outcome {
            Ok(()) => Ok(()),
            Err(Error::Io(ref e)) if e.kind() == ErrorKind::BrokenPipe => {
                trace!("{} disconnected", serial);
                let _ = clients.remove(serial);
                Err(Error::AtomicOffline(serial.into()))
            },
            Err(err) => Err(err)
        }
    }
}

/// A `TcpClient` will read `SecondaryMessage`s sent from a `TcpServer`.
pub struct TcpClient {
    serial: String,
    stream: TcpStream,
}

impl TcpClient {
    /// Connect to the specified `TcpServer`.
    pub fn new<A: ToSocketAddrs>(serial: String, server: A) -> Result<Self, Error> {
        let mut stream = TcpStream::connect(server)?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.set_write_timeout(Some(Duration::from_millis(500)))?;
        write_stream(&mut stream, &PrimaryMessage::Connect { serial: serial.clone() })?;
        Ok(TcpClient { serial: serial, stream: stream })
    }

    /// Read a new message from the connected TCP stream.
    pub fn read_message(&mut self) -> Result<SecondaryMessage, Error> {
        match read_stream(&mut self.stream) {
            Ok(msg) => {
                trace!("{} got message: {:?}", self.serial, msg);
                Ok(msg)
            }
            Err(err) => Err(err)
        }
    }

    /// Write a new `PrimaryMessage`.
    pub fn write_message(&mut self, msg: &PrimaryMessage) -> Result<(), Error> {
        trace!("{} writing message: {:?}", self.serial, msg);
        write_stream(&mut self.stream, msg)
    }
}

/// Read the data size then read the rest of the data from the stream.
fn read_stream<T: DeserializeOwned>(mut stream: &mut Read) -> Result<T, Error> {
    let mut size_buf = [0; 4];
    stream.read_exact(&mut size_buf)?;
    let num_bytes = BigEndian::read_u32(&size_buf);

    let mut data_buf = vec![0; num_bytes as usize];
    let mut bytes_read = 0;
    loop {
        match stream.read(&mut data_buf[bytes_read..]) {
            Ok(0) => return Ok(bincode::deserialize(&data_buf)?),
            Ok(n) => bytes_read += n,
            Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => continue,
            Err(err) => return Err(err.into())
        }
    }
}

/// Write the data size then write the referenced data to the stream.
fn write_stream<T: Serialize>(mut stream: &mut Write, data: &T) -> Result<(), Error> {
    let encoded = bincode::serialize(data, Infinite)?;
    let mut size_buf = [0; 4];
    BigEndian::write_u32(&mut size_buf, encoded.len() as u32);
    loop {
        match stream.write_all(&size_buf) {
            Ok(()) => break,
            Err(err) => match err.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => continue,
                _ => return Err(err.into())
            }
        }
    }

    let mut written = 0;
    loop {
        match stream.write(&encoded[written..]) {
            Ok(0) => return Ok(stream.flush()?),
            Ok(n) => written += n,
            Err(err) => match err.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => continue,
                _ => return Err(err.into())
            }
        }
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
            let empty = json::from_str("{}").expect("empty object");
            let report = PRIVATE_KEY.sign_data(empty, SignatureType::Ed25519).expect("report");
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
                (State::Verify, Some(Payload::Generic(ref b))) if b == "verify payload" => Ok(None),
                (State::Verify, _) => Err(Error::AtomicPayload),
                _ => Ok(step_data(state))
            }
        }
    }

    struct FetchPayload;
    impl Step for FetchPayload {
        fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
            match (state, payload) {
                (State::Fetch, Some(Payload::Generic(ref b))) if b == "fetch payload" => Ok(None),
                (State::Fetch, _) => Err(Error::AtomicPayload),
                _ => Ok(step_data(state))
            }
        }
    }

    struct CommitPayload;
    impl Step for CommitPayload {
        fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
            match (state, payload) {
                (State::Commit, Some(Payload::Generic(ref b))) if b == "commit payload" => Ok(step_data(state)),
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


    fn connect(prefix: &str) -> (
        Payloads,
        TcpServer,
        TcpClient,
        TcpClient,
        TcpClient,
        String,
        String,
        String,
    ) {
        let now = time::precise_time_ns().to_string();
        let a = format!("{}_{}_a", prefix, now);
        let b = format!("{}_{}_b", prefix, now);
        let c = format!("{}_{}_c", prefix, now);
        let payloads = hashmap!{
            a.clone() => hashmap!{},
            b.clone() => hashmap!{},
            c.clone() => hashmap!{},
        };

        let srv = TcpServer::default();
        let ca = TcpClient::new(a.clone(), &srv._addr).expect("ca");
        let cb = TcpClient::new(b.clone(), &srv._addr).expect("cb");
        let cc = TcpClient::new(c.clone(), &srv._addr).expect("cc");

        (payloads, srv, ca, cb, cc, a, b, c)
    }

    fn timeout(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }


    #[test]
    fn atomic_ok() {
        let (payloads, srv, ca, cb, cc, a, b, c) = connect("ok");
        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(Success), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_ok()));

        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_payloads() {
        let (_, srv, ca, cb, cc, a, b, c) = connect("payloads");
        let payloads = hashmap!{
            a.clone() => hashmap!{ State::Verify => Payload::Generic(Bytes::from("verify payload")) },
            b.clone() => hashmap!{ State::Fetch  => Payload::Generic(Bytes::from("fetch payload")) },
            c.clone() => hashmap!{ State::Commit => Payload::Generic(Bytes::from("commit payload")) },
        };
        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(VerifyPayload), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(FetchPayload), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(CommitPayload), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_ok()));

        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_verify_fail() {
        let (payloads, srv, ca, cb, cc, a, b, c) = connect("verify_fail");
        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(VerifyFail), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_err()));
        thread::spawn(move || assert!(sb.listen().is_err()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{});
        assert_eq!(primary.aborted(), &hashset!{a, b, c});
    }

    #[test]
    fn atomic_fetch_fail() {
        let (payloads, srv, ca, cb, cc, a, b, c) = connect("fetch_fail");
        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(FetchFail), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_err()));
        thread::spawn(move || assert!(sb.listen().is_err()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{});
        assert_eq!(primary.aborted(), &hashset!{a, b, c});
    }

    #[test]
    fn atomic_commit_fail() {
        let (payloads, srv, ca, cb, cc, a, b, c) = connect("commit_fail");
        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(CommitFail), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{a, b});
        assert_eq!(primary.aborted(), &hashset!{c});
    }

    #[test]
    fn atomic_verify_timeout() {
        let (payloads, srv, ca, cb, cc, a, b, _) = connect("verify_timeout");
        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(VerifyTimeout), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_err()));
        thread::spawn(move || assert!(sb.listen().is_err()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{});
        assert_eq!(primary.aborted(), &hashset!{a, b});
    }

    #[test]
    fn atomic_fetch_timeout() {
        let (payloads, srv, ca, cb, cc, a, b, _) = connect("fetch_timeout");
        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(FetchTimeout), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_err()));
        thread::spawn(move || assert!(sb.listen().is_err()));
        thread::spawn(move || assert!(sc.listen().is_err()));

        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{});
        assert_eq!(primary.aborted(), &hashset!{a, b});
    }

    #[test]
    fn atomic_commit_timeout() {
        let (payloads, srv, ca, cb, cc, a, b, _) = connect("commit_timeout");
        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(CommitTimeout), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_ok()));

        assert!(primary.commit().is_err());
        assert_eq!(primary.committed(), &hashset!{a, b});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_verify_crash() {
        let (payloads, srv, ca, cb, cc, a, b, c) = connect("verify_crash");
        let addr = srv._addr.clone();
        let serial_c = c.clone();

        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || {
            let path = format!("/tmp/sota-atomic-verify-crash-{}", time::precise_time_ns().to_string());
            let outcome = panic::catch_unwind(|| {
                let mut sc = Secondary::new(cc, Box::new(VerifyCrash), timeout(500), Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(sc.listen().is_err());
            });
            assert!(outcome.is_err());
            let cc = TcpClient::new(serial_c, addr).expect("cc");
            let mut sc = Secondary::recover(path, cc, Box::new(Success)).expect("recover");
            assert!(sc.listen().is_ok());
        });

        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_fetch_crash() {
        let (payloads, srv, ca, cb, cc, a, b, c) = connect("fetch_crash");
        let addr = srv._addr.clone();
        let serial_c = c.clone();

        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || {
            let path = format!("/tmp/sota-atomic-fetch-crash-{}", time::precise_time_ns().to_string());
            let outcome = panic::catch_unwind(|| {
                let mut sc = Secondary::new(cc, Box::new(FetchCrash), timeout(500), Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(sc.listen().is_err());
            });
            assert!(outcome.is_err());
            let cc = TcpClient::new(serial_c, addr).expect("cc");
            let mut sc = Secondary::recover(path, cc, Box::new(Success)).expect("recover");
            assert!(sc.listen().is_ok());
        });

        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_commit_crash() {
        let (payloads, srv, ca, cb, cc, a, b, c) = connect("commit_crash");
        let addr = srv._addr.clone();
        let serial_c = c.clone();

        let mut primary = Primary::new(payloads, hashmap!{}, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || {
            let path = format!("/tmp/sota-atomic-commit-crash-{}", time::precise_time_ns().to_string());
            let outcome = panic::catch_unwind(|| {
                let mut sc = Secondary::new(cc, Box::new(CommitCrash), timeout(500), Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(sc.listen().is_err());
            });
            assert!(outcome.is_err());
            let cc = TcpClient::new(serial_c, addr).expect("cc");
            let mut sc = Secondary::recover(path, cc, Box::new(Success)).expect("recover");
            assert!(sc.listen().is_ok());
        });

        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_fetch_image() {
        let mut buf = [0; 123];
        SystemRandom::new().fill(&mut buf).expect("fill buf");
        let image_name = "test-image";
        let image_dir = format!("/tmp/sota-test-image-{}", Utc::now().timestamp());
        fs::create_dir_all(&image_dir).expect("create dir");
        Util::write_file(&format!("{}/{}", image_dir, image_name), &buf).expect("write buf");
        let mut reader = ImageReader::new(image_name.into(), image_dir).expect("reader");
        let meta = reader.image_meta().expect("meta");

        let (_, srv, ca, cb, cc, a, b, c) = connect("fetch_image");
        let payloads = hashmap!{
            a.clone() => hashmap!{},
            b.clone() => hashmap!{},
            c.clone() => {
                let bytes = Bytes::from(json::to_vec(&meta).expect("json"));
                hashmap!{ State::Fetch => Payload::ImageMeta(bytes) }
            }
        };
        let images = hashmap!{image_name.into() => reader};

        let mut primary = Primary::new(payloads, images, &srv, timeout(5000), None);
        let mut sa = Secondary::new(ca, Box::new(Success), timeout(500), None);
        let mut sb = Secondary::new(cb, Box::new(Success), timeout(500), None);
        let mut sc = Secondary::new(cc, Box::new(FetchImage), timeout(500), None);
        thread::spawn(move || assert!(sa.listen().is_ok()));
        thread::spawn(move || assert!(sb.listen().is_ok()));
        thread::spawn(move || assert!(sc.listen().is_ok()));

        assert!(primary.commit().is_ok());
        assert_eq!(primary.committed(), &hashset!{a, b, c});
        assert_eq!(primary.aborted(), &hashset!{});
    }
}
