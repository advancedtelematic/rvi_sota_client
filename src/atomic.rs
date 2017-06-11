use serde_json as json;
use std::fs::{self, File};
use std::io::{BufReader, ErrorKind};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};
use net2::UdpBuilder;
use net2::unix::UnixUdpBuilderExt;
use uuid::Uuid;

use datatype::{Error, Util};

/*
for package in packages {
    if package.ecu_serial == self.config.uptane.primary_ecu_serial {
    let outcome = package.install(&self.get_credentials())?;
    let result  = outcome.into_result(package.refName.clone());
    let success = result.result_code.is_success();
    let version = uptane.signed_version(Some(EcuCustom { operation_result: result }))?;
    if success {
    Event::UptaneInstallComplete(version)
        } else {
            Event::UptaneInstallFailed(version)
        }
    } else {
        Event::UptaneInstallNeeded(package)
    }
}
*/


lazy_static! {
    static ref VALID_TRANSITIONS: HashMap<State, Vec<State>> = hashmap! {
        State::Ready   => vec![State::Verify],
        State::Verify  => vec![State::Abort, State::Prepare],
        State::Prepare => vec![State::Abort, State::Commit],
        State::Commit  => vec![State::Abort],
        State::Abort   => vec![],
    };
}

const BUFFER_SIZE: usize = 100*1024;


/// Execute a transition to the next state using the payload data.
pub trait Transition: Send {
    fn exec(&self, state: State, payload: &[u8]) -> Result<(), String>;
}


/// Send a message to be picked up by either a `Leader` or a `Follower`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    Next  { txid: Uuid, serial: String, state: State, payload: Vec<u8> },
    Ack   { txid: Uuid, serial: String, state: State },
    Query { txid: Uuid },
}

/// An enumeration of all possible states for a `Leader` or `Follower`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Ready,
    Verify,
    Prepare,
    Commit,
    Abort,
}

/// A mapping from serials to the payloads to be delivered at each state.
pub type Payloads = HashMap<String, HashMap<State, Vec<u8>>>;


/// Holds a receiver and transmitter for UDP messages across the network.
pub struct Multicast {
    socket: UdpSocket,
    broadcast: SocketAddr,
}

impl Multicast {
    fn new(addr: Ipv4Addr, port: u16) -> Result<Self, Error> {
        let socket = UdpBuilder::new_v4()?
            .reuse_address(true)?
            .reuse_port(true)?
            .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::from([0, 0, 0, 0])), port))?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        socket.join_multicast_v4(&addr, &Ipv4Addr::new(0,0,0,0))?;
        Ok(Multicast { socket: socket, broadcast: SocketAddr::new(IpAddr::V4(addr), port) })
    }

    fn read_message(&self) -> Result<Message, Error> {
        let mut buf = Box::new(vec![0u8; BUFFER_SIZE]);
        let (len, _) = self.socket.recv_from(&mut buf)?;
        buf.truncate(len);
        Ok(json::from_slice(&buf)?)
    }

    fn write_message(&self, msg: &Message) -> Result<(), Error> {
        let _ = self.socket.send_to(&json::to_vec(msg)?, self.broadcast)?;
        Ok(())
    }
}


/// A `Leader` is responsible for coordinating the state changes of followers.
#[derive(Serialize, Deserialize)]
pub struct Leader {
    txid: Uuid,
    addr: Ipv4Addr,
    port: u16,

    payloads: Payloads,
    acks:     HashMap<State, HashSet<String>>,
    state:    State,
    timeout:  Duration,
    recover:  Option<String>,

    #[serde(skip_serializing, skip_deserializing)]
    started: Option<Instant>,
    #[serde(skip_serializing, skip_deserializing)]
    multicast: Option<Multicast>,
}

impl Leader {
    /// Create a new `Leader` that will send UDP multicast messages to coordinate
    /// state changes with each `Follower`.
    pub fn new(txid: Uuid,
               payloads: Payloads,
               addr: Ipv4Addr,
               port: u16,
               timeout: Duration,
               recover: Option<String>)
               -> Result<Self, Error>
    {
        Ok(Leader {
            txid: txid,
            addr: addr,
            port: port,

            payloads: payloads,
            acks: hashmap! {
                State::Ready   => HashSet::new(),
                State::Verify  => HashSet::new(),
                State::Prepare => HashSet::new(),
                State::Commit  => HashSet::new(),
                State::Abort   => HashSet::new(),
            },
            state: State::Ready,
            timeout: timeout,
            recover: recover,

            started: Some(Instant::now()),
            multicast: Some(Multicast::new(addr, port)?),
        })
    }

    /// Recover from a crash while a transaction was in progress.
    pub fn recover<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut l: Leader = json::from_reader(BufReader::new(File::open(&path)?))?;
        info!("Leader state recovered from `{}`", path.as_ref().display());
        l.multicast = Some(Multicast::new(l.addr, l.port)?);
        l.multicast().write_message(&Message::Query { txid: l.txid })?;
        Ok(l)
    }

    /// Start the three-phase commit process.
    pub fn commit(&mut self) -> Result<(), Error> {
        info!("Transaction {} starting.", self.txid);
        self.next(State::Verify)?;
        self.next(State::Prepare)?;
        self.next(State::Commit)?;
        info!("Transaction {} complete.", self.txid);

        if let Some(ref path) = self.recover {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Transition all followers to the next state.
    pub fn next(&mut self, state: State) -> Result<(), Error> {
        if ! self.valid_transition(state) { return Ok(()) }
        info!("Transaction {} moving to {:?}.", self.txid, state);
        self.checkpoint(state)?;
        self.send_request(state)?;

        while self.state == state && self.acks(state).len() < self.payloads.len() {
            self.multicast()
                .read_message()
                .and_then(|msg| self.handle_response(msg))
                .or_else(|err| {
                    if is_waiting(&err) && self.is_timeout() {
                        self.next(State::Abort)?;
                        Err(Error::AtomicTimeout)
                    } else if is_waiting(&err) {
                        Ok(())
                    } else {
                        self.next(State::Abort)?;
                        Err(err)
                    }
                })?;
        }

        Ok(())
    }

    fn send_request(&self, state: State) -> Result<(), Error> {
        let default_payload = Vec::new();
        for (serial, states) in &self.payloads {
            let payload = states.get(&state).unwrap_or(&default_payload);
            if payload.len() > BUFFER_SIZE-1024 { return Err(Error::AtomicPayload) }
            self.multicast().write_message(&Message::Next {
                txid:    self.txid,
                serial:  serial.clone(),
                state:   state,
                payload: payload.clone()
            })?;
        }
        Ok(())
    }

    fn handle_response(&mut self, msg: Message) -> Result<(), Error> {
        match msg {
            Message::Ack { txid, serial, state } => {
                if txid != self.txid { return Ok(()) }
                debug!("ack from {}: {:?}", serial, state);
                let _ = self.acks(state).insert(serial);
                if state == State::Abort && self.state != State::Abort {
                    self.next(State::Abort)
                } else {
                    Ok(())
                }
            }
            Message::Next  { .. } => Ok(()),
            Message::Query { .. } => Ok(()),
        }
    }

    fn checkpoint(&mut self, state: State) -> Result<(), Error> {
        self.started = Some(Instant::now());
        self.state = state;
        if let Some(ref path) = self.recover {
            Util::write_file(path, &json::to_vec(self)?)?;
        }
        Ok(())
    }

    fn is_timeout(&self) -> bool {
        Instant::now().duration_since(self.started.expect("started")) > self.timeout
    }

    fn valid_transition(&self, state: State) -> bool {
        VALID_TRANSITIONS.get(&self.state).expect("transitions").contains(&state)
    }

    fn multicast(&self) -> &Multicast {
        self.multicast.as_ref().expect("multicast")
    }

    fn acks(&mut self, state: State) -> &mut HashSet<String> {
        self.acks.get_mut(&state).expect("get acks")
    }

    pub fn committed(&self) -> &HashSet<String> { self.acks.get(&State::Commit).expect("commit acks") }
    pub fn aborted(&self) -> &HashSet<String> { self.acks.get(&State::Abort).expect("abort acks") }
}


/// A `Follower` awaits instructions from a `Leader` to transition between states.
#[derive(Serialize, Deserialize)]
pub struct Follower {
    txid: Uuid,
    addr: Ipv4Addr,
    port: u16,

    timeout: Duration,
    recover: Option<String>,
    #[serde(skip_serializing, skip_deserializing)]
    started: Option<Instant>,
    #[serde(skip_serializing, skip_deserializing)]
    multicast: Option<Multicast>,
    #[serde(skip_serializing, skip_deserializing)]
    transition: Option<Box<Transition>>,

    serial: String,
    state:  State,
}

impl Follower {
    /// Create a `Follower` that listens for UDP multicast messages requesting a
    /// transition to the next state.
    pub fn new(txid: Uuid,
               serial: String,
               transition: Box<Transition>,
               addr: Ipv4Addr,
               port: u16,
               timeout: Duration,
               recover: Option<String>)
               -> Result<Self, Error>
    {
        Ok(Follower {
            txid: txid,
            addr: addr,
            port: port,

            timeout: timeout,
            recover: recover,
            started: Some(Instant::now()),
            multicast: Some(Multicast::new(addr, port)?),
            transition: Some(transition),

            serial: serial,
            state:  State::Ready,
        })
    }

    /// Recover from a crash while a transaction was in progress.
    pub fn recover<P: AsRef<Path>>(path: P, transition: Box<Transition>) -> Result<Self, Error> {
        let mut f: Follower = json::from_reader(BufReader::new(File::open(&path)?))?;
        info!("Follower `{}` state recovered from `{}`", f.serial, path.as_ref().display());
        f.multicast = Some(Multicast::new(f.addr, f.port)?);
        f.multicast().write_message(&Message::Ack { txid: f.txid, serial: f.serial.clone(), state: f.state })?;
        f.transition = Some(transition);
        Ok(f)
    }

    /// Block on new messages until we reach a terminating state.
    pub fn listen(&mut self) -> Result<(), Error> {
        while self.state != State::Commit && self.state != State::Abort {
            self.multicast()
                .read_message()
                .and_then(|msg| self.handle_request(msg))
                .or_else(|err| {
                    if is_waiting(&err) && self.is_timeout() {
                        self.next(State::Abort, &Vec::new())?;
                        Err(Error::AtomicTimeout)
                    } else if is_waiting(&err) {
                        Ok(())
                    } else {
                        let _ = self.next(State::Abort, &Vec::new());
                        Err(err)
                    }
                })?
        }

        if let Some(ref path) = self.recover {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn handle_request(&mut self, msg: Message) -> Result<(), Error> {
        match msg {
            Message::Next { txid, serial, state, payload } => {
                if txid != self.txid || serial != self.serial { return Ok(()) }
                self.next(state, &payload)
            }
            Message::Query { txid } => {
                if txid != self.txid { return Ok(()) }
                self.multicast().write_message(&self.ack())
            }
            Message::Ack { .. } => Ok(()),
        }
    }

    fn next(&mut self, state: State, payload: &[u8]) -> Result<(), Error> {
        if self.state == state {
            return Ok(());
        } else if ! self.valid_transition(state) {
            return Err(Error::AtomicStep(format!("from {:?} to {:?}", self.state, state)));
        }

        debug!("serial {}: moving to {:?}", self.serial, state);
        self.checkpoint(state, payload)?;
        self.transition(state, payload)
            .or_else(|reason| {
                error!("serial {}: {}", self.serial, reason);
                self.next(State::Abort, &Vec::new())?;
                Err(Error::AtomicAbort(reason))
            })
            .and_then(|_| self.multicast().write_message(&self.ack()))
    }

    fn checkpoint(&mut self, state: State, _: &[u8]) -> Result<(), Error> {
        self.started = Some(Instant::now());
        self.state = state;
        if let Some(ref path) = self.recover {
            Util::write_file(path, &json::to_vec(self)?)?;
        }
        Ok(())
    }

    fn transition(&self, state: State, payload: &[u8]) -> Result<(), String> {
        self.transition.as_ref().expect("transition").exec(state, payload)
    }

    fn ack(&self) -> Message {
        Message::Ack { txid: self.txid, serial: self.serial.clone(), state: self.state }
    }

    fn is_timeout(&self) -> bool {
        Instant::now().duration_since(self.started.expect("started")) > self.timeout
    }

    fn valid_transition(&self, state: State) -> bool {
        VALID_TRANSITIONS.get(&self.state).expect("transitions").contains(&state)
    }

    fn multicast(&self) -> &Multicast {
        self.multicast.as_ref().expect("multicast")
    }
}


fn is_waiting(err: &Error) -> bool {
    match *err {
        Error::Io(ref err) if err.kind() == ErrorKind::TimedOut => true,
        Error::Io(ref err) if err.kind() == ErrorKind::WouldBlock => true,
        _ => false
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::{panic, thread};


    struct Success;
    impl Transition for Success {
        fn exec(&self, _: State, _: &[u8]) -> Result<(), String> { Ok(()) }
    }

    struct VerifyPayload;
    impl Transition for VerifyPayload {
        fn exec(&self, state: State, payload: &[u8]) -> Result<(), String> {
            if state == State::Verify && payload != b"verify payload" {
                Err("unexpected payload".into())
            } else {
                Ok(())
            }
        }
    }

    struct VerifyFail;
    impl Transition for VerifyFail {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Verify { Err("verify failed".into()) } else { Ok(()) }
        }
    }

    struct PrepareFail;
    impl Transition for PrepareFail {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Prepare { Err("prepare failed".into()) } else { Ok(()) }
        }
    }

    struct CommitFail;
    impl Transition for CommitFail {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Commit { Err("commit failed".into()) } else { Ok(()) }
        }
    }

    struct VerifyTimeout;
    impl Transition for VerifyTimeout {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Verify {
                thread::sleep(Duration::from_secs(1));
                Err("verify timeout".into())
            } else {
                Ok(())
            }
        }
    }

    struct PrepareTimeout;
    impl Transition for PrepareTimeout {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Prepare {
                thread::sleep(Duration::from_secs(1));
                Err("verify timeout".into())
            } else {
                Ok(())
            }
        }
    }

    struct CommitTimeout;
    impl Transition for CommitTimeout {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Commit {
                thread::sleep(Duration::from_secs(1));
                Err("commit timeout".into())
            } else {
                Ok(())
            }
        }
    }

    struct VerifyCrash;
    impl Transition for VerifyCrash {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Verify { panic!("verify crashed"); } else { Ok(()) }
        }
    }

    struct PrepareCrash;
    impl Transition for PrepareCrash {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Prepare { panic!("prepare crashed"); } else { Ok(()) }
        }
    }

    struct CommitCrash;
    impl Transition for CommitCrash {
        fn exec(&self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Commit { panic!("commit crashed"); } else { Ok(()) }
        }
    }

    fn defaults(id: u8) -> (Uuid, Ipv4Addr, u16, Duration, Payloads) {
        let txid = format!("00000000-0000-0000-0000-0000000000{:02}", id).parse::<Uuid>().expect("uuid");
        let addr = Ipv4Addr::new(224,0,0,251);
        let port = 1234u16;
        let timeout = Duration::from_secs(1);
        let payloads = hashmap!{
            "a".into() => hashmap!{},
            "b".into() => hashmap!{},
            "c".into() => hashmap!{},
        };
        (txid, addr, port, timeout, payloads)
    }

    #[test]
    fn atomic_ok() {
        let (txid, addr, port, timeout, payloads) = defaults(1);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");
        let mut fc = Follower::new(txid, "c".into(), Box::new(Success), addr, port, timeout, None).expect("fc");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_ok()));

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{"a".into(), "b".into(), "c".into()});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_verify_payload() {
        let (txid, addr, port, timeout, _) = defaults(2);
        let payloads = hashmap!{
            "a".into() => hashmap!{State::Verify => "verify payload".as_bytes().into()},
            "b".into() => hashmap!{State::Verify => "verify payload".as_bytes().into()},
            "c".into() => hashmap!{State::Verify => "verify payload".as_bytes().into()},
        };
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(VerifyPayload), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(VerifyPayload), addr, port, timeout, None).expect("fb");
        let mut fc = Follower::new(txid, "c".into(), Box::new(VerifyPayload), addr, port, timeout, None).expect("fc");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_ok()));

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{"a".into(), "b".into(), "c".into()});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_verify_fail() {
        let (txid, addr, port, timeout, payloads) = defaults(3);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");
        let mut fc = Follower::new(txid, "c".into(), Box::new(VerifyFail), addr, port, timeout, None).expect("fc");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{});
        assert_eq!(leader.aborted(), &hashset!{"a".into(), "b".into(), "c".into()});
    }

    #[test]
    fn atomic_prepare_fail() {
        let (txid, addr, port, timeout, payloads) = defaults(4);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");
        let mut fc = Follower::new(txid, "c".into(), Box::new(PrepareFail), addr, port, timeout, None).expect("fc");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{});
        assert_eq!(leader.aborted(), &hashset!{"a".into(), "b".into(), "c".into()});
    }

    #[test]
    fn atomic_commit_fail() {
        let (txid, addr, port, timeout, payloads) = defaults(5);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");
        let mut fc = Follower::new(txid, "c".into(), Box::new(CommitFail), addr, port, timeout, None).expect("fc");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        assert!(leader.commit().is_err());
        assert_eq!(leader.committed(), &hashset!{"a".into(), "b".into()});
        assert_eq!(leader.aborted(), &hashset!{"c".into()});
    }

    #[test]
    fn atomic_verify_timeout() {
        let (txid, addr, port, timeout, payloads) = defaults(6);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");
        let mut fc = Follower::new(txid, "c".into(), Box::new(VerifyTimeout), addr, port, timeout, None).expect("fc");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{});
        assert_eq!(leader.aborted(), &hashset!{"a".into(), "b".into(), "c".into()});
    }

    #[test]
    fn atomic_prepare_timeout() {
        let (txid, addr, port, timeout, payloads) = defaults(7);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");
        let mut fc = Follower::new(txid, "c".into(), Box::new(PrepareTimeout), addr, port, timeout, None).expect("fc");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{});
        assert_eq!(leader.aborted(), &hashset!{"a".into(), "b".into(), "c".into()});
    }

    #[test]
    fn atomic_commit_timeout() {
        let (txid, addr, port, timeout, payloads) = defaults(8);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");
        let mut fc = Follower::new(txid, "c".into(), Box::new(CommitTimeout), addr, port, timeout, None).expect("fc");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        assert!(leader.commit().is_err());
        assert_eq!(leader.committed(), &hashset!{"a".into(), "b".into()});
        assert_eq!(leader.aborted(), &hashset!{"c".into()});
    }

    #[test]
    fn atomic_verify_crash() {
        let (txid, addr, port, timeout, payloads) = defaults(9);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || {
            let path = "/tmp/sota-atomic-verify-crash".to_string();
            let outcome = panic::catch_unwind(|| {
                let mut fc = Follower::new(txid, "c".into(), Box::new(VerifyCrash), addr, port, timeout, Some(path.clone())).expect("fc");
                panic::set_hook(Box::new(|_| ()));
                assert!(fc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut fc = Follower::recover(path, Box::new(Success)).expect("fc recover");
            assert!(fc.listen().is_ok());
        });

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{"a".into(), "b".into(), "c".into()});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_prepare_crash() {
        let (txid, addr, port, timeout, payloads) = defaults(10);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || {
            let path = "/tmp/sota-atomic-prepare-crash".to_string();
            let outcome = panic::catch_unwind(|| {
                let mut fc = Follower::new(txid, "c".into(), Box::new(PrepareCrash), addr, port, timeout, Some(path.clone())).expect("fc");
                panic::set_hook(Box::new(|_| ()));
                assert!(fc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut fc = Follower::recover(path, Box::new(Success)).expect("fc recover");
            assert!(fc.listen().is_ok());
        });

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{"a".into(), "b".into(), "c".into()});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_commit_crash() {
        let (txid, addr, port, timeout, payloads) = defaults(10);
        let mut leader = Leader::new(txid, payloads, addr, port, timeout, None).expect("leader");
        let mut fa = Follower::new(txid, "a".into(), Box::new(Success), addr, port, timeout, None).expect("fa");
        let mut fb = Follower::new(txid, "b".into(), Box::new(Success), addr, port, timeout, None).expect("fb");

        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || {
            let path = "/tmp/sota-atomic-commit-crash".to_string();
            let outcome = panic::catch_unwind(|| {
                let mut fc = Follower::new(txid, "c".into(), Box::new(CommitCrash), addr, port, timeout, Some(path.clone())).expect("fc");
                panic::set_hook(Box::new(|_| ()));
                assert!(fc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut fc = Follower::recover(path, Box::new(Success)).expect("fc recover");
            assert!(fc.listen().is_ok());
        });

        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{"a".into(), "b".into(), "c".into()});
        assert_eq!(leader.aborted(), &hashset!{});
    }
}
