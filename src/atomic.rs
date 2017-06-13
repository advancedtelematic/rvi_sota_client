use serde_json as json;
use std::fs::{self, File};
use std::io::{BufReader, ErrorKind};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};
use net2::{UdpBuilder, UdpSocketExt};
use net2::unix::UnixUdpBuilderExt;
use uuid::Uuid;

use datatype::{Error, TufSigned, Util};


lazy_static! {
    static ref VALID_TRANSITIONS: HashMap<State, Vec<State>> = hashmap! {
        State::Sleep   => vec![State::Ready],
        State::Ready   => vec![State::Verify],
        State::Verify  => vec![State::Abort, State::Prepare],
        State::Prepare => vec![State::Abort, State::Commit],
        State::Commit  => vec![State::Abort],
        State::Abort   => vec![],
    };
}

const BUFFER_SIZE: usize = 100*1024;


/// Define the interface for communication between nodes.
pub trait Bus: Send {
    fn read_message(&mut self) -> Result<Message, Error>;
    fn write_message(&self, msg: &Message) -> Result<(), Error>;
}

/// Transition a `Follower` to the next state.
pub trait Next: Send {
    fn next(&mut self, state: State, payload: &[u8]) -> Result<(), String>;
}


/// A mapping from serials to the payloads to be delivered at each state.
pub type Payloads = HashMap<String, HashMap<State, Vec<u8>>>;

/// Send a message to be picked up by either a `Leader` or a `Follower`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Message {
    Wake  { txid: Uuid, serial: String },
    Next  { txid: Uuid, serial: String, state: State, payload: Vec<u8> },
    Ack   { txid: Uuid, serial: String, state: State },
    Query { txid: Uuid },
    End   { txid: Uuid, signed: TufSigned },
}

/// An enumeration of all possible states for a `Leader` or `Follower`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Sleep,
    Ready,
    Verify,
    Prepare,
    Commit,
    Abort,
}


/// A `Leader` is responsible for coordinating the state changes of followers.
#[derive(Serialize, Deserialize)]
pub struct Leader {
    txid:  Uuid,
    state: State,

    payloads: Payloads,
    acks:     HashMap<State, HashSet<String>>,
    timeout:  Duration,
    recover:  Option<String>,

    #[serde(skip_serializing, skip_deserializing)]
    started: Option<Instant>,
    #[serde(skip_serializing, skip_deserializing)]
    bus: Option<Box<Bus>>,
    #[serde(skip_serializing, skip_deserializing)]
    signed: Option<Vec<TufSigned>>,
}

impl Leader {
    /// Create a new `Leader` to coordinate `Follower` changes for a specific txid.
    pub fn new(bus: Box<Bus>, payloads: Payloads, timeout: Duration, recover: Option<String>) -> Result<Self, Error> {
        let mut leader = Leader {
            txid:  Uuid::new_v4(),
            state: State::Sleep,

            payloads: payloads,
            acks: hashmap! {
                State::Ready   => HashSet::new(),
                State::Verify  => HashSet::new(),
                State::Prepare => HashSet::new(),
                State::Commit  => HashSet::new(),
                State::Abort   => HashSet::new(),
            },
            timeout: timeout,
            recover: recover,

            started: Some(Instant::now()),
            bus:     Some(bus),
            signed:  Some(Vec::new()),
        };

        for (serial, _) in &leader.payloads {
            leader.write_message(&Message::Wake { txid: leader.txid, serial: serial.clone() })?;
        }
        leader.transition(State::Ready)?;
        Ok(leader)
    }

    /// Recover from a crash by requesting an update on all `Follower` states.
    pub fn recover<P: AsRef<Path>>(path: P, bus: Box<Bus>) -> Result<Self, Error> {
        let mut leader: Leader = json::from_reader(BufReader::new(File::open(&path)?))?;
        info!("Leader state recovered from `{}`", path.as_ref().display());
        leader.bus = Some(bus);
        leader.write_message(&Message::Query { txid: leader.txid })?;
        Ok(leader)
    }

    /// Start the three-phase commit process with each `Follower`.
    pub fn commit(&mut self) -> Result<(), Error> {
        info!("Transaction {} starting.", self.txid);
        self.transition(State::Verify)?;
        self.transition(State::Prepare)?;
        self.transition(State::Commit)?;
        info!("Transaction {} complete.", self.txid);

        if let Some(ref path) = self.recover {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Transition all followers to the next state.
    pub fn transition(&mut self, state: State) -> Result<(), Error> {
        if ! self.valid_transition(state) { return Ok(()) }
        info!("Transaction {} moving to {:?}.", self.txid, state);
        self.checkpoint(state)?;
        self.send_request(state)?;

        while self.state == state && self.acks(state).len() < self.payloads.len() {
            self.read_message()
                .and_then(|msg| self.handle_response(msg))
                .or_else(|err| {
                    if is_waiting(&err) && self.is_timeout() {
                        self.transition(State::Abort)?;
                        Err(Error::AtomicTimeout)
                    } else if is_waiting(&err) {
                        self.write_message(&Message::Query { txid: self.txid })
                    } else {
                        self.transition(State::Abort)?;
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
            self.write_message(&Message::Next {
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
                    self.transition(State::Abort)
                } else {
                    Ok(())
                }
            }
            Message::End { txid, signed } => {
                if txid == self.txid { self.signed.as_mut().expect("signed").push(signed); }
                Ok(())
            }
            Message::Wake  { .. } => Ok(()),
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

    fn acks(&mut self, state: State) -> &mut HashSet<String> {
        self.acks.get_mut(&state).expect("get acks")
    }

    pub fn committed(&self) -> &HashSet<String> {
        self.acks.get(&State::Commit).expect("commit acks")
    }

    pub fn aborted(&self) -> &HashSet<String> {
        self.acks.get(&State::Abort).expect("abort acks")
    }

    fn is_timeout(&self) -> bool {
        Instant::now().duration_since(self.started.expect("started")) > self.timeout
    }

    fn valid_transition(&self, state: State) -> bool {
        VALID_TRANSITIONS.get(&self.state).expect("transitions").contains(&state)
    }

    fn read_message(&mut self) -> Result<Message, Error> {
        self.bus.as_mut().expect("bus").read_message()
    }

    fn write_message(&self, msg: &Message) -> Result<(), Error> {
        self.bus.as_ref().expect("bus").write_message(msg)
    }
}


/// A `Follower` awaits instructions from a `Leader` to transition between states.
#[derive(Serialize, Deserialize)]
pub struct Follower {
    txid:    Option<Uuid>,
    serial:  String,
    state:   State,
    timeout: Duration,
    recover: Option<String>,

    #[serde(skip_serializing, skip_deserializing)]
    started: Option<Instant>,
    #[serde(skip_serializing, skip_deserializing)]
    bus: Option<Box<Bus>>,
    #[serde(skip_serializing, skip_deserializing)]
    next: Option<Box<Next>>,
}

impl Follower {
    /// Create a `Follower` that listens for bus requests for state transitions.
    pub fn new(serial: String, bus: Box<Bus>, next: Box<Next>, timeout: Duration, recover: Option<String>) -> Self {
        Follower {
            txid:    None,
            serial:  serial,
            state:   State::Sleep,
            timeout: timeout,
            recover: recover,

            started: Some(Instant::now()),
            bus:     Some(bus),
            next:    Some(next),
        }
    }

    /// Recover from a crash while a transaction was in progress.
    pub fn recover<P: AsRef<Path>>(path: P, bus: Box<Bus>, next: Box<Next>) -> Result<Self, Error> {
        let mut follower: Follower = json::from_reader(BufReader::new(File::open(&path)?))?;
        info!("Follower `{}` state recovered from `{}`", follower.serial, path.as_ref().display());
        follower.bus  = Some(bus);
        follower.next = Some(next);
        follower.write_ack()?;
        Ok(follower)
    }

    /// Block until a wake-up signal is received then read new transaction
    /// messages until we reach a terminating state.
    pub fn listen(&mut self) -> Result<(), Error> {
        while self.state != State::Commit && self.state != State::Abort {
            self.read_message()
                .and_then(|msg| self.handle_request(msg))
                .or_else(|err| {
                    if is_waiting(&err) && self.is_timeout() {
                        self.transition(State::Abort, &Vec::new())?;
                        Err(Error::AtomicTimeout)
                    } else if is_waiting(&err) {
                        self.write_ack()
                    } else {
                        let _ = self.transition(State::Abort, &Vec::new());
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
            Message::Wake { txid, serial } => {
                if serial != self.serial || self.state != State::Sleep { return Ok(()) }
                self.txid = Some(txid);
                self.transition(State::Ready, &Vec::new())
            }
            Message::Next { txid, serial, state, payload } => {
                if txid != self.txid() || serial != self.serial { return Ok(()) }
                self.transition(state, &payload)
            }
            Message::Query { txid } => {
                if txid != self.txid() { return Ok(()) }
                self.write_ack()
            }
            Message::Ack { .. } => Ok(()),
            Message::End { .. } => Ok(()),
        }
    }

    fn transition(&mut self, state: State, payload: &[u8]) -> Result<(), Error> {
        if self.state == state || ! self.valid_transition(state) { return Ok(()) }
        debug!("serial {}: moving to {:?}", self.serial, state);
        self.checkpoint(state, payload)?;
        self.next(state, payload)
            .or_else(|reason| {
                error!("serial {}: {}", self.serial, reason);
                self.transition(State::Abort, &Vec::new())?;
                Err(Error::AtomicAbort(reason))
            })
            .and_then(|_| self.write_ack())
    }

    fn checkpoint(&mut self, state: State, _: &[u8]) -> Result<(), Error> {
        self.started = Some(Instant::now());
        self.state = state;
        if let Some(ref path) = self.recover {
            Util::write_file(path, &json::to_vec(self)?)?;
        }
        Ok(())
    }

    fn next(&mut self, state: State, payload: &[u8]) -> Result<(), String> {
        self.next.as_mut().expect("next interface").next(state, payload)
    }

    fn txid(&self) -> Uuid {
        self.txid.unwrap_or_else(|| Uuid::default())
    }

    fn is_timeout(&self) -> bool {
        Instant::now().duration_since(self.started.expect("started")) > self.timeout
    }

    fn valid_transition(&self, state: State) -> bool {
        VALID_TRANSITIONS.get(&self.state).expect("transitions").contains(&state)
    }

    fn read_message(&mut self) -> Result<Message, Error> {
        self.bus.as_mut().expect("bus").read_message()
    }

    fn write_message(&self, msg: &Message) -> Result<(), Error> {
        self.bus.as_ref().expect("bus").write_message(msg)
    }

    fn write_ack(&self) -> Result<(), Error> {
        self.write_message(&Message::Ack { txid: self.txid(), serial: self.serial.clone(), state: self.state })
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
    socket: UdpSocket,
    addr: SocketAddrV4,
}

impl Multicast {
    pub fn new(addr: SocketAddrV4) -> Result<Self, Error> {
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
        Ok(Multicast { socket: socket, addr: addr })
    }
}

impl Bus for Multicast {
    fn read_message(&mut self) -> Result<Message, Error> {
        let mut buf = Box::new(vec![0; BUFFER_SIZE]);
        let (len, _) = self.socket.recv_from(&mut buf).map_err(Error::Io)?;
        Ok(json::from_slice(&buf[..len])?)
    }

    fn write_message(&self, msg: &Message) -> Result<(), Error> {
        trace!("writing message: {:?}", msg);
        let _ = self.socket.send_to(&json::to_vec(msg)?, self.addr)?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::{panic, thread};


    lazy_static! {
        static ref TIMEOUT: Duration = Duration::from_secs(2);
    }

    struct Success;
    impl Next for Success {
        fn next(&mut self, _: State, _: &[u8]) -> Result<(), String> { Ok(()) }
    }

    struct VerifyPayload;
    impl Next for VerifyPayload {
        fn next(&mut self, state: State, payload: &[u8]) -> Result<(), String> {
            if state == State::Verify && payload != b"verify payload" {
                Err("unexpected payload".into())
            } else {
                Ok(())
            }
        }
    }

    struct VerifyFail;
    impl Next for VerifyFail {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Verify { Err("verify failed".into()) } else { Ok(()) }
        }
    }

    struct PrepareFail;
    impl Next for PrepareFail {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Prepare { Err("prepare failed".into()) } else { Ok(()) }
        }
    }

    struct CommitFail;
    impl Next for CommitFail {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Commit { Err("commit failed".into()) } else { Ok(()) }
        }
    }

    struct VerifyTimeout;
    impl Next for VerifyTimeout {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Verify { thread::sleep(Duration::from_secs(10)) }
            Ok(())
        }
    }

    struct PrepareTimeout;
    impl Next for PrepareTimeout {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Prepare { thread::sleep(Duration::from_secs(10)) }
            Ok(())
        }
    }

    struct CommitTimeout;
    impl Next for CommitTimeout {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Commit { thread::sleep(Duration::from_secs(10)) }
            Ok(())
        }
    }

    struct VerifyCrash;
    impl Next for VerifyCrash {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Verify { panic!("verify crashed"); } else { Ok(()) }
        }
    }

    struct PrepareCrash;
    impl Next for PrepareCrash {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Prepare { panic!("prepare crashed"); } else { Ok(()) }
        }
    }

    struct CommitCrash;
    impl Next for CommitCrash {
        fn next(&mut self, state: State, _: &[u8]) -> Result<(), String> {
            if state == State::Commit { panic!("commit crashed"); } else { Ok(()) }
        }
    }


    fn bus() -> Box<Bus> {
        Box::new(Multicast::new(SocketAddrV4::new(Ipv4Addr::new(232,0,0,101), 23201)).expect("multicast"))
    }

    fn serials(prefix: &str) -> (String, String, String) {
        (format!("{}_a", prefix), format!("{}_b", prefix), format!("{}_c", prefix))
    }

    fn payloads(a: &str, b: &str, c: &str) -> Payloads {
        hashmap!{a.into() => hashmap!{}, b.into() => hashmap!{}, c.into() => hashmap!{} }
    }

    #[test]
    fn atomic_ok() {
        let (a, b, c) = serials("ok");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fc = Follower::new(c.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_ok()));

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{a, b, c});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_verify_payload() {
        let (a, b, c) = serials("verify_payload");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(VerifyPayload), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(VerifyPayload), *TIMEOUT, None);
        let mut fc = Follower::new(c.clone(), bus(), Box::new(VerifyPayload), *TIMEOUT, None);
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_ok()));

        let payloads = hashmap!{
            a.clone() => hashmap!{State::Verify => "verify payload".as_bytes().into()},
            b.clone() => hashmap!{State::Verify => "verify payload".as_bytes().into()},
            c.clone() => hashmap!{State::Verify => "verify payload".as_bytes().into()},
        };
        let mut leader = Leader::new(bus(), payloads, *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{a, b, c});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[test]
    fn atomic_verify_fail() {
        let (a, b, c) = serials("verify_fail");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fc = Follower::new(c.clone(), bus(), Box::new(VerifyFail), *TIMEOUT, None);
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{});
        assert_eq!(leader.aborted(), &hashset!{a, b, c});
    }

    #[test]
    fn atomic_prepare_fail() {
        let (a, b, c) = serials("prepare_fail");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fc = Follower::new(c.clone(), bus(), Box::new(PrepareFail), *TIMEOUT, None);
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{});
        assert_eq!(leader.aborted(), &hashset!{a, b, c});
    }

    #[test]
    fn atomic_commit_fail() {
        let (a, b, c) = serials("commit_fail");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fc = Follower::new(c.clone(), bus(), Box::new(CommitFail), *TIMEOUT, None);
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_err()));

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_err());
        assert_eq!(leader.committed(), &hashset!{a, b});
        assert_eq!(leader.aborted(), &hashset!{c});
    }

    #[test]
    fn atomic_verify_timeout() {
        let (a, b, c) = serials("verify_timeout");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fc = Follower::new(c.clone(), bus(), Box::new(VerifyTimeout), *TIMEOUT, None);
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_ok()));

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_err());
        assert_eq!(leader.committed(), &hashset!{});
        assert_eq!(leader.aborted(), &hashset!{a, b});
    }

    #[test]
    fn atomic_prepare_timeout() {
        let (a, b, c) = serials("prepare_timeout");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fc = Follower::new(c.clone(), bus(), Box::new(PrepareTimeout), *TIMEOUT, None);
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_ok()));

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_err());
        assert_eq!(leader.committed(), &hashset!{});
        assert_eq!(leader.aborted(), &hashset!{a, b});
    }

    #[test]
    fn atomic_commit_timeout() {
        let (a, b, c) = serials("commit_timeout");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fc = Follower::new(c.clone(), bus(), Box::new(CommitTimeout), *TIMEOUT, None);
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || assert!(fc.listen().is_ok()));

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_err());
        assert_eq!(leader.committed(), &hashset!{a, b});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[cfg(not(feature = "docker"))]
    #[test]
    fn atomic_verify_crash() {
        let (a, b, c) = serials("verify_crash");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let c2 = c.clone();
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || {
            let path = "/tmp/sota-atomic-verify-crash".to_string();
            let outcome = panic::catch_unwind(|| {
                let mut fc = Follower::new(c2, bus(), Box::new(VerifyCrash), *TIMEOUT, Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(fc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut fc = Follower::recover(path, bus(), Box::new(Success)).expect("recover");
            assert!(fc.listen().is_ok());
        });

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{a, b, c});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[cfg(not(feature = "docker"))]
    #[test]
    fn atomic_prepare_crash() {
        let (a, b, c) = serials("prepare_crash");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let c2 = c.clone();
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || {
            let path = "/tmp/sota-atomic-prepare-crash".to_string();
            let outcome = panic::catch_unwind(|| {
                let mut fc = Follower::new(c2, bus(), Box::new(PrepareCrash), *TIMEOUT, Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(fc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut fc = Follower::recover(path, bus(), Box::new(Success)).expect("recover");
            assert!(fc.listen().is_ok());
        });

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{a, b, c});
        assert_eq!(leader.aborted(), &hashset!{});
    }

    #[cfg(not(feature = "docker"))]
    #[test]
    fn atomic_commit_crash() {
        let (a, b, c) = serials("commit_crash");
        let mut fa = Follower::new(a.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let mut fb = Follower::new(b.clone(), bus(), Box::new(Success), *TIMEOUT, None);
        let c2 = c.clone();
        thread::spawn(move || assert!(fa.listen().is_ok()));
        thread::spawn(move || assert!(fb.listen().is_ok()));
        thread::spawn(move || {
            let path = "/tmp/sota-atomic-commit-crash".to_string();
            let outcome = panic::catch_unwind(|| {
                let mut fc = Follower::new(c2, bus(), Box::new(CommitCrash), *TIMEOUT, Some(path.clone()));
                panic::set_hook(Box::new(|_| ()));
                assert!(fc.listen().is_err());
            });
            assert!(outcome.is_err());
            let mut fc = Follower::recover(path, bus(), Box::new(Success)).expect("recover");
            assert!(fc.listen().is_ok());
        });

        let mut leader = Leader::new(bus(), payloads(&a, &b, &c), *TIMEOUT, None).expect("leader");
        assert!(leader.commit().is_ok());
        assert_eq!(leader.committed(), &hashset!{a, b, c});
        assert_eq!(leader.aborted(), &hashset!{});
    }
}
