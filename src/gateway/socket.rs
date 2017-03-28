use chan::{self, Sender, Receiver};
use serde::ser::Serialize;
use serde_json as json;
use std::io::{BufReader, Read, Write};
use std::net::Shutdown;
use std::sync::{Arc, Mutex};
use std::{fs, thread};

use datatype::{Command, DownloadFailed, Error, Event};
use super::{Gateway, Interpret};
use unix_socket::{UnixListener, UnixStream};


/// The `Socket` gateway is used for communication via Unix Domain Sockets.
pub struct Socket {
    pub cmd_sock: String,
    pub ev_sock:  String,
}

impl Gateway for Socket {
    fn start(&mut self, itx: Sender<Interpret>, erx: Receiver<Event>) {
        info!("Listening for commands at socket {}", self.cmd_sock);
        info!("Sending events to socket {}", self.ev_sock);
        let _ = fs::remove_file(&self.cmd_sock);
        let cmd_sock = UnixListener::bind(&self.cmd_sock).expect("command socket");

        let ev_sock = self.ev_sock.clone();
        thread::spawn(move || loop {
            handle_event(&ev_sock, erx.recv().expect("socket events"))
        });

        for conn in cmd_sock.incoming() {
            let _ = conn
                .map_err(|err| error!("couldn't open socket connection: {}", err))
                .map(|stream| {
                    let itx = itx.clone();
                    thread::spawn(move || handle_stream(stream, &itx));
                });
        }
    }
}


fn handle_stream(mut stream: UnixStream, itx: &Sender<Interpret>) {
    info!("New socket connection.");
    let resp = parse_command(&mut stream, itx)
        .map(|ev| json::to_vec(&ev).expect("couldn't encode Event"))
        .unwrap_or_else(|err| format!("{}", err).into_bytes());

    stream.write_all(&resp).unwrap_or_else(|err| error!("couldn't write to commands socket: {}", err));
    stream.shutdown(Shutdown::Write).unwrap_or_else(|err| error!("couldn't close commands socket: {}", err));
}

fn parse_command(stream: &mut UnixStream, itx: &Sender<Interpret>) -> Result<Event, Error> {
    let mut reader = BufReader::new(stream);
    let mut input  = String::new();
    reader.read_to_string(&mut input)?;
    debug!("socket input: {}", input);

    let cmd = input.parse::<Command>()?;
    let (etx, erx) = chan::async::<Event>();
    itx.send(Interpret { cmd: cmd, etx: Some(Arc::new(Mutex::new(etx))) });
    erx.recv().ok_or_else(|| Error::Socket("internal receiver error".to_string()))
}

fn handle_event(ev_sock: &str, event: Event) {
    let reply = match event {
        Event::DownloadComplete(dl) => {
            EventWrapper::new("DownloadComplete", dl).to_json()
        }

        Event::DownloadFailed(id, reason) => {
            EventWrapper::new("DownloadFailed", DownloadFailed { update_id: id, reason: reason }).to_json()
        }

        _ => return
    };

    let _ = UnixStream::connect(ev_sock)
        .map_err(|err| debug!("couldn't open events socket: {}", err))
        .map(|mut stream| {
            stream.write_all(&reply).unwrap_or_else(|err| error!("couldn't write to events socket: {}", err));
            stream.shutdown(Shutdown::Write).unwrap_or_else(|err| error!("couldn't close events socket: {}", err));
        });
}


// FIXME(PRO-1322): create a proper JSON api
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct EventWrapper<S: Serialize> {
    pub version: String,
    pub event:   String,
    pub data:    S
}

impl<S: Serialize> EventWrapper<S> {
    fn new(event: &str, data: S) -> Self {
        EventWrapper { version: "0.1".into(), event: event.into(), data: data }
    }

    fn to_json(&self) -> Vec<u8> {
        json::to_vec(self).expect("encode EventWrapper")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use chan;
    use crossbeam;
    use serde_json as json;
    use std::{fs, thread};
    use std::io::Write;
    use std::net::Shutdown;
    use uuid::Uuid;

    use datatype::{Command, DownloadComplete, Event};
    use gateway::{Gateway, Interpret};
    use unix_socket::{UnixListener, UnixStream};


    const CMD_SOCK: &'static str = "/tmp/sota-commands.socket";
    const EV_SOCK:  &'static str = "/tmp/sota-events.socket";

    #[test]
    fn socket_commands_and_events() {
        let (etx, erx) = chan::sync::<Event>(0);
        let (itx, irx) = chan::sync::<Interpret>(0);
        let mut socket = Socket { cmd_sock: CMD_SOCK.into(), ev_sock: EV_SOCK.into() };
        thread::spawn(move || socket.start(itx, erx));

        let _ = fs::remove_file(EV_SOCK);
        let serv = UnixListener::bind(EV_SOCK).expect("open events socket");
        let send = DownloadComplete { update_id: Uuid::default(), update_image: "/foo".into(), signature: "sig".into() };
        etx.send(Event::DownloadComplete(send.clone()));

        let (stream, _) = serv.accept().expect("read events socket");
        let recv: EventWrapper<DownloadComplete> = json::from_reader(&stream).expect("recv event");
        assert_eq!(recv.version, "0.1".to_string());
        assert_eq!(recv.event, "DownloadComplete".to_string());
        assert_eq!(recv.data, send);

        thread::spawn(move || {
            let _ = etx; // move into this scope
            loop {
                match irx.recv() {
                    Some(Interpret { cmd: Command::StartInstall(id), etx: Some(etx) }) => {
                        etx.lock().unwrap().send(Event::InstallingUpdate(id));
                    }
                    Some(_) => panic!("expected StartInstall"),
                    None    => break
                }
            }
        });

        crossbeam::scope(|scope| {
            for n in 0..10 {
                scope.spawn(move || {
                    let id = format!("00000000-0000-0000-0000-00000000000{}", n).parse::<Uuid>().unwrap();
                    let mut stream = UnixStream::connect(CMD_SOCK).expect("open command socket");
                    let _ = stream.write_all(&format!("inst {}", id).into_bytes()).expect("write to stream");
                    stream.shutdown(Shutdown::Write).expect("shut down writing");
                    assert_eq!(Event::InstallingUpdate(id), json::from_reader(&stream).expect("read event"));
                });
            }
        });
    }
}
