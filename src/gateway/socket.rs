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
    pub commands_path: String,
    pub events_path:   String,
}

impl Gateway for Socket {
    fn start(&mut self, itx: Sender<Interpret>, erx: Receiver<Event>) {
        info!("Starting Socket command listener at {}", self.commands_path);
        info!("Starting Socket event broadcasting to {}", self.events_path);

        let itx  = Arc::new(Mutex::new(itx));
        let _    = fs::remove_file(&self.commands_path);
        let sock = UnixListener::bind(&self.commands_path).expect("couldn't open socket_commands_path");

        thread::spawn(move || {
            for conn in sock.incoming() {
                let _ = conn
                    .map(|stream| spawn_handler(stream, itx.clone()))
                    .map_err(|err| error!("couldn't open socket connection: {}", err));
            }
        });

        let reply = Reply { sock: self.events_path.clone() };
        thread::spawn(move || loop {
            reply.handle_event(erx.recv().expect("dbus etx closed"))
        });
    }
}


fn spawn_handler(mut stream: UnixStream, itx: Arc<Mutex<Sender<Interpret>>>) {
    info!("New socket connection.");
    thread::spawn(move || {
        let resp = parse_stream(&mut stream, itx)
            .map(|ev| json::to_vec(&ev).expect("couldn't encode Event"))
            .unwrap_or_else(|err| format!("{}", err).into_bytes());

        stream.write_all(&resp).unwrap_or_else(|err| error!("couldn't write to commands socket: {}", err));
        stream.shutdown(Shutdown::Write).unwrap_or_else(|err| error!("couldn't close commands socket: {}", err));
    });
}

fn parse_stream(stream: &mut UnixStream, itx: Arc<Mutex<Sender<Interpret>>>) -> Result<Event, Error> {
    let mut reader = BufReader::new(stream);
    let mut input  = String::new();
    reader.read_to_string(&mut input)?;
    debug!("socket input: {}", input);

    let (etx, erx) = chan::async::<Event>();
    let cmd = input.parse::<Command>()?;
    itx.lock().unwrap().send(Interpret { cmd: cmd, etx: Some(Arc::new(Mutex::new(etx))) });
    erx.recv().ok_or(Error::Socket("internal receiver error".to_string()))
}


struct Reply {
    sock: String
}

impl Reply {
    fn handle_event(&self, event: Event) {
        let wrapper = match event {
            Event::DownloadComplete(dl) => EventWrapper::new("DownloadComplete", dl).to_json(),
            Event::DownloadFailed(id, reason) => {
                EventWrapper::new("DownloadFailed", DownloadFailed { update_id: id, reason: reason }).to_json()
            }
            _ => return
        };

        UnixStream::connect(&self.sock)
            .map(|mut stream| {
                stream.write_all(&wrapper)
                    .unwrap_or_else(|err| error!("couldn't write to events socket: {}", err));
                stream.shutdown(Shutdown::Write)
                    .unwrap_or_else(|err| error!("couldn't close events socket: {}", err));
            })
            .unwrap_or_else(|err| debug!("couldn't open events socket: {}", err));
    }
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
        json::to_vec(self).expect("couldn't encode EventWrapper")
    }
}


#[cfg(test)]
mod tests {
    use chan;
    use crossbeam;
    use serde_json as json;
    use std::{fs, thread};
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::time::Duration;

    use datatype::{Command, DownloadComplete, Event};
    use gateway::{Gateway, Interpret};
    use super::*;
    use unix_socket::{UnixListener, UnixStream};


    #[test]
    fn socket_commands_and_events() {
        let (etx, erx) = chan::sync::<Event>(0);
        let (itx, irx) = chan::sync::<Interpret>(0);

        thread::spawn(move || Socket {
            commands_path: "/tmp/sota-commands.socket".to_string(),
            events_path:   "/tmp/sota-events.socket".to_string(),
        }.start(itx, erx));
        thread::sleep(Duration::from_millis(100)); // wait until socket gateway is created

        let path = "/tmp/sota-events.socket";
        let _ = fs::remove_file(&path);
        let server = UnixListener::bind(&path).expect("couldn't create events socket for testing");

        let send = DownloadComplete {
            update_id:    "1".to_string(),
            update_image: "/foo/bar".to_string(),
            signature:    "abc".to_string()
        };
        etx.send(Event::DownloadComplete(send.clone()));

        let (mut stream, _) = server.accept().expect("couldn't read from events socket");
        let mut text = String::new();
        stream.read_to_string(&mut text).unwrap();
        let receive: EventWrapper<DownloadComplete> = json::from_str(&text).expect("couldn't decode Event");
        assert_eq!(receive.version, "0.1".to_string());
        assert_eq!(receive.event, "DownloadComplete".to_string());
        assert_eq!(receive.data, send);

        thread::spawn(move || {
            let _ = etx; // move into this scope
            loop {
                let interpret = irx.recv().unwrap();
                match interpret.cmd {
                    Command::StartDownload(id) => {
                        let resp_tx = interpret.etx.unwrap();
                        resp_tx.lock().unwrap().send(Event::FoundSystemInfo(id));
                    }
                    _ => panic!("expected StartDownload"),
                }
            }
        });

        crossbeam::scope(|scope| {
            for id in 0..10 {
                scope.spawn(move || {
                    let mut stream = UnixStream::connect("/tmp/sota-commands.socket").expect("couldn't connect to socket");
                    let _ = stream.write_all(&format!("dl {}", id).into_bytes()).expect("couldn't write to stream");
                    stream.shutdown(Shutdown::Write).expect("couldn't shut down writing");

                    let mut resp = String::new();
                    stream.read_to_string(&mut resp).expect("couldn't read from stream");
                    let ev: Event = json::from_str(&resp).expect("couldn't decode json event");
                    assert_eq!(ev, Event::FoundSystemInfo(format!("{}", id)));
                });
            }
        });
    }
}
