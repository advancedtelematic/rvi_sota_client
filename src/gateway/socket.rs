use chan;
use chan::Sender;
use rustc_serialize::{Encodable, json};
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
    fn initialize(&mut self, itx: Sender<Interpret>) -> Result<(), String> {
        let _ = fs::remove_file(&self.commands_path);
        let commands = match UnixListener::bind(&self.commands_path) {
            Ok(sock) => sock,
            Err(err) => return Err(format!("couldn't open commands socket: {}", err))
        };

        let itx = Arc::new(Mutex::new(itx));
        thread::spawn(move || {
            for conn in commands.incoming() {
                if let Err(err) = conn {
                    error!("couldn't get commands socket connection: {}", err);
                    continue
                }
                let mut stream = conn.unwrap();
                let itx = itx.clone();

                thread::spawn(move || {
                    let resp = handle_client(&mut stream, itx)
                        .map(|ev| json::encode(&ev).expect("couldn't encode Event").into_bytes())
                        .unwrap_or_else(|err| format!("{}", err).into_bytes());

                    stream.write_all(&resp)
                        .unwrap_or_else(|err| error!("couldn't write to commands socket: {}", err));
                    stream.shutdown(Shutdown::Write)
                        .unwrap_or_else(|err| error!("couldn't close commands socket: {}", err));
                });
            }
        });

        Ok(info!("Socket listening for commands at {} and sending events to {}.",
                 self.commands_path, self.events_path))
    }

    fn pulse(&self, event: Event) {
        let output = match event {
            Event::DownloadComplete(dl) => {
                json::encode(&EventWrapper {
                    version: "0.1".to_string(),
                    event:   "DownloadComplete".to_string(),
                    data:    dl
                }).expect("couldn't encode DownloadComplete event")
            }

            Event::DownloadFailed(id, reason) => {
                json::encode(&EventWrapper {
                    version: "0.1".to_string(),
                    event:   "DownloadFailed".to_string(),
                    data:    DownloadFailed { update_id: id, reason: reason }
                }).expect("couldn't encode DownloadFailed event")
            }

            _ => return
        };

        let _ = UnixStream::connect(&self.events_path).map(|mut stream| {
            stream.write_all(&output.into_bytes())
                .unwrap_or_else(|err| error!("couldn't write to events socket: {}", err));
            stream.shutdown(Shutdown::Write)
                .unwrap_or_else(|err| error!("couldn't close events socket: {}", err));
        }).map_err(|err| debug!("couldn't open events socket: {}", err));
    }
}

fn handle_client(stream: &mut UnixStream, itx: Arc<Mutex<Sender<Interpret>>>) -> Result<Event, Error> {
    info!("New domain socket connection");
    let mut reader = BufReader::new(stream);
    let mut input  = String::new();
    try!(reader.read_to_string(&mut input));
    debug!("socket input: {}", input);

    let cmd = try!(input.parse::<Command>());
    let (etx, erx) = chan::async::<Event>();
    itx.lock().unwrap().send(Interpret { command: cmd, resp_tx: Some(Arc::new(Mutex::new(etx))) });
    erx.recv().ok_or(Error::Socket("internal receiver error".to_string()))
}


// FIXME(PRO-1322): create a proper JSON api
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug)]
pub struct EventWrapper<E: Encodable> {
    pub version: String,
    pub event:   String,
    pub data:    E
}


#[cfg(test)]
mod tests {
    use chan;
    use crossbeam;
    use rustc_serialize::json;
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
        let receive: EventWrapper<DownloadComplete> = json::decode(&text).expect("couldn't decode Event");
        assert_eq!(receive.version, "0.1".to_string());
        assert_eq!(receive.event, "DownloadComplete".to_string());
        assert_eq!(receive.data, send);

        thread::spawn(move || {
            let _ = etx; // move into this scope
            loop {
                let interpret = irx.recv().expect("gtx is closed");
                match interpret.command {
                    Command::StartDownload(id) => {
                        let tx = interpret.resp_tx.unwrap();
                        tx.lock().unwrap().send(Event::FoundSystemInfo(id));
                    }
                    _ => panic!("expected AcceptUpdates"),
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
                    let ev: Event = json::decode(&resp).expect("couldn't decode json event");
                    assert_eq!(ev, Event::FoundSystemInfo(format!("{}", id)));
                });
            }
        });
    }
}
