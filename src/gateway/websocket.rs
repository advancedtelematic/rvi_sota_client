use chan::{self, Sender, Receiver};
use serde_json as json;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use tungstenite::{self, Message, WebSocket};

use datatype::{Command, Event};
use gateway::{Gateway, Interpret};


// FIXME(PRO-2835): broadcast system events
pub struct Websocket {
    pub server: String
}

impl Gateway for Websocket {
    fn start(&mut self, itx: Sender<Interpret>, _: Receiver<Event>) {
        info!("Starting Websocket gateway at {}.", self.server);
        let mut addr: Vec<_> = self.server.to_socket_addrs().expect("websocket server").collect();
        let server = TcpListener::bind(&addr.pop().expect("websocket address")).expect("websocket listener");

        for stream in server.incoming() {
            let _ = stream
                .map_err(|err| error!("Opening websocket: {}", err))
                .map(|stream| tungstenite::accept(stream).map(|sock| {
                    let itx = itx.clone();
                    thread::spawn(move || handle_socket(sock, &itx));
                }));
        }
    }
}


fn handle_socket(mut socket: WebSocket<TcpStream>, itx: &Sender<Interpret>) {
    let _ = socket.read_message()
        .map_err(|err| error!("Websocket message: {}", err))
        .map(|msg| {
            let text = match msg {
                Message::Text(text) => text,
                Message::Binary(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => text,
                    Err(err) => { error!("Websocket data: {}", err); return; }
                }
            };

            let _ = json::from_str::<Command>(&text)
                .map_err(|err| error!("Websocket request not a command: {}", err))
                .map(|cmd| {
                    let (etx, erx) = chan::sync::<Event>(0);
                    itx.send(Interpret { cmd: cmd, etx: Some(Arc::new(Mutex::new(etx.clone()))) });
                    let reply = json::to_string(&erx.recv().expect("websocket response")).expect("json reply");
                    socket.write_message(Message::Text(reply)).map_err(|err| error!("Writing to websocket: {}", err))
                });
        });
    let _ = socket.close();
}


#[cfg(test)]
mod tests {
    use super::*;

    use chan;
    use crossbeam;
    use serde_json as json;
    use std::thread;
    use std::time::Duration;
    use tungstenite;
    use uuid::Uuid;

    use datatype::{Command, Event};
    use gateway::{Gateway, Interpret};


    #[test]
    fn websocket_connections() {
        let (etx, erx) = chan::sync::<Event>(0);
        let (itx, irx) = chan::sync::<Interpret>(0);
        thread::spawn(move || Websocket { server: "localhost:3012".into() }.start(itx, erx));
        thread::sleep(Duration::from_millis(100)); // wait before connecting

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
                    let mut sock = tungstenite::connect("ws://localhost:3012".parse().expect("url")).expect("connect");
                    let id = format!("00000000-0000-0000-0000-00000000000{}", n).parse::<Uuid>().unwrap();
                    let msg = Message::Text(json::to_string(&Command::StartInstall(id.clone())).expect("json"));
                    sock.write_message(msg).expect("write");

                    let reply = format!("{}", sock.read_message().expect("reply"));
                    let event = json::from_str::<Event>(&reply).expect("event");
                    assert_eq!(event, Event::InstallingUpdate(id));
                    sock.close().expect("close");
                });
            }
        });
    }
}
