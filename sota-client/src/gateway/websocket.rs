use chan::{self, Sender, Receiver};
use json;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use tungstenite::{self, Message, WebSocket};

use datatype::{Command, Event};
use gateway::Gateway;
use interpreter::CommandExec;


pub struct Websocket {
    pub server: String
}

impl Gateway for Websocket {
    fn start(&mut self, ctx: Sender<CommandExec>, _: Receiver<Event>) {
        info!("Starting Websocket gateway at {}.", self.server);
        let mut addr: Vec<_> = self.server.to_socket_addrs().expect("websocket server").collect();
        let server = TcpListener::bind(&addr.pop().expect("websocket address")).expect("websocket listener");

        for stream in server.incoming() {
            let _ = stream
                .map_err(|err| error!("Opening websocket: {}", err))
                .map(|stream| tungstenite::accept(stream).map(|sock| {
                    let ctx = ctx.clone();
                    thread::spawn(move || handle_socket(sock, &ctx));
                }));
        }
    }
}


fn handle_socket(mut socket: WebSocket<TcpStream>, ctx: &Sender<CommandExec>) {
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
                    ctx.send(CommandExec { cmd: cmd, etx: Some(etx) });
                    let reply = json::to_string(&erx.recv().expect("websocket response")).expect("json reply");
                    socket.write_message(Message::Text(reply)).map_err(|err| error!("Writing to websocket: {}", err))
                });
        });
    socket.close(None).unwrap_or_else(|err| error!("Closing websocket: {}", err))
}


#[cfg(all(test, not(feature = "docker")))]
mod tests {
    use super::*;
    use crossbeam;
    use std::time::Duration;
    use uuid::Uuid;


    #[test]
    fn websocket_connections() {
        let (ctx, crx) = chan::sync::<CommandExec>(0);
        let (etx, erx) = chan::sync::<Event>(0);
        thread::spawn(move || Websocket { server: "localhost:3012".into() }.start(ctx, erx));
        thread::sleep(Duration::from_millis(100)); // wait before connecting

        thread::spawn(move || {
            let _ = etx; // move into this scope
            loop {
                match crx.recv() {
                    Some(CommandExec { cmd: Command::StartInstall(id), etx: Some(etx) }) => {
                        etx.send(Event::InstallingUpdate(id));
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
                    sock.close(None).expect("close");
                });
            }
        });
    }
}
