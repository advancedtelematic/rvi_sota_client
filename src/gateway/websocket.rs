use chan;
use chan::Sender;
use rustc_serialize::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use ws;
use ws::{CloseCode, Handler, Handshake, Message, Sender as WsSender};
use ws::util::Token;

use datatype::{Command, Error, Event};
use super::gateway::{Gateway, Interpret};


/// The `Websocket` gateway allows connected clients to listen to `Event`s that
/// happen in the SOTA client.
pub struct Websocket {
    pub server:  String,
    pub clients: Arc<Mutex<HashMap<Token, WsSender>>>
}

impl Gateway for Websocket {
    fn initialize(&mut self, itx: Sender<Interpret>) -> Result<(), String> {
        let clients = self.clients.clone();
        let addr    = self.server.clone();

        thread::spawn(move || {
            ws::listen(&addr as &str, |out| {
                WebsocketHandler {
                    out:     out,
                    itx:     itx.clone(),
                    clients: clients.clone()
                }
            }).expect("couldn't start websocket listener");
        });

        Ok(info!("Websocket gateway started at {}.", self.server))
    }

    fn pulse(&self, event: Event) {
        let json = encode(event);
        for (_, out) in self.clients.lock().unwrap().iter() {
            let _ = out.send(Message::Text(json.clone()));
        }
    }
}


pub struct WebsocketHandler {
    out:     WsSender,
    itx:     Sender<Interpret>,
    clients: Arc<Mutex<HashMap<Token, WsSender>>>
}

impl Handler for WebsocketHandler {
    fn on_message(&mut self, msg: Message) -> ws::Result<()> {
        debug!("received websocket message: {:?}", msg);
        msg.as_text().or_else(|err| {
            error!("websocket on_message text error: {}", err);
            Err(err)
        }).and_then(|msg| match decode(msg) {
            Ok(cmd) => Ok(self.forward_command(cmd)),

            Err(Error::Websocket(err)) => {
                error!("websocket on_message error: {}", err);
                Err(err)
            }

            Err(err) => panic!("unexpected websocket on_message error: {}", err)
        })
    }

    fn on_open(&mut self, _: Handshake) -> ws::Result<()> {
        let _ = self.clients.lock().unwrap().insert(self.out.token(), self.out.clone());
        Ok(debug!("new websocket client: {:?}", self.out.token()))
    }

    fn on_close(&mut self, code: CloseCode, _: &str) {
        let _ = self.clients.lock().unwrap().remove(&self.out.token());
        debug!("closing websocket client {:?}: {:?}", self.out.token(), code);
    }

    fn on_error(&mut self, err: ws::Error) {
        error!("websocket error: {:?}", err);
    }
}

impl WebsocketHandler {
    fn forward_command(&self, cmd: Command) {
        let (etx, erx) = chan::sync::<Event>(0);
        let etx        = Arc::new(Mutex::new(etx.clone()));
        self.itx.send(Interpret { command: cmd, response_tx: Some(etx) });

        let e = erx.recv().expect("websocket response_tx is closed");
        let _ = self.out.send(Message::Text(encode(e)));
    }
}

fn encode(event: Event) -> String {
    json::encode(&event).expect("Error encoding event into JSON")
}

fn decode(s: &str) -> Result<Command, Error> {
    Ok(try!(json::decode::<Command>(s)))
}


#[cfg(test)]
mod tests {
    use chan;
    use crossbeam;
    use rustc_serialize::json;
    use std::thread;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use ws;
    use ws::CloseCode;

    use datatype::{Command, Event};
    use gateway::{Gateway, Interpret};
    use super::*;


    #[test]
    fn websocket_connections() {
        let (etx, erx) = chan::sync::<Event>(0);
        let (itx, irx) = chan::sync::<Interpret>(0);

        thread::spawn(move || {
            Websocket {
                server:  "localhost:3012".to_string(),
                clients: Arc::new(Mutex::new(HashMap::new()))
            }.start(itx, erx);
        });
        thread::spawn(move || {
            let _ = etx; // move into this scope
            loop {
                let interpret = irx.recv().expect("gtx is closed");
                match interpret.command {
                    Command::StartDownload(id) => {
                        let tx = interpret.response_tx.unwrap();
                        tx.lock().unwrap().send(Event::FoundSystemInfo(id));
                    }
                    _ => panic!("expected AcceptUpdates"),
                }
            }
        });

        crossbeam::scope(|scope| {
            for id in 0..10 {
                scope.spawn(move || {
                    ws::connect("ws://localhost:3012", |out| {
                        let msg = format!(r#"{{ "variant": "StartDownload", "fields": [["{}"]] }}"#, id);
                        out.send(msg).expect("couldn't write to websocket");

                        move |msg: ws::Message| {
                            let ev: Event = json::decode(&format!("{}", msg)).unwrap();
                            assert_eq!(ev, Event::FoundSystemInfo(format!("{}", id)));
                            out.close(CloseCode::Normal)
                        }
                    }).expect("couldn't connect to websocket");
                });
            }
        });
    }
}
