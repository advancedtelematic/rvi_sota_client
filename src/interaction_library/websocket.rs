use chan;
use chan::Sender;
use rustc_serialize::{json, Decodable, Encodable};
use std::{env, thread};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use ws;
use ws::{listen, CloseCode, Handler, Handshake, Message, Sender as WsSender};
use ws::util::Token;

use super::gateway::{Gateway, Interpret};
use datatype::Error;


pub struct Websocket {
    clients: Arc<Mutex<HashMap<Token, WsSender>>>
}

impl<C, E> Gateway<C, E> for Websocket
    where C: Decodable + Send + Clone + Debug + 'static,
          E: Encodable + Send + Clone + Debug + 'static,
{
    fn new(itx: Sender<Interpret<C, E>>) -> Result<Self, String> {
        let clients = Arc::new(Mutex::new(HashMap::new()));
        let addr    = env::var("SOTA_WEBSOCKET_ADDR").unwrap_or("127.0.0.1:3012".to_string());

        let handler_clients = clients.clone();
        let (start_tx, start_rx) = chan::sync::<Result<(), ws::Error>>(0);
        thread::spawn(move || {
            info!("Opening websocket listener on {}", addr);
            start_tx.send(listen(&addr as &str, |out| {
                WebsocketHandler {
                    out:     out,
                    itx:     itx.clone(),
                    clients: handler_clients.clone()
                }
            }));
        });

        let tick = chan::tick_ms(1000); // FIXME: ugly hack for blocking call
        chan_select! {
            tick.recv()                => return Ok(Websocket{ clients: clients }),
            start_rx.recv() -> outcome => match outcome {
                Some(outcome) => match outcome {
                    Ok(_)    => return Ok(Websocket{ clients: clients }),
                    Err(err) => return Err(format!("couldn't open websocket listener: {}", err))
                },
                None => panic!("expected websocket start outcome")
            }
        }
    }

    fn pulse(&self, event: E) {
        let json = encode(event);
        for (_, out) in self.clients.lock().unwrap().iter() {
            let _ = out.send(Message::Text(json.clone()));
        }
    }
}


pub struct WebsocketHandler<C, E>
    where C: Decodable + Send + Clone + Debug + 'static,
          E: Encodable + Send + Clone + Debug + 'static,
{
    out:     WsSender,
    itx:     Sender<Interpret<C, E>>,
    clients: Arc<Mutex<HashMap<Token, WsSender>>>
}

impl<C, E> Handler for WebsocketHandler<C, E>
    where C: Decodable + Send + Clone + Debug + 'static,
          E: Encodable + Send + Clone + Debug + 'static,
{
    fn on_message(&mut self, msg: Message) -> ws::Result<()> {
        debug!("received websocket message: {:?}", msg);
        match msg.as_text() {
            Ok(msg) => match decode(msg) {
                Ok(cmd) => Ok(self.forward_command(cmd)),

                Err(Error::WebsocketError(err)) => {
                    error!("websocket on_message error: {}", err);
                    Err(err)
                }

                Err(_)  => unreachable!(),
            },

            Err(err) => {
                error!("websocket on_message text error: {}", err);
                Err(err)
            }
        }
    }

    fn on_open(&mut self, _: Handshake) -> ws::Result<()> {
        let _ = self.clients.lock().unwrap().insert(self.out.token(), self.out.clone());
        Ok(debug!("new websocket client: {:?}", self.out.token()))
    }

    fn on_close(&mut self, code: CloseCode, _: &str) {
        let _ = self.clients.lock().unwrap().remove(&self.out.token().clone());
        debug!("closing websocket client {:?}: {:?}", self.out.token(), code);
    }

    fn on_error(&mut self, err: ws::Error) {
        error!("websocket error: {:?}", err);
    }
}

impl<C, E> WebsocketHandler<C, E>
    where C: Decodable + Send + Clone + Debug + 'static,
          E: Encodable + Send + Clone + Debug + 'static,
{
    fn forward_command(&self, cmd: C) {
        let (etx, erx) = chan::sync::<E>(0);
        let etx        = Arc::new(Mutex::new(etx.clone()));
        self.itx.send(Interpret { command: cmd, response_tx: Some(etx) });

        let e = erx.recv().expect("websocket response_tx is closed");
        let _ = self.out.send(Message::Text(encode(e)));
    }
}

fn encode<E: Encodable>(e: E) -> String {
    json::encode(&e).expect("Error encoding event into JSON")
}

fn decode<C: Decodable>(s: &str) -> Result<C, Error> {
    Ok(try!(json::decode::<C>(s)))
}


#[cfg(test)]
mod tests {
    use chan;
    use crossbeam;
    use rustc_serialize::json;
    use std::thread;
    use ws;
    use ws::{connect, CloseCode};

    use super::*;
    use super::super::gateway::Gateway;
    use super::super::super::datatype::{Command, Event};
    use super::super::super::interpreter::Global;

    #[test]
    fn websocket_connections() {
        let (etx, erx) = chan::sync::<Event>(0);
        let (gtx, grx) = chan::sync::<Global>(0);
        Websocket::run(gtx, erx);

        thread::spawn(move || {
            let _ = etx; // move into this scope
            loop {
                let global = grx.recv().expect("gtx is closed");
                match global.command {
                    Command::AcceptUpdates(ids) => {
                        let tx = global.response_tx.unwrap();
                        tx.lock().unwrap().send(Event::Error(ids.first().unwrap().to_owned()));
                    }
                    _ => panic!("expected AcceptUpdates"),
                }
            }
        });

        crossbeam::scope(|scope| {
            for id in 0..10 {
                scope.spawn(move || {
                    connect("ws://localhost:3012", |out| {
                        let text = format!(r#"{{ "variant": "AcceptUpdates", "fields": [["{}"]] }}"#, id);
                        out.send(text).unwrap();

                        move |msg: ws::Message| {
                            let ev: Event = json::decode(&format!("{}", msg)).unwrap();
                            assert_eq!(ev, Event::Error(format!("{}", id)));
                            out.close(CloseCode::Normal)
                        }
                    }).unwrap();
                });
            }
        });
    }
}
