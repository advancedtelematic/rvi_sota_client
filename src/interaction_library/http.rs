use chan;
use chan::{Sender, Receiver};
use hyper::{Decoder, Encoder, Next, StatusCode};
use hyper::header::{ContentLength, ContentType};
use hyper::mime::{Attr, Mime, TopLevel, SubLevel, Value};
use hyper::net::HttpStream;
use hyper::server::{Handler, Server, Request, Response};
use rustc_serialize::{json, Decodable, Encodable};
use std::{env, io, mem, thread};
use std::fmt::Debug;
use std::io::{ErrorKind, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::gateway::{Gateway, Interpret};


pub struct Http;

impl<C, E> Gateway<C, E> for Http
    where C: Decodable + Send + Clone + Debug + 'static,
          E: Encodable + Send + Clone + Debug + 'static
{
    fn new(itx: Sender<Interpret<C, E>>) -> Result<Self, String> {
        let itx    = Arc::new(Mutex::new(itx));
        let addr   = env::var("SOTA_HTTP_ADDR").unwrap_or("127.0.0.1:8888".to_string());

        let server = match Server::http(&addr.parse().unwrap()) {
            Ok(server) => server,
            Err(err)   => return Err(format!("couldn't start http server: {}", err))
        };
        let (addr, server) = server.handle(move |_| HttpHandler::new(itx.clone())).unwrap();
        thread::spawn(move || server.run());

        info!("Listening on http://{}", addr);
        Ok(Http)
    }
}


pub struct HttpHandler<C, E>
    where C: Decodable + Send + Clone + Debug + 'static,
          E: Encodable + Send + Clone + Debug + 'static
{
    itx:         Arc<Mutex<Sender<Interpret<C, E>>>>,
    response_rx: Option<Receiver<E>>,
    req_body:    Vec<u8>,
    resp_body:   Option<Vec<u8>>,
    written:     usize,
}

impl<C, E> HttpHandler<C, E>
    where C: Decodable + Send + Clone + Debug + 'static,
          E: Encodable + Send + Clone + Debug + 'static
{
    fn new(itx: Arc<Mutex<Sender<Interpret<C, E>>>>) -> HttpHandler<C, E> {
        HttpHandler {
            itx:         itx,
            response_rx: None,
            req_body:    Vec::new(),
            resp_body:   None,
            written:     0
        }
    }

    fn decode_request(&mut self) -> Next {
        let body = mem::replace(&mut self.req_body, Vec::new());

        match String::from_utf8(body) {
            Ok(body) => match json::decode::<C>(&body) {
                Ok(cmd) => {
                    info!("on_request_readable: decoded command: {:?}", cmd);
                    let (etx, erx)   = chan::async::<E>();
                    self.response_rx = Some(erx);
                    self.itx.lock().unwrap().send(Interpret {
                        command:     cmd,
                        response_tx: Some(Arc::new(Mutex::new(etx))),
                    });
                    Next::write().timeout(Duration::from_secs(20))
                }

                Err(err) => {
                    error!("decode_request: parse json: {}", err);
                    Next::remove()
                }
            },

            Err(err) => {
                error!("decode_request: parse string: {}", err);
                Next::remove()
            }
        }
    }
}

impl<C, E> Handler<HttpStream> for HttpHandler<C, E>
    where C: Decodable + Send + Clone + Debug + 'static,
          E: Encodable + Send + Clone + Debug + 'static
{
    fn on_request(&mut self, req: Request) -> Next {
        info!("on_request: {} {}", req.method(), req.uri());
        Next::read()
    }

    fn on_request_readable(&mut self, transport: &mut Decoder<HttpStream>) -> Next {
        match io::copy(transport, &mut self.req_body) {
            Ok(0) => {
                debug!("on_request_readable bytes read: {:?}", self.req_body.len());
                self.decode_request()
            }

            Ok(n) => {
                trace!("{} more request bytes read", n);
                Next::read()
            }

            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                trace!("retry on_request_readable");
                Next::read()
            }

            Err(err) => {
                error!("unable to read request body: {}", err);
                Next::remove()
            }
        }
    }

    fn on_response(&mut self, resp: &mut Response) -> Next {
        info!("on_response: status {}", resp.status());
        let response_rx = self.response_rx.as_ref().expect("Some receiver expected");

        match response_rx.recv() {
            Some(e) => match json::encode(&e) {
                Ok(body) => {
                    resp.set_status(StatusCode::Ok);
                    let mut headers = resp.headers_mut();
                    headers.set(ContentType(Mime(TopLevel::Application, SubLevel::Json,
                                                 vec![(Attr::Charset, Value::Utf8)])));
                    headers.set(ContentLength(body.len() as u64));
                    self.resp_body = Some(body.into_bytes());
                    Next::write()
                }

                Err(err) => {
                    error!("on_response encoding json: {:?}", err);
                    resp.set_status(StatusCode::InternalServerError);
                    Next::end()
                }
            },

            None => {
                error!("on_response receiver error");
                resp.set_status(StatusCode::InternalServerError);
                Next::end()
            }
        }
    }

    fn on_response_writable(&mut self, transport: &mut Encoder<HttpStream>) -> Next {
        let body = self.resp_body.as_ref().expect("on_response_writable has empty body");

        match transport.write(&body[self.written..]) {
            Ok(0) => {
                debug!("{} bytes written to response body", self.written);
                Next::end()
            }

            Ok(n) => {
                self.written += n;
                trace!("{} bytes written to response body", n);
                Next::write()
            }

            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                trace!("retry on_response_writable");
                Next::write()
            }

            Err(err) => {
                error!("unable to write response body: {}", err);
                Next::remove()
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use chan;
    use crossbeam;
    use rustc_serialize::json;
    use std::thread;

    use super::*;
    use super::super::gateway::Gateway;
    use super::super::super::datatype::{Auth, Command, Event, Method, Url};
    use super::super::super::http_client::{AuthClient, HttpClient, HttpRequest};
    use super::super::super::interpreter::Global;

    #[test]
    fn http_connections() {
        let (etx, erx) = chan::sync::<Event>(0);
        let (gtx, grx) = chan::sync::<Global>(0);
        Http::run(gtx, erx);

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

        // wait for all scoped threads to complete
        crossbeam::scope(|scope| {
            for id in 0..10 {
                scope.spawn(move || {
                    let client   = AuthClient::new(Auth::None);
                    let cmd      = Command::AcceptUpdates(vec!(format!("{}", id)));
                    let req_body = json::encode(&cmd).unwrap();

                    let req = HttpRequest {
                        method: Method::Post,
                        url:    Url::parse("http://127.0.0.1:8888").unwrap(),
                        body:   Some(req_body.into_bytes()),
                    };
                    let resp_rx = client.send_request(req);
                    let resp    = resp_rx.recv().unwrap().unwrap();

                    let text      = String::from_utf8(resp).unwrap();
                    let ev: Event = json::decode(&text).unwrap();
                    assert_eq!(ev, Event::Error(format!("{}", id)));
                });
            }
        });
    }
}
