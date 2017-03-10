use chan::{self, Sender};
use hyper::header::ContentType;
use hyper::mime::{Mime, SubLevel, TopLevel};
use hyper::server::{Handler, Server, Request as HyperRequest, Response as HyperResponse};
use hyper::status::StatusCode;
use rustc_serialize::json;
use std::io::Read;
use std::net::SocketAddr;
use std::thread;
use std::sync::{Arc, Mutex};

use datatype::{Command, Event};
use gateway::{Gateway, Interpret};


/// The `Http` gateway parses `Command`s from the body of incoming requests.
pub struct Http {
    pub server: SocketAddr
}

impl Gateway for Http {
    fn initialize(&mut self, itx: Sender<Interpret>) -> Result<(), String> {
        let server = try!(Server::http(&self.server).map_err(|err| {
            format!("couldn't start http gateway: {}", err)
        }));

        let itx = Arc::new(Mutex::new(itx));
        thread::spawn(move || server.handle(HttpHandler::new(itx.clone())).unwrap());
        Ok(info!("HTTP gateway listening at http://{}", self.server))
    }
}


struct HttpHandler {
    itx: Arc<Mutex<Sender<Interpret>>>,
}

impl HttpHandler {
    fn new(itx: Arc<Mutex<Sender<Interpret>>>) -> HttpHandler {
        HttpHandler { itx: itx }
    }
}

impl Handler for HttpHandler {
    fn handle(&self, mut req: HyperRequest, mut resp: HyperResponse) {
        let mut buf = Vec::new();
        req.read_to_end(&mut buf).expect("couldn't read HTTP request body");

        let mut response_rx = None;
        String::from_utf8(buf).map(|body| {
            json::decode::<Command>(&body).map(|cmd| {
                info!("Incoming HTTP request command: {}", cmd);
                let (etx, erx) = chan::async::<Event>();
                response_rx = Some(erx);
                self.itx.lock().unwrap().send(Interpret {
                    command: cmd,
                    resp_tx: Some(Arc::new(Mutex::new(etx))),
                });
            }).unwrap_or_else(|err| error!("http request parse json: {}", err))
        }).unwrap_or_else(|err| error!("http request parse string: {}", err));

        let mut body = Vec::new();
        *resp.status_mut() = response_rx.map_or(StatusCode::BadRequest, |rx| {
            rx.recv().map_or_else(|| {
                error!("http receiver error");
                StatusCode::InternalServerError
            }, |event| {
                json::encode(&event).map(|text| {
                    resp.headers_mut().set(ContentType(Mime(TopLevel::Application, SubLevel::Json, vec![])));
                    body = text.into_bytes();
                    StatusCode::Ok
                }).unwrap_or_else(|err| {
                    error!("http response encoding: {:?}", err);
                    StatusCode::InternalServerError
                })
            })
        });
        resp.send(&body).expect("couldn't send HTTP response");
    }
}


#[cfg(test)]
mod tests {
    use chan;
    use crossbeam;
    use rustc_serialize::json;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use gateway::{Gateway, Interpret};
    use datatype::{Command, Event};
    use http::{AuthClient, Client, Response, TlsClient, TlsData};


    #[test]
    fn http_connections() {
        TlsClient::init(TlsData::default());

        let (etx, erx) = chan::sync::<Event>(0);
        let (itx, irx) = chan::sync::<Interpret>(0);

        thread::spawn(move || Http { server: "127.0.0.1:8888".parse().unwrap() }.start(itx, erx));
        thread::sleep(Duration::from_millis(100)); // add delay for http gateway starting

        thread::spawn(move || {
            let _ = etx; // move into this scope
            loop {
                let interpret = irx.recv().expect("itx is closed");
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
                    let cmd     = Command::StartDownload(format!("{}", id));
                    let client  = AuthClient::default();
                    let url     = "http://127.0.0.1:8888".parse().unwrap();
                    let body    = json::encode(&cmd).unwrap();
                    let resp_rx = client.post(url, Some(body.into_bytes()));
                    let resp    = resp_rx.recv().unwrap();
                    let text    = match resp {
                        Response::Success(data) => String::from_utf8(data.body).unwrap(),
                        Response::Failed(data)  => panic!("failed response: {}", data),
                        Response::Error(err)    => panic!("error response: {}", err)
                    };
                    assert_eq!(json::decode::<Event>(&text).unwrap(),
                               Event::FoundSystemInfo(format!("{}", id)));
                });
            }
        });
    }
}
