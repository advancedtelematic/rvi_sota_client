use chan::{self, Sender, Receiver};
use hyper::header::ContentType;
use hyper::mime::{Mime, SubLevel, TopLevel};
use hyper::server::{Handler, Server, Request as HyperRequest, Response as HyperResponse};
use hyper::status::StatusCode;
use json;
use std::net::SocketAddrV4;
use std::thread;

use datatype::Event;
use gateway::Gateway;
use interpreter::CommandExec;


/// The `Http` gateway parses `Command`s from the body of incoming requests.
pub struct Http {
    pub server: SocketAddrV4
}

impl Gateway for Http {
    fn start(&mut self, ctx: Sender<CommandExec>, _: Receiver<Event>) {
        info!("Starting HTTP gateway at http://{}", self.server);
        let server = Server::http(&self.server).expect("http gateway");
        thread::spawn(move || server.handle(HttpHandler { ctx: ctx.clone() }).expect("serve http"));
    }
}


struct HttpHandler {
    ctx: Sender<CommandExec>
}

impl Handler for HttpHandler {
    fn handle(&self, req: HyperRequest, mut resp: HyperResponse) {
        let mut body = Vec::new();
        let _ = json::from_reader(req)
            .map_err(|err| {
                error!("couldn't read HTTP request: {}", err);
                *resp.status_mut() = StatusCode::BadRequest;
            })
            .map(|cmd| {
                let (etx, erx) = chan::async::<Event>();
                self.ctx.send(CommandExec { cmd: cmd, etx: Some(etx) });
                body = json::to_vec(&erx.recv().expect("no http response")).expect("encode event");
                resp.headers_mut().set(ContentType(Mime(TopLevel::Application, SubLevel::Json, vec![])));
                *resp.status_mut() = StatusCode::Ok;
            });
        resp.send(&body).expect("couldn't send HTTP response");
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam;
    use std::time::Duration;
    use uuid::Uuid;

    use datatype::Command;
    use http::{AuthClient, Client, Response, TlsClient, TlsData};


    #[test]
    fn http_connections() {
        TlsClient::init(TlsData::default());
        let (ctx, crx) = chan::sync::<CommandExec>(0);
        let (etx, erx) = chan::sync::<Event>(0);

        thread::spawn(move || Http { server: "127.0.0.1:8888".parse().unwrap() }.start(ctx, erx));
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
                    let id = format!("00000000-0000-0000-0000-00000000000{}", n).parse::<Uuid>().unwrap();
                    let body = json::to_vec(&Command::StartInstall(id)).expect("body");
                    let rx = AuthClient::default().post("http://127.0.0.1:8888".parse().unwrap(), Some(body));
                    match rx.recv().expect("http resp") {
                        Response::Success(data) => {
                            assert_eq!(Event::InstallingUpdate(id), json::from_slice(&data.body).unwrap());
                        },
                        Response::Failed(data) => panic!("failed response: {}", data),
                        Response::Error(err)   => panic!("error response: {}", err)
                    };
                });
            }
        });
    }
}
