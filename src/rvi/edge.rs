use hyper::server::{Handler, Server, Request as HyperRequest, Response as HyperResponse};
use hyper::status::StatusCode;
use rustc_serialize::json::{self, Json};
use std::str;
use std::io::Read;

use datatype::{RpcRequest, RpcOk, RpcErr, SocketAddr, Url};
use super::services::Services;


/// The HTTP server endpoint for `RVI` client communication.
pub struct Edge {
    rvi_edge: SocketAddr,
    services: Services,
}

impl Edge {
    /// Create a new `Edge` by registering each `RVI` service.
    pub fn new(mut services: Services, rvi_edge: SocketAddr, rvi_client: Url) -> Self {
        services.register_services(|service| {
            let req = RpcRequest::new("register_service", RegisterServiceRequest {
                network_address: format!("http://{}", rvi_edge),
                service:         service.to_string(),
            });
            let resp = req.send(rvi_client.clone())
                .unwrap_or_else(|err| panic!("RegisterServiceRequest failed: {}", err));
            let rpc_ok = json::decode::<RpcOk<RegisterServiceResponse>>(&resp)
                .unwrap_or_else(|err| panic!("couldn't decode RegisterServiceResponse: {}", err));
            rpc_ok.result.expect("expected rpc_ok result").service
        });

        Edge { rvi_edge: rvi_edge, services: services }
    }

    /// Start the HTTP server listening for incoming RVI client connections.
    pub fn start(&mut self) {
        let server = Server::http(&*self.rvi_edge)
            .unwrap_or_else(|err| panic!("couldn't start rvi edge server: {}", err));
        let _ = server.handle(EdgeHandler::new(self.services.clone())).unwrap();
        info!("RVI server edge listening at http://{}.", self.rvi_edge);
    }
}


#[derive(RustcEncodable)]
struct RegisterServiceRequest {
    pub network_address: String,
    pub service:         String,
}

#[derive(RustcDecodable)]
struct RegisterServiceResponse {
    pub service: String,
    pub status:  i32,
}


struct EdgeHandler {
    services: Services,
}

impl EdgeHandler {
    fn new(services: Services) -> EdgeHandler {
        EdgeHandler { services:  services }
    }
}

impl Handler for EdgeHandler {
    fn handle(&self, mut req: HyperRequest, mut resp: HyperResponse) {
        let mut buf = Vec::new();
        req.read_to_end(&mut buf).expect("couldn't read Edge HTTP request body");

        let outcome = || -> Result<RpcOk<i32>, RpcErr> {
            let text   = try!(str::from_utf8(&buf).map_err(|err| RpcErr::parse_error(err.to_string())));
            let data   = try!(Json::from_str(text).map_err(|err| RpcErr::parse_error(err.to_string())));
            let object = try!(data.as_object().ok_or(RpcErr::parse_error("not an object".to_string())));
            let id     = try!(object.get("id").and_then(|x| x.as_u64())
                              .ok_or(RpcErr::parse_error("expected id".to_string())));
            let method = try!(object.get("method").and_then(|x| x.as_string())
                              .ok_or(RpcErr::invalid_request(id, "expected method".to_string())));

            match method {
                "services_available" => Ok(RpcOk::new(id, None)),

                "message" => {
                    let params  = try!(object.get("params").and_then(|p| p.as_object())
                                       .ok_or(RpcErr::invalid_request(id, "expected params".to_string())));
                    let service = try!(params.get("service_name").and_then(|s| s.as_string())
                                       .ok_or(RpcErr::invalid_request(id, "expected params.service_name".to_string())));
                    self.services.handle_service(service, id, text)
                }

                _ => Err(RpcErr::method_not_found(id, format!("unknown method: {}", method)))
            }
        }();

        let body = match outcome {
            Ok(msg)  => {
                *resp.status_mut() = StatusCode::Ok;
                json::encode::<RpcOk<i32>>(&msg).expect("couldn't encode RpcOk response")
            }

            Err(err) => {
                *resp.status_mut() = StatusCode::BadRequest;
                json::encode::<RpcErr>(&err).expect("couldn't encode RpcErr response")
            }
        };

        resp.send(&body.into_bytes()).expect("couldn't send Edge HTTP response");
    }
}
