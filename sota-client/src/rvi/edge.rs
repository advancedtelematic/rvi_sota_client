use hyper::server::{Handler, Server, Request as HyperRequest, Response as HyperResponse};
use hyper::status::StatusCode;
use json;
use std::str;
use std::io::Read;

use datatype::{SocketAddrV4, Url};
use rvi::{RpcErr, RpcOk, RpcRequest, Services};


/// The HTTP server endpoint for `RVI` client communication.
pub struct Edge {
    rvi_edge: SocketAddrV4,
    services: Services,
}

impl Edge {
    /// Create a new `Edge` by registering each `RVI` service.
    pub fn new(mut services: Services, rvi_edge: SocketAddrV4, rvi_client: Url) -> Self {
        services.register_services(|service| {
            let req = RpcRequest::new("register_service", RegisterServiceRequest {
                network_address: format!("http://{}", rvi_edge),
                service:         service.to_string(),
            });
            let resp = req.send(rvi_client.clone()).expect("RegisterServiceRequest failed");
            let rpc_ok = json::from_str::<RpcOk<RegisterServiceResponse>>(&resp)
                .expect("couldn't decode RegisterServiceResponse");
            rpc_ok.result.expect("expected rpc_ok result").service
        });

        Edge { rvi_edge, services }
    }

    /// Start the HTTP server listening for incoming RVI client connections.
    pub fn start(&mut self) {
        let server = Server::http(&*self.rvi_edge).expect("couldn't start rvi edge server");
        let _ = server.handle(EdgeHandler::new(self.services.clone())).unwrap();
        info!("RVI server edge listening at http://{}.", self.rvi_edge);
    }
}


#[derive(Serialize)]
struct RegisterServiceRequest {
    pub network_address: String,
    pub service:         String,
}

#[derive(Deserialize)]
struct RegisterServiceResponse {
    pub service: String,
    pub status:  i32,
}


struct EdgeHandler {
    services: Services,
}

impl EdgeHandler {
    fn new(services: Services) -> EdgeHandler {
        EdgeHandler { services }
    }
}

impl Handler for EdgeHandler {
    fn handle(&self, mut req: HyperRequest, mut resp: HyperResponse) {
        let mut text = String::new();
        req.read_to_string(&mut text).expect("edge request");

        let outcome = || -> Result<RpcOk<i32>, RpcErr> {
            let body: json::Value = json::to_value(&text)
                .map_err(|err| RpcErr::parse_error(format!("invalid json: {}", err)))?;
            let id = body.get("id").and_then(|x| x.as_u64())
                .ok_or_else(|| RpcErr::parse_error("missing id".into()))?;
            let method = body.get("method").and_then(|x| x.as_str())
                .ok_or_else(|| RpcErr::invalid_request(id, "missing method".into()))?;
            match method {
                "services_available" => Ok(RpcOk::new(id, None)),
                "message" => {
                    let params = body.get("params")
                        .ok_or_else(|| RpcErr::invalid_request(id, "missing params".into()))?;
                    let service = params.get("service_name").and_then(|x| x.as_str())
                        .ok_or_else(|| RpcErr::invalid_request(id, "missing params.service_name".into()))?;
                    self.services.handle_service(service, id, &text)
                },
                _ => Err(RpcErr::method_not_found(id, format!("unknown method: {}", method)))
            }
        }();

        let body = match outcome {
            Ok(msg) => {
                *resp.status_mut() = StatusCode::Ok;
                json::to_vec::<RpcOk<i32>>(&msg).expect("encode RpcOk")
            },

            Err(err) => {
                *resp.status_mut() = StatusCode::BadRequest;
                json::to_vec::<RpcErr>(&err).expect("encode RpcErr")
            }
        };
        resp.send(&body).expect("edge response");
    }
}
