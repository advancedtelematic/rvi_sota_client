use serde::{Deserialize, Serialize};
use serde_json as json;
use time;
use uuid::Uuid;

use datatype::Url;
use http::{AuthClient, Client, Response};
use rvi::services::LocalServices;


/// Encode the body of a JSON-RPC call.
#[derive(Deserialize, Serialize)]
pub struct RpcRequest<S: Serialize> {
    pub jsonrpc: String,
    pub id:      u64,
    pub method:  String,
    pub params:  S
}

impl<S: Serialize> RpcRequest<S> {
    /// Instantiate a new `RpcRequest` with the default version (2.0) and an id
    /// generated from the current time.
    pub fn new(method: &str, params: S) -> RpcRequest<S> {
        RpcRequest {
            jsonrpc: "2.0".to_string(),
            id:      time::precise_time_ns(),
            method:  method.to_string(),
            params:  params
        }
    }

    /// Send a JSON-RPC POST request to the specified URL.
    pub fn send(&self, url: Url) -> Result<String, String> {
        let rx = AuthClient::default().post(url, Some(json::to_vec(self).expect("serialize RpcRequest")));
        match rx.recv().expect("no RpcRequest response received") {
            Response::Success(data) => String::from_utf8(data.body).or_else(|err| Err(format!("{}", err))),
            Response::Failed(data)  => Err(format!("{}", data)),
            Response::Error(err)    => Err(format!("{}", err))
        }
    }
}


/// Encapsulates a successful JSON-RPC response.
#[derive(Deserialize, Serialize)]
pub struct RpcOk<D: Deserialize> {
    pub jsonrpc: String,
    pub id:      u64,
    pub result:  Option<D>
}

impl<D: Deserialize> RpcOk<D> {
    /// Instantiate a new successful JSON-RPC response type.
    pub fn new(id: u64, result: Option<D>) -> RpcOk<D> {
        RpcOk { jsonrpc: "2.0".to_string(), id: id, result: result }
    }
}


/// The error code as [specified by jsonrpc](http://www.jsonrpc.org/specification#error_object).
#[derive(Deserialize, Serialize)]
pub struct ErrorCode {
    pub code:    i32,
    pub message: String,
    pub data:    String
}

/// Encapsulates a failed JSON-RPC response.
#[derive(Deserialize, Serialize)]
pub struct RpcErr {
    pub jsonrpc: String,
    pub id:      u64,
    pub error:   ErrorCode
}

impl RpcErr {
    /// Instantiate a new `RpcErr` type with the default JSON-RPC version (2.0).
    pub fn new(id: u64, error: ErrorCode) -> Self {
        RpcErr { jsonrpc: "2.0".to_string(), id: id, error: error }
    }

    /// Create a new `RpcErr` with a reason of "Invalid Request".
    pub fn invalid_request(id: u64, data: String) -> Self {
        Self::new(id, ErrorCode { code: -32600, message: "Invalid Request".to_string(), data: data })
    }

    /// Create a new `RpcErr` with a reason of "Method not found".
    pub fn method_not_found(id: u64, data: String) -> Self {
        Self::new(id, ErrorCode { code: -32601, message: "Method not found".to_string(), data: data })
    }

    /// Create a new `RpcErr` with a reason of "Parse error".
    pub fn parse_error(data: String) -> Self {
        Self::new(0,  ErrorCode { code: -32700, message: "Parse error".to_string(), data: data })
    }

    /// Create a new `RpcErr` with a reason of "Invalid params".
    pub fn invalid_params(id: u64, data: String) -> Self {
        Self::new(id, ErrorCode { code: -32602, message: "Invalid params".to_string(), data: data })
    }

    /// Create a new `RpcErr` with a reason of "Couldn't handle request".
    pub fn unspecified(id: u64, data: String) -> Self {
        Self::new(id, ErrorCode { code: -32100, message: "Couldn't handle request".to_string(), data: data })
    }
}


/// A JSON-RPC request type to notify RVI that a new package download has started.
#[derive(Deserialize, Serialize)]
pub struct DownloadStarted {
    pub device:    String,
    pub update_id: Uuid,
    pub services:  LocalServices,
}

/// A JSON-RPC request type to notify RVI that a new package chunk was received.
#[derive(Deserialize, Serialize)]
pub struct ChunkReceived {
    pub device:    String,
    pub update_id: Uuid,
    pub chunks:    Vec<u64>,
}
