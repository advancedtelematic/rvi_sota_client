use chan::Sender;
use hyper::status::StatusCode;
use std::cell::RefCell;

use datatype::Error;
use http::{Client, Request, Response, ResponseData};


/// The `TestClient` will return HTTP responses from an existing list of strings.
pub struct TestClient<T> {
    responses: RefCell<Vec<T>>
}

impl<T> Default for TestClient<T> {
    fn default() -> Self {
        TestClient { responses: RefCell::new(Vec::new()) }
    }
}

impl<T> TestClient<T> {
    /// Create a new `TestClient` that will return these responses.
    pub fn from(responses: Vec<T>) -> TestClient<T> {
        TestClient { responses: RefCell::new(responses) }
    }
}

impl Client for TestClient<String> {
    fn chan_request(&self, req: Request, resp_tx: Sender<Response>) {
        match self.responses.borrow_mut().pop() {
            Some(body) => resp_tx.send(Response::Success(ResponseData {
                code: StatusCode::Ok,
                body: body.as_bytes().to_vec()
            })),
            None => resp_tx.send(Response::Error(Error::Client(req.url.to_string())))
        }
    }

    fn is_testing(&self) -> bool { true }
}

impl Client for TestClient<Vec<u8>> {
    fn chan_request(&self, req: Request, resp_tx: Sender<Response>) {
        match self.responses.borrow_mut().pop() {
            Some(body) => resp_tx.send(Response::Success(ResponseData {
                code: StatusCode::Ok,
                body: body
            })),
            None => resp_tx.send(Response::Error(Error::Client(req.url.to_string())))
        }
    }

    fn is_testing(&self) -> bool { true }
}
