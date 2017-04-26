use chan::Sender;
use hyper::status::StatusCode;
use std::cell::RefCell;
use std::collections::VecDeque;

use datatype::{Error, Util};
use http::{Client, Request, Response, ResponseData};


/// The `TestClient` will return an ordered list of successful HTTP responses.
#[derive(Default)]
pub struct TestClient {
    responses: RefCell<VecDeque<Vec<u8>>>
}

impl TestClient {
    /// Create a new `TestClient` that will return these responses.
    pub fn from(responses: Vec<Vec<u8>>) -> TestClient {
        TestClient { responses: RefCell::new(VecDeque::from(responses)) }
    }

    /// Create a new `TestClient` that will return each file's data as a response.
    pub fn from_paths(reply_paths: &[&str]) -> TestClient {
        let responses = reply_paths.iter()
            .map(|path| Util::read_file(path).expect(&format!("couldn't read {}", path)))
            .collect();
        TestClient::from(responses)
    }
}

impl Client for TestClient {
    fn chan_request(&self, req: Request, resp_tx: Sender<Response>) {
        self.responses
            .borrow_mut()
            .pop_front()
            .map(|body| ResponseData { code: StatusCode::Ok, body: body })
            .map(|data| resp_tx.send(Response::Success(data)))
            .unwrap_or_else(|| resp_tx.send(Response::Error(Error::Client(req.url.to_string()))))
    }

    fn is_testing(&self) -> bool { true }
}
