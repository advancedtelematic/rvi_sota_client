use super::datatype::Error;
use http::{HttpClient, HttpRequest, HttpResponse, HttpStatus};


pub struct TestHttpClient<'a> {
    replies: Vec<&'a str>,
}

impl<'a> TestHttpClient<'a> {

    pub fn new() -> TestHttpClient<'a> {
        TestHttpClient { replies: Vec::new() }
    }

    pub fn from(replies: Vec<&'a str>) -> TestHttpClient<'a> {
        TestHttpClient { replies: replies }
    }

}

impl<'a> HttpClient for TestHttpClient<'a> {

    fn send_request(&mut self, req: &HttpRequest) -> Result<HttpResponse, Error> {

        self.replies.pop()
            .ok_or(Error::ClientError(req.to_string()))
            .map(|s| HttpResponse
                 { status: HttpStatus::Ok,
                   body:   s.as_bytes().to_vec(),
                 })

    }

}
