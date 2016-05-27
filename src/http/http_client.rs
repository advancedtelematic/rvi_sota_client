use rustc_serialize::json;
use std::borrow::Cow;
use std::fs::File;
use std::io::SeekFrom;
use std::io::prelude::*;
use tempfile;
use time;

use super::datatype::{AccessToken, ClientId, ClientSecret, Error, Method, Url};

#[derive(Clone)]
pub enum Auth<'a> {
    Credentials(ClientId, ClientSecret),
    Token(&'a AccessToken),
}

impl<'a> Into<Cow<'a, Auth<'a>>> for Auth<'a> {
    fn into(self) -> Cow<'a, Auth<'a>> {
        Cow::Owned(self)
    }
}

pub struct HttpRequest<'a> {
    pub method: Cow<'a, Method>,
    pub url:    Cow<'a, Url>,
    pub auth:   Option<Cow<'a, Auth<'a>>>,
    pub body:   Option<Cow<'a, str>>,
}

impl<'a> HttpRequest<'a> {

    fn new<M, U, A, B>(meth: M,
                       url:  U,
                       auth: Option<A>,
                       body: Option<B>) -> HttpRequest<'a>
        where
        M: Into<Cow<'a, Method>>,
        U: Into<Cow<'a, Url>>,
        A: Into<Cow<'a, Auth<'a>>>,
        B: Into<Cow<'a, str>>
    {
        HttpRequest {
            method: meth.into(),
            url:    url.into(),
            auth:   auth.map(|a| a.into()),
            body:   body.map(|b| b.into()),
        }
    }

    pub fn get<U, A>(url: U, auth: Option<A>) -> HttpRequest<'a>
        where
        U: Into<Cow<'a, Url>>,
        A: Into<Cow<'a, Auth<'a>>>,
    {
        HttpRequest::new::<Method, U, A, String>(Method::Get, url, auth, None)
    }

    pub fn post<U, A, B>(url: U, auth: Option<A>, body: Option<B>) -> HttpRequest<'a>
        where
        U: Into<Cow<'a, Url>>,
        A: Into<Cow<'a, Auth<'a>>>,
        B: Into<Cow<'a, str>>
    {
        HttpRequest::new(Method::Post, url, auth, body)
    }

    pub fn put<U, A, B>(url: U, auth: Option<A>, body: Option<B>) -> HttpRequest<'a>
        where
        U: Into<Cow<'a, Url>>,
        A: Into<Cow<'a, Auth<'a>>>,
        B: Into<Cow<'a, str>>
    {
        HttpRequest::new(Method::Put, url, auth, body)
    }
}

impl<'a> ToString for HttpRequest<'a> {
    fn to_string(&self) -> String {
        format!("{} {}", self.method.to_string(), self.url.to_string())
    }
}

#[derive(RustcEncodable, RustcDecodable)]
pub enum HttpStatus {
    Ok,
}

impl ToString for HttpStatus {
    fn to_string(&self) -> String {
        match *self {
            HttpStatus::Ok => "200".to_string()
        }
    }
}

#[derive(RustcEncodable, RustcDecodable)]
pub struct HttpResponse {
    pub status: HttpStatus,
    pub body:   Vec<u8>,
}

pub trait HttpClient: Send + Sync {

    fn send_request_to(&mut self, req: &HttpRequest, file: &mut File) -> Result<(), Error> {

        let t0   = time::precise_time_ns();
        let resp = try!(self.send_request(req));
        let t1   = time::precise_time_ns();

        let latency = t1 - t0;

        info!("HttpClient::send_request_to, request: {}, response status: {}, latency: {} ns",
              req.to_string(), resp.status.to_string(), latency);

        let json = try!(json::encode(&resp));

        Ok(try!(file.write_all(&json.as_bytes())))

    }

    fn send_request(&mut self, req: &HttpRequest) -> Result<HttpResponse, Error> {

        let mut temp_file: File = try!(tempfile::tempfile());

        let t0 = time::precise_time_ns();
        try!(self.send_request_to(req, &mut temp_file));
        let t1 = time::precise_time_ns();

        let latency = t1 - t0;

        try!(temp_file.seek(SeekFrom::Start(0)));

        let mut buf = String::new();
        let _: usize = try!(temp_file.read_to_string(&mut buf));

        let resp: HttpResponse = try!(json::decode(&buf));

        info!("HttpClient::send_request, request: {}, response status: {}, latency: {} ns",
              req.to_string(), resp.status.to_string(), latency);

        Ok(resp)

    }

}
