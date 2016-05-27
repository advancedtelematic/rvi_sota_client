use hyper::Client;
use hyper::client::RedirectPolicy;
use hyper::client::response::Response;
use hyper::header::{Authorization, Basic, Bearer, ContentType, Headers, Location};
use hyper::mime::{Attr, Mime, TopLevel, SubLevel, Value};
use rustc_serialize::json;
use std::fs::File;
use std::io::{copy, Read};

use http::{Auth, HttpClient, HttpRequest, HttpResponse, HttpStatus};

use super::datatype::Error;

pub struct Hyper {
    client: Client,
}

impl Hyper {
    pub fn new() -> Hyper {
        let mut client = Client::new();
        client.set_redirect_policy(RedirectPolicy::FollowNone);
        Hyper { client: client }
    }
}

impl HttpClient for Hyper {

    fn send_request_to(&mut self, req: &HttpRequest, file: &mut File) -> Result<(), Error> {

        debug!("send_request_to, request: {}", req.to_string());

        let mut headers  = Headers::new();
        let mut req_body = String::new();

        match (req.auth.clone().map(|a| a.into_owned()), req.body.to_owned()) {

            (None, None) => {}

            (Some(Auth::Credentials(ref id, ref secret)), None) => {

                headers.set(Authorization(Basic {
                    username: id.get.clone(),
                    password: Some(secret.get.clone())
                }));

                headers.set(ContentType(Mime(
                    TopLevel::Application,
                    SubLevel::WwwFormUrlEncoded,
                    vec![(Attr::Charset, Value::Utf8)])));

                req_body.push_str("grant_type=client_credentials")

            }

            (Some(Auth::Token(token)), body) => {

               headers.set(Authorization(Bearer {
                   token: token.access_token.clone()
               }));

               if let Some(json) = body {

                   headers.set(ContentType(Mime(
                       TopLevel::Application,
                       SubLevel::Json,
                       vec![(Attr::Charset, Value::Utf8)])));

                   req_body.push_str(&json)

               }

            }

            _ => panic!("hyper's send_request_to has been misused, this is a bug.")

        }

        debug!("send_request_to, headers:  `{}`", headers);
        debug!("send_request_to, req_body: `{}`", req_body);

        let mut resp = try!(self.client
                            .request(req.method.clone().into_owned().into(),
                                     req.url.clone().into_owned())
                            .headers(headers)
                            .body(&req_body)
                            .send());

        if resp.status.is_success() {
            let mut data = Vec::new();
            let _: usize = try!(resp.read_to_end(&mut data));
            let resp     = HttpResponse {
                status: HttpStatus::Ok,
                body:   data,
            };
            let json   = try!(json::encode(&resp));
            let _: u64 = try!(copy(&mut json.as_bytes(), file));
            Ok(())
        } else if resp.status.is_redirection() {
            let req = try!(relocate_request(req, &resp));
            self.send_request_to(&req, file)
        } else {
            let mut rbody = String::new();
            let _: usize = try!(resp.read_to_string(&mut rbody));
            Err(Error::ClientError(format!("Request errored with status {}, body: {}", resp.status, rbody)))
        }

    }

}

fn relocate_request<'a>(req: &'a HttpRequest, resp: &Response) -> Result<HttpRequest<'a>, Error> {

    if let Some(&Location(ref loc)) = resp.headers.get::<Location>() {

        let url = try!(req.url.join(loc));

        Ok(HttpRequest {
            url:    url.into(),
            method: req.method.clone(),
            auth:   None,
            body:   req.body.clone(),
        })

    } else {
        Err(Error::ClientError("Redirect with no Location header".to_string()))
    }

}

#[cfg(test)]
mod tests {
    use rustc_serialize::json;
    use std::fs::File;
    use std::io::SeekFrom;
    use std::io::prelude::*;
    use tempfile;

    use super::*;
    use datatype::Url;
    use http_client::{Auth, HttpClient, HttpRequest, HttpResponse};


    #[test]
    fn test_send_request_get() {

        let mut client: &mut HttpClient = &mut Hyper::new();

        let req = HttpRequest::get::<_, Auth>(
            Url::parse("https://eu.httpbin.org/get").unwrap(), None);

        let resp: HttpResponse = client.send_request(&req).unwrap();

        assert!(!resp.body.is_empty())

    }

    #[test]
    fn test_send_request_to_get() {

        let mut client = &mut Hyper::new();

        let req = HttpRequest::get::<_, Auth>(
            Url::parse("https://eu.httpbin.org/get").unwrap(), None);

        let mut temp_file: File = tempfile::tempfile().unwrap();
        client.send_request_to(&req, &mut temp_file).unwrap();

        temp_file.seek(SeekFrom::Start(0)).unwrap();

        let mut buf = String::new();
        let _: usize = temp_file.read_to_string(&mut buf).unwrap();

        assert!(buf != "".to_string())

    }

    #[test]
    fn test_send_request_to_binary() {

        let mut client = &mut Hyper::new();

        let req = HttpRequest::get::<_, Auth>(
            Url::parse("https://eu.httpbin.org/bytes/16?seed=123").unwrap(), None);

        let mut temp_file: File = tempfile::tempfile().unwrap();
        client.send_request_to(&req, &mut temp_file).unwrap();

        temp_file.seek(SeekFrom::Start(0)).unwrap();

        let mut buf  = String::new();
        let _: usize = temp_file.read_to_string(&mut buf).unwrap();

        let resp: HttpResponse = json::decode(&buf).unwrap();

        assert_eq!(resp.body, vec![13, 22, 104, 27, 230, 9, 137, 85,
                                   218, 40, 86, 85, 62, 0, 111, 22])

    }

}
