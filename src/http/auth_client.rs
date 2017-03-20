use chan::Sender;
use hyper::client::{Body, Client as HyperClient, ProxyConfig, RedirectPolicy,
                    Response as HyperResponse};
use hyper::header::{Authorization, Basic, Bearer, Connection, ContentLength,
                    ContentType, Headers, Location};
use hyper::mime::{Attr, Mime, TopLevel, SubLevel, Value};
use hyper::net::{HttpsConnector};
use hyper::status::StatusCode;
use std::{env, str};
use std::io::Read;
use time;

use datatype::{Auth, Error};
use http::{Client, Request, Response, ResponseData, TlsClient};
use url::Url;


/// The `AuthClient` will attach an `Authentication` header to each outgoing request.
pub struct AuthClient {
    auth:   Auth,
    client: HyperClient,
}

impl Default for AuthClient {
    fn default() -> Self {
        Self::from(Auth::None)
    }
}

impl Client for AuthClient {
    fn chan_request(&self, req: Request, resp_tx: Sender<Response>) {
        resp_tx.send(self.send(AuthRequest::new(&self.auth, req)));
    }
}

impl AuthClient {
    /// Create a new HTTP client for the given `Auth` type.
    pub fn from(auth: Auth) -> Self {
        let mut client = match env::var("HTTP_PROXY") {
            Ok(ref proxy) => {
                let url = Url::parse(proxy).unwrap_or_else(|err| panic!("couldn't parse HTTP_PROXY: {}", err));
                let host = url.host_str().expect("couldn't parse HTTP_PROXY host").to_string();
                let port = url.port_or_known_default().expect("couldn't parse HTTP_PROXY port");
                HyperClient::with_proxy_config(ProxyConfig(host, port, TlsClient::new()))
            },

            Err(_) => HyperClient::with_connector(HttpsConnector::new(TlsClient::new()))
        };

        client.set_redirect_policy(RedirectPolicy::FollowNone);

        AuthClient {
            auth:   auth,
            client: client,
        }
    }

    /// Set the Authorization headers that are used for each outgoing request.
    pub fn set_auth(&mut self, auth: Auth) {
        self.auth = auth;
    }

    fn send(&self, req: AuthRequest) -> Response {
        let started = time::precise_time_ns();
        let mut request = self.client
            .request(req.request.method.clone().into(), (*req.request.url).clone())
            .headers(req.headers.clone());

        if let Some(ref body) = req.request.body {
            request = request.body(Body::BufBody(body, body.len()));
            debug!("request length: {} bytes", body.len());
            if let Ok(text) = str::from_utf8(body) {
                debug!("request body:\n{}", text);
            }
        }

        match request.send() {
            Ok(mut resp) => {
                info!("Response status: {}", resp.status);
                debug!("response headers:\n{}", resp.headers);
                let latency = time::precise_time_ns() as f64 - started as f64;
                debug!("response latency: {}ms", (latency / 1e6) as u32);

                let mut body = Vec::new();
                let data = match resp.read_to_end(&mut body) {
                    Ok(_)    => ResponseData { code: resp.status, body: body },
                    Err(err) => return Response::Error(Error::Client(format!("couldn't read response body: {}", err)))
                };
                debug!("response body size: {}", data.body.len());

                if resp.status.is_redirection() {
                    self.redirect_request(&req, resp)
                } else if resp.status.is_success() {
                    Response::Success(data)
                } else if resp.status == StatusCode::Unauthorized || resp.status == StatusCode::Forbidden {
                    Response::Error(Error::HttpAuth(data))
                } else {
                    Response::Failed(data)
                }
            }

            Err(err) => Response::Error(Error::Client(format!("couldn't send request: {}", err)))
        }
    }

    /// Redirect drops the Authorization header.
    fn redirect_request(&self, req: &AuthRequest, resp: HyperResponse) -> Response {
        resp.headers.get::<Location>()
            .map(|loc| {
                self.send(AuthRequest::new(&Auth::None, Request {
                    url: match loc.parse() {
                        Ok(url) => url,
                        Err(_) if &loc[0..1] == "/" => req.request.url.join(loc),
                        Err(_) => return Response::Error(Error::Parse(format!("not a url: {}", loc)))
                    },
                    method: req.request.method.clone(),
                    body:   req.request.body.clone(),
                }))
            }).unwrap_or_else(|| Response::Error(Error::Client("redirect missing Location header".into())))
    }
}


struct AuthRequest {
    request: Request,
    headers: Headers,
}

impl AuthRequest {
    fn new(auth: &Auth, req: Request) -> Self {
        let mut headers = Headers::new();

        headers.set(Connection::close());
        headers.set(ContentLength(req.body.as_ref().map_or(0, |body| body.len() as u64)));

        // empty Charset to keep RVI happy
        let mime_json = Mime(TopLevel::Application, SubLevel::Json, vec![]);
        let mime_form = Mime(TopLevel::Application, SubLevel::WwwFormUrlEncoded,
                             vec![(Attr::Charset, Value::Utf8)]);

        match *auth {
            Auth::Credentials(ref cred) => {
                headers.set(Authorization(Basic {
                    username: cred.client_id.clone(),
                    password: Some(cred.client_secret.clone())
                }));
                headers.set(ContentType(mime_form));
            }

            Auth::Token(ref token) => {
                headers.set(Authorization(Bearer { token: token.access_token.clone() }));
                headers.set(ContentType(mime_json));
            }

            _ => {
                headers.set(ContentType(mime_json));
            }
        };

        AuthRequest {
            request: req,
            headers: headers,
        }
    }
}


#[cfg(test)]
mod tests {
    use rustc_serialize::json::Json;

    use super::*;
    use http::{Client, Response, TlsClient, TlsData};


    fn get_client() -> AuthClient {
        TlsClient::init(TlsData::default());
        AuthClient::default()
    }

    #[test]
    fn test_send_get_request() {
        let client  = get_client();
        let url     = "http://eu.httpbin.org/bytes/16?seed=123".parse().unwrap();
        let resp_rx = client.get(url, None);
        let resp    = resp_rx.recv().unwrap();
        let expect  = vec![13, 22, 104, 27, 230, 9, 137, 85, 218, 40, 86, 85, 62, 0, 111, 22];
        match resp {
            Response::Success(data) => assert_eq!(data.body, expect),
            Response::Failed(data)  => panic!("failed response: {}", data),
            Response::Error(err)    => panic!("error response: {}", err)
        };
    }

    #[test]
    fn test_send_post_request() {
        let client  = get_client();
        let url     = "https://eu.httpbin.org/post".parse().unwrap();
        let resp_rx = client.post(url, Some(br#"foo"#.to_vec()));
        let resp    = resp_rx.recv().unwrap();
        let body    = match resp {
            Response::Success(data) => String::from_utf8(data.body).unwrap(),
            Response::Failed(data)  => panic!("failed response: {}", data),
            Response::Error(err)    => panic!("error response: {}", err)
        };
        let json    = Json::from_str(&body).unwrap();
        let obj     = json.as_object().unwrap();
        let data    = obj.get("data").unwrap().as_string().unwrap();
        assert_eq!(data, "foo");
    }
}
