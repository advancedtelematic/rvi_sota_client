use chan::Sender;
use hyper::client::{Body, Client as HyperClient, ProxyConfig, RedirectPolicy,
                    Response as HyperResponse};
use hyper::header::{Authorization, Basic, Bearer, Connection, ContentLength,
                    ContentType, Headers, Location, UserAgent};
use hyper::mime::{Attr, Mime, TopLevel, SubLevel, Value};
use hyper::net::{HttpConnector, HttpsConnector};
use hyper::status::StatusCode;
use std::{env, str};
use std::io::Read;
use time;

use datatype::{Auth, Error};
use http::{Client, Request, Response, ResponseData, TlsClient};
use url::Url;


/// The `AuthClient` will attach an `Authentication` header to each outgoing request.
pub struct AuthClient {
    auth: Auth,
    client: HyperClient,
    version: Option<String>,
}

impl Default for AuthClient {
    fn default() -> Self {
        Self::from(Auth::None, None)
    }
}

impl Client for AuthClient {
    fn chan_request(&self, req: Request, resp_tx: Sender<Response>) {
        resp_tx.send(self.send(AuthRequest::new(&self.auth, req)));
    }
}

impl AuthClient {
    /// Create a new HTTP client for the given `Auth` type.
    pub fn from(auth: Auth, version: Option<String>) -> Self {
        let mut client = env::var("HTTP_PROXY").map(|ref proxy| {
            let tls = TlsClient::default();
            let url = Url::parse(proxy).expect("couldn't parse HTTP_PROXY");
            let host = url.host_str().expect("couldn't parse HTTP_PROXY host").to_string();
            let port = url.port_or_known_default().expect("couldn't parse HTTP_PROXY port");
            let proxy = ProxyConfig::new(url.scheme(), host, port, HttpConnector::default(), tls);
            HyperClient::with_proxy_config(proxy)
        }).unwrap_or_else(|_| HyperClient::with_connector(HttpsConnector::new(TlsClient::default())));

        client.set_redirect_policy(RedirectPolicy::FollowNone);
        AuthClient { auth, client, version }
    }

    fn send(&self, req: AuthRequest) -> Response {
        let started = time::precise_time_ns();
        let mut headers = req.headers.clone();
        if let Some(ref version) = self.version {
            headers.set(UserAgent(format!("sota-client/{}", version)));
        }

        let mut request = self.client
            .request(req.request.method.clone().into(), (*req.request.url).clone())
            .headers(headers);
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
                    Ok(_) => ResponseData { code: resp.status, body: body },
                    Err(err) => {
                        let msg = format!("couldn't read response body: {}", err);
                        return Response::Error(Box::new(Error::Client(msg)));
                    }
                };
                debug!("response body size: {}", data.body.len());

                if resp.status.is_redirection() {
                    self.redirect_request(&req, resp)
                } else if resp.status.is_success() {
                    Response::Success(data)
                } else if resp.status == StatusCode::Unauthorized || resp.status == StatusCode::Forbidden {
                    Response::Error(Box::new(Error::HttpAuth(data)))
                } else {
                    Response::Failed(data)
                }
            }

            Err(err) => Response::Error(Box::new(Error::Client(format!("couldn't send request: {}", err))))
        }
    }

    /// Redirect drops the Authorization header.
    fn redirect_request(&self, req: &AuthRequest, resp: HyperResponse) -> Response {
        resp.headers
            .get::<Location>()
            .map(|loc| {
                self.send(AuthRequest::new(&Auth::None, Request {
                    url: match loc.parse() {
                        Ok(absolute) => absolute,
                        Err(_) if loc[0..1] == *"/" => req.request.url.join(loc), // relative
                        Err(err) => {
                            let msg = format!("`{}` not a url: {}", loc, err);
                            return Response::Error(Box::new(Error::Parse(msg)))
                        }
                    },
                    method: req.request.method.clone(),
                    body:   req.request.body.clone(),
                }))
            })
            .unwrap_or_else(|| {
                Response::Error(Box::new(Error::Client("redirect missing Location header".into())))
            })
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
    use super::*;
    use json;

    use http::{Client, Response, TlsClient, TlsData};


    fn get_client() -> AuthClient {
        TlsClient::init(TlsData::default());
        AuthClient::default()
    }

    #[test]
    fn test_send_get_request() {
        let url = "http://eu.httpbin.org/bytes/16?seed=123".parse().unwrap();
        match get_client().get(url, None).recv().unwrap() {
            Response::Success(data) => {
                let expect = vec![13, 22, 104, 27, 230, 9, 137, 85, 218, 40, 86, 85, 62, 0, 111, 22];
                assert_eq!(data.body, expect);
            }
            Response::Failed(data)  => panic!("failed response: {}", data),
            Response::Error(err)    => panic!("error response: {}", err)
        };
    }

    #[test]
    fn test_send_post_request() {
        let url = "https://eu.httpbin.org/post".parse().unwrap();
        match get_client().post(url, Some(br#"foo"#.to_vec())).recv().unwrap() {
            Response::Success(data) => {
                let body: json::Value = json::from_slice(&data.body).unwrap();
                assert_eq!(body.get("data").unwrap(), &json::Value::String("foo".into()));
            }
            Response::Failed(data) => panic!("failed response: {}", data),
            Response::Error(err)   => panic!("error response: {}", err)
        };
    }
}
