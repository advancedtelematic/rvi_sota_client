use rustc_serialize::json;

use datatype::{AccessToken, Error, Url};
use http::{Client, Response};


#[derive(RustcEncodable)]
#[allow(non_snake_case)]
struct RegistrationPayload {
    deviceId: String,
    ttl: u32
}

/// Register with the specified auth gateway server to retrieve a new pkcs#12 bundle.
pub fn pkcs12(server: Url, device_id: String, ttl: u32, client: &Client) -> Result<Vec<u8>, Error> {
    debug!("registering at {}", server);
    let body = try!(json::encode(&RegistrationPayload { deviceId: device_id, ttl: ttl }));
    let resp_rx = client.post(server, Some(body.into_bytes()));
    let resp    = resp_rx.recv().expect("no authenticate response received");
    match resp {
        Response::Success(data) => return Ok(data.body),
        Response::Failed(data)  => return Err(Error::from(data)),
        Response::Error(err)    => return Err(err)
    }
}


/// Authenticate with the specified OAuth2 server to retrieve a new `AccessToken`.
pub fn oauth2(server: Url, client: &Client) -> Result<AccessToken, Error> {
    debug!("authenticating at {}", server);
    let resp_rx = client.post(server, Some(br#"grant_type=client_credentials"#.to_vec()));
    let resp    = resp_rx.recv().expect("no authenticate response received");
    let body    = match resp {
        Response::Success(data) => try!(String::from_utf8(data.body)),
        Response::Failed(data)  => return Err(Error::from(data)),
        Response::Error(err)    => return Err(err)
    };
    Ok(try!(json::decode(&body)))
}


#[cfg(test)]
mod tests {
    use super::*;
    use datatype::{AccessToken, Url};
    use http::TestClient;


    fn test_server() -> Url {
        "http://localhost:8000".parse().unwrap()
    }

    #[test]
    fn test_register() {
        let client = TestClient::from(vec![vec![12u8]]);
        let expect = vec![12u8];
        assert_eq!(expect, pkcs12(test_server(), "device_id".to_string(), 12, &client).unwrap());
    }

    #[test]
    fn test_oauth2() {
        let token = r#"{
            "access_token": "token",
            "token_type": "type",
            "expires_in": 10,
            "scope": "scope1 scope2"
        }"#;
        let client = TestClient::from(vec![token.to_string()]);
        let expect = AccessToken {
            access_token: "token".to_string(),
            token_type:   "type".to_string(),
            expires_in:   10,
            scope:        "scope1 scope2".to_string()
        };
        assert_eq!(expect, oauth2(test_server(), &client).unwrap());
    }

    #[test]
    fn test_oauth2_bad_json() {
        let client = TestClient::from(vec![r#"{"apa": 1}"#.to_string()]);
        let expect = r#"Failed to decode JSON: MissingFieldError("access_token")"#;
        assert_eq!(expect, format!("{}", oauth2(test_server(), &client).unwrap_err()));
    }
}
