use serde_json as json;

use datatype::{AccessToken, Error, Url};
use http::{Client, Response};


#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct RegistrationPayload {
    pub deviceId: String,
    pub ttl:      u32
}

/// Register with the specified auth gateway server to retrieve a new pkcs#12 bundle.
pub fn pkcs12(client: &Client, server: Url, payload: &RegistrationPayload) -> Result<Vec<u8>, Error> {
    info!("PKCS#12 registration server: {}", server);
    let rx = client.post(server, Some(json::to_vec(payload)?));
    match rx.recv().expect("no authenticate response received") {
        Response::Success(data) => Ok(data.body),
        Response::Failed(data)  => Err(data.into()),
        Response::Error(err)    => Err(err)
    }
}


/// Authenticate with the specified `OAuth2` server to retrieve a new `AccessToken`.
pub fn oauth2(server: Url, client: &Client) -> Result<AccessToken, Error> {
    info!("OAuth2 authentication server: {}", server);
    let rx = client.post(server, Some(br#"grant_type=client_credentials"#.to_vec()));
    match rx.recv().expect("no authenticate response received") {
        Response::Success(data) => Ok(json::from_slice(&data.body)?),
        Response::Failed(data)  => Err(data.into()),
        Response::Error(err)    => Err(err)
    }
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
        let body   = RegistrationPayload { deviceId: "device_id".to_string(), ttl: 1 };
        assert_eq!(vec![12u8], pkcs12(&client, test_server(), &body).unwrap());
    }

    #[test]
    fn test_oauth2() {
        let token = br#"{
            "access_token": "token",
            "token_type": "type",
            "expires_in": 10,
            "scope": "scope1 scope2"
        }"#;
        let client = TestClient::from(vec![token.to_vec()]);
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
        let client = TestClient::from(vec![br#"{"apa": 1}"#.to_vec()]);
        assert!(oauth2(test_server(), &client).is_err());
    }
}
