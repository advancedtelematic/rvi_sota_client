use rustc_serialize::json::encode;
use datatype::{Error, Url};
use http::{Client, Response};

#[derive(RustcEncodable)]
#[allow(non_snake_case)]
struct RegistrationPayload {
    deviceId: String,
    ttl: u32
}

/// Register with the specified auth gateway server to retrieve a new access pkcs#12.
pub fn register(server: Url, device_id: String, ttl: u32, client: &Client) -> Result<Vec<u8>, Error> {
    debug!("registering at {}", server);
    let body = try!(encode(&RegistrationPayload { deviceId: device_id, ttl: ttl }));
    let resp_rx = client.post(server, Some(body.into_bytes()));
    let resp    = resp_rx.recv().expect("no authenticate response received");
    match resp {
        Response::Success(data) => return Ok(data.body),
        Response::Failed(data)  => return Err(Error::from(data)),
        Response::Error(err)    => return Err(err)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use datatype::Url;
    use http::TestClient;


    fn test_server() -> Url {
        "http://localhost:8000".parse().unwrap()
    }

    #[test]
    fn test_authenticate() {
        let client = TestClient::from(vec![vec![12u8]]);
        let expect = vec![12u8];
        assert_eq!(expect, register(test_server(), "device_id".to_string(), 12, &client).unwrap());
    }
}
