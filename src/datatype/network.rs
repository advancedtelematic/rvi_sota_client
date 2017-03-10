use hyper::method::Method as HyperMethod;
use rustc_serialize::{Decoder, Decodable, Encoder, Encodable};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::{SocketAddr as StdSocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use url;

use datatype::Error;


/// Encapsulate a socket address for implementing additional traits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketAddr(pub StdSocketAddr);

impl Decodable for SocketAddr {
    fn decode<D: Decoder>(d: &mut D) -> Result<SocketAddr, D::Error> {
        d.read_str()?.parse().or_else(|err| Err(d.error(&format!("{}", err))))
    }
}

impl FromStr for SocketAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match StdSocketAddr::from_str(s) {
            Ok(addr) => Ok(SocketAddr(addr)),
            Err(err) => Err(Error::Parse(format!("couldn't parse SocketAddr: {}", err)))
        }
    }
}

impl Deref for SocketAddr {
    type Target = StdSocketAddr;

    fn deref(&self) -> &StdSocketAddr {
        &self.0
    }
}

impl Display for SocketAddr {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.0)
    }
}


/// Encapsulate a url with additional methods and traits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Url(pub url::Url);

impl Url {
    /// Append the string suffix to this URL.
    pub fn join(&self, suffix: &str) -> Url {
        let mut url = self.0.clone();
        url.path_segments_mut()
            .expect("couldn't get url segments")
            .pop_if_empty() // drop trailing slash before extending
            .extend(suffix.split("/"));
        Url(url)
    }
}

impl FromStr for Url {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Url(url::Url::parse(s)?))
    }
}

impl Decodable for Url {
    fn decode<D: Decoder>(d: &mut D) -> Result<Url, D::Error> {
        d.read_str()?.parse().map_err(|err: Error| d.error(&err.to_string()))
    }
}

impl Encodable for Url {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&format!("{}", self))
    }
}

impl Deref for Url {
    type Target = url::Url;

    fn deref(&self) -> &url::Url {
        &self.0
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let host = self.0.host_str().unwrap_or("localhost");
        if let Some(port) = self.0.port() {
            write!(f, "{}://{}:{}{}", self.0.scheme(), host, port, self.0.path())
        } else {
            write!(f, "{}://{}{}", self.0.scheme(), host, self.0.path())
        }
    }
}


/// Enumerate the supported HTTP methods.
#[derive(Clone, Debug)]
pub enum Method {
    Get,
    Post,
    Put,
}

impl Into<HyperMethod> for Method {
    fn into(self) -> HyperMethod {
        match self {
            Method::Get  => HyperMethod::Get,
            Method::Post => HyperMethod::Post,
            Method::Put  => HyperMethod::Put,
        }
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let method = match *self {
            Method::Get  => "GET".to_string(),
            Method::Post => "POST".to_string(),
            Method::Put  => "PUT".to_string(),
        };
        write!(f, "{}", method)
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_join_url() {
        let slash:    Url = "http://localhost:1234/foo/".parse().unwrap();
        let no_slash: Url = "http://localhost:1234/foo".parse().unwrap();
        let expect:   Url = "http://localhost:1234/foo/bar".parse().unwrap();
        assert_eq!(slash.join("bar"), expect);
        assert_eq!(no_slash.join("bar"), expect);
        assert_eq!(slash.join("a/b"), "http://localhost:1234/foo/a/b".parse().unwrap());
    }
}
