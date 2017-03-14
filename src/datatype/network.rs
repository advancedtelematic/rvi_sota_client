use hyper::method::Method as HyperMethod;
use serde::de::{Deserialize, Deserializer, Error as SerdeError};
use serde::ser::{Serialize, Serializer};
use serde_json as json;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::net::{SocketAddr as StdSocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use url;

use datatype::Error;


/// Encapsulate a socket address for implementing additional traits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketAddr(pub StdSocketAddr);

impl FromStr for SocketAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match StdSocketAddr::from_str(s) {
            Ok(addr) => Ok(SocketAddr(addr)),
            Err(err) => Err(Error::Parse(format!("couldn't parse SocketAddr: {}", err)))
        }
    }
}

impl Deserialize for SocketAddr {
    fn deserialize<D: Deserializer>(de: D) -> Result<SocketAddr, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("invalid SocketAddr: {}", err)))
        } else {
            Err(SerdeError::custom("Not a SocketAddr"))
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
    /// Append the string suffix to this URL. Will panic on parse failure.
    pub fn join(&self, suffix: &str) -> Url {
        Url(url::Url::parse(&format!("{}{}", self.0, suffix))
            .expect(&format!("couldn't join `{}` with `{}`", self.0, suffix)))
    }
}

impl FromStr for Url {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Url(url::Url::parse(s)?))
    }
}

impl Serialize for Url {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format!("{}", self))
    }
}

impl Deserialize for Url {
    fn deserialize<D: Deserializer>(de: D) -> Result<Url, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("invalid Url: {}", err)))
        } else {
            Err(SerdeError::custom("Not a Url"))
        }
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
        let slash: Url = "http://localhost:1234/foo/".parse().unwrap();
        assert_eq!(slash.join("bar"), "http://localhost:1234/foo/bar".parse().unwrap());
        assert_eq!(slash.join("/double"), "http://localhost:1234/foo//double".parse().unwrap());
        assert_eq!(slash.join("a/b"), "http://localhost:1234/foo/a/b".parse().unwrap());

        let no_slash: Url = "http://localhost:1234/foo".parse().unwrap();
        assert_eq!(no_slash.join("bar"), "http://localhost:1234/foobar".parse().unwrap());
        assert_eq!(no_slash.join("/two"), "http://localhost:1234/foo/two".parse().unwrap());
        assert_eq!(no_slash.join("/query%25?x=1"), "http://localhost:1234/foo/query%25?x=1".parse().unwrap());
    }
}
