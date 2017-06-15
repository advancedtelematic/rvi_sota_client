use hyper::method::Method as HyperMethod;
use serde::de::{Deserialize, Deserializer, Error as SerdeError};
use serde::ser::{Serialize, Serializer};
use serde_json as json;
use std::fmt::{self, Display, Formatter};
use std::net::{SocketAddrV4 as NetSocketAddrV4};
use std::ops::Deref;
use std::str::FromStr;
use url;

use datatype::Error;


/// Encapsulate a socket address for implementing additional traits.
#[derive(Serialize, Clone, Debug, Eq, PartialEq)]
pub struct SocketAddrV4(pub NetSocketAddrV4);

impl FromStr for SocketAddrV4 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match NetSocketAddrV4::from_str(s) {
            Ok(addr) => Ok(SocketAddrV4(addr)),
            Err(err) => Err(Error::Parse(format!("couldn't parse SocketAddrV4: {}", err)))
        }
    }
}

impl<'de> Deserialize<'de> for SocketAddrV4 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<SocketAddrV4, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("invalid SocketAddrV4: {}", err)))
        } else {
            Err(SerdeError::custom("Not a SocketAddrV4"))
        }
    }
}

impl Deref for SocketAddrV4 {
    type Target = NetSocketAddrV4;

    fn deref(&self) -> &NetSocketAddrV4 {
        &self.0
    }
}

impl Display for SocketAddrV4 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


/// Encapsulate a url with additional methods and traits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Url(pub url::Url);

impl Url {
    /// Append the string suffix to this URL, trimming multiple slashes.
    /// Will panic on parse failure.
    pub fn join(&self, suffix: &str) -> Url {
        let url = match (self.0.as_str().ends_with('/'), suffix.starts_with('/')) {
            (true, true)   => format!("{}{}", self.0, suffix.trim_left_matches('/')),
            (false, false) => format!("{}/{}", self.0, suffix),
            _              => format!("{}{}", self.0, suffix)
        };
        Url(url::Url::parse(&url).expect(&format!("couldn't join `{}` with `{}`", self.0, suffix)))
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

impl<'de> Deserialize<'de> for Url {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Url, D::Error> {
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
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
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
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
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
        assert_eq!(slash.join("///multiple"), "http://localhost:1234/foo/multiple".parse().unwrap());
        assert_eq!(slash.join("a/b"), "http://localhost:1234/foo/a/b".parse().unwrap());

        let no_slash: Url = "http://localhost:1234/foo".parse().unwrap();
        assert_eq!(no_slash.join("bar"), "http://localhost:1234/foo/bar".parse().unwrap());
        assert_eq!(no_slash.join("/two"), "http://localhost:1234/foo/two".parse().unwrap());
        assert_eq!(no_slash.join("/query%25?x=1"), "http://localhost:1234/foo/query%25?x=1".parse().unwrap());
    }
}
