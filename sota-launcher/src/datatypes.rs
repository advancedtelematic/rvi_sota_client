use reqwest;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::str::FromStr;
use uuid;


error_chain!{
    foreign_links {
        Http(reqwest::Error);
        Io(io::Error);
        Uuid(uuid::ParseError);
    }
}


pub enum Environment {
    CI,
    QA,
    Production,
}

impl FromStr for Environment {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_ref() {
            "ci" => Ok(Environment::CI),
            "qa" => Ok(Environment::QA),
            "production" => Ok(Environment::Production),
            _ => Err(format!("unknown environment: {}", s).into())
        }
    }
}

impl Display for Environment {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let url = match *self {
            Environment::CI => "https://ci-app.atsgarage.com/api/v1",
            Environment::QA => "https://qa-app.atsgarage.com/api/v1",
            Environment::Production => "https://app.atsgarage.com/api/v1",
        };
        write!(f, "{}", url)
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Targets {
    pub targets: HashMap<String, Update>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Update {
    pub to: Target
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Target {
    pub target: String,
    pub targetLength: u64,
    pub checksum: Checksum,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Checksum {
    pub method: String,
    pub hash: String,
}


#[derive(Clone, Debug, PartialEq)]
pub struct PlayCookie {
    session: String,
    access_token: String,
    auth_plus_token: String,
    pub csrf_token: String,
    namespace: String,
}

impl FromStr for PlayCookie {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let cookie = s.trim().splitn(2, '=').collect::<Vec<_>>();
        if cookie[0] != "PLAY_SESSION" {
            return Err((format!("expected cookie 'PLAY_SESSION', got '{}'", cookie[0])).into())
        }

        let parts = cookie[1].split('&').collect::<Vec<_>>();
        let session = parts[0];
        let access_token = parts[1].split('=').collect::<Vec<_>>();
        let auth_plus_token = parts[2].split('=').collect::<Vec<_>>();
        let csrf_token = parts[3].split('=').collect::<Vec<_>>();
        let namespace = parts[4].split('=').collect::<Vec<_>>();

        if access_token[0] != "access_token" {
            return Err(format!("expected key 'access_token', got '{}'", access_token[0]).into())
        } else if auth_plus_token[0] != "auth_plus_access_token" {
            return Err(format!("expected key 'auth_plus_access_token', got '{}'", auth_plus_token[0]).into())
        } else if csrf_token[0] != "csrfToken" {
            return Err(format!("expected key 'csrfToken', got '{}'", csrf_token[0]).into())
        } else if namespace[0] != "namespace" {
            return Err(format!("expected key 'namespace', got '{}'", namespace[0]).into())
        }

        Ok(PlayCookie {
            session: session.into(),
            access_token: access_token[1].into(),
            auth_plus_token: auth_plus_token[1].into(),
            csrf_token: csrf_token[1].into(),
            namespace: namespace[1].into(),
        })
    }
}

impl Display for PlayCookie {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "PLAY_SESSION={}&access_token={}&auth_plus_access_token={}&csrfToken={}&namespace={}",
               self.session, self.access_token, self.auth_plus_token, self.csrf_token, self.namespace)
    }
}

impl PlayCookie {
    pub fn into_bytes(&self) -> Vec<u8> {
        format!("{}", self).as_bytes().to_vec()
    }
}


#[cfg(test)]
mod tests {
    extern crate env_logger;
    use super::*;

    const COOKIE: &'static str = "\n\t PLAY_SESSION=1234567890abcdef1234567890abcdef12345678-id_token=1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABC.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG&access_token=abcdefghijklmnop&auth_plus_access_token=1234567890abcdefghijklmnopqrstuvwxy.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG&csrfToken=1234567890abcdef1234567890abcdef12345678-1234567890123-1234567890abcdef12345678&namespace=auth0%7C1234567890abcdefghijklmn";


    #[test]
    fn parse_cookie() {
        let cookie = COOKIE.parse::<PlayCookie>().expect("parse");
        assert_eq!(&cookie.session, "1234567890abcdef1234567890abcdef12345678-id_token=1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABC.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG");
        assert_eq!(&cookie.access_token, "abcdefghijklmnop");
        assert_eq!(&cookie.auth_plus_token, "1234567890abcdefghijklmnopqrstuvwxy.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG");
        assert_eq!(&cookie.csrf_token, "1234567890abcdef1234567890abcdef12345678-1234567890123-1234567890abcdef12345678");
        assert_eq!(&cookie.namespace, "auth0%7C1234567890abcdefghijklmn");
        assert_eq!(format!("{}", cookie), COOKIE.trim());
    }
}
