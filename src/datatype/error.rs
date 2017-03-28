use chrono::ParseError as ChronoParseError;
use hyper::error::Error as HyperError;
use openssl::error::ErrorStack as OpensslErrors;
use serde_json::Error as SerdeJsonError;
use std::convert::From;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::sync::PoisonError;
use std::sync::mpsc::{SendError, RecvError};
use toml::de::Error as TomlError;
use tungstenite::Error as WebsocketError;
use url::ParseError as UrlParseError;

use datatype::Event;
use http::ResponseData;
use gateway::Interpret;


/// System-wide errors that are returned from `Result` type failures.
#[derive(Debug)]
pub enum Error {
    ChronoParse(ChronoParseError),
    Client(String),
    Command(String),
    Config(String),
    FromUtf8(FromUtf8Error),
    Http(ResponseData),
    HttpAuth(ResponseData),
    Hyper(HyperError),
    Io(IoError),
    Openssl(OpensslErrors),
    OSTree(String),
    PacMan(String),
    Parse(String),
    Poison(String),
    Recv(RecvError),
    SendEvent(SendError<Event>),
    SendInterpret(SendError<Interpret>),
    SerdeJson(SerdeJsonError),
    Socket(String),
    SystemInfo(String),
    Toml(TomlError),
    UptaneExpired,
    UptaneInvalidKeyType(String),
    UptaneInvalidSigType(String),
    UptaneInvalidRole,
    UptaneMissingSignatures,
    UptaneMissingField(&'static str),
    UptaneRoleThreshold,
    UptaneUnknownRole,
    UptaneVerifySignatures,
    UrlParse(UrlParseError),
    Utf8(Utf8Error),
    Verify(String),
    Websocket(WebsocketError),
}

impl<E> From<PoisonError<E>> for Error {
    fn from(e: PoisonError<E>) -> Error {
        Error::Poison(format!("{}", e))
    }
}

macro_rules! derive_from {
    ([ $( $from: ident => $to: ident ),* ]) => {
        $(impl From<$from> for Error {
            fn from(e: $from) -> Error {
                Error::$to(e)
            }
        })*
    };

    ([ $( $error: ident < $ty: ty > => $to: ident),* ]) => {
        $(impl From<$error<$ty>> for Error {
            fn from(e: $error<$ty>) -> Error {
                Error::$to(e)
            }
        })*
    };
}

derive_from!([
    ChronoParseError => ChronoParse,
    FromUtf8Error    => FromUtf8,
    HyperError       => Hyper,
    IoError          => Io,
    OpensslErrors    => Openssl,
    RecvError        => Recv,
    ResponseData     => Http,
    SerdeJsonError   => SerdeJson,
    TomlError        => Toml,
    UrlParseError    => UrlParse,
    Utf8Error        => Utf8,
    WebsocketError   => Websocket
]);

derive_from!([
    SendError<Event>     => SendEvent,
    SendError<Interpret> => SendInterpret
]);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let inner: String = match *self {
            Error::ChronoParse(ref e)   => format!("DateTime parse error: {}", e.clone()),
            Error::Client(ref s)        => format!("Http client error: {}", s.clone()),
            Error::Command(ref e)       => format!("Unknown Command: {}", e.clone()),
            Error::Config(ref s)        => format!("Bad Config: {}", s.clone()),
            Error::FromUtf8(ref e)      => format!("From utf8 error: {}", e.clone()),
            Error::Http(ref r)          => format!("HTTP client error: {}", r.clone()),
            Error::HttpAuth(ref r)      => format!("HTTP authorization error: {}", r.clone()),
            Error::Hyper(ref e)         => format!("Hyper error: {}", e.clone()),
            Error::Io(ref e)            => format!("IO error: {}", e.clone()),
            Error::Openssl(ref e)       => format!("OpenSSL errors: {}", e.clone()),
            Error::OSTree(ref e)        => format!("OSTree error: {}", e.clone()),
            Error::Poison(ref e)        => format!("Poison error: {}", e.clone()),
            Error::PacMan(ref s)        => format!("Package manager error: {}", s.clone()),
            Error::Parse(ref s)         => format!("Parse error: {}", s.clone()),
            Error::Recv(ref s)          => format!("Recv error: {}", s.clone()),
            Error::SendEvent(ref s)     => format!("Send error for Event: {}", s.clone()),
            Error::SendInterpret(ref s) => format!("Send error for Interpret: {}", s.clone()),
            Error::SerdeJson(ref e)     => format!("Serde JSON error: {}", e.clone()),
            Error::Socket(ref s)        => format!("Unix Domain Socket error: {}", s.clone()),
            Error::SystemInfo(ref s)    => format!("System info error: {}", s.clone()),
            Error::Toml(ref e)          => format!("TOML error: {:?}", e.clone()),
            Error::UptaneExpired               => "Uptane: expired".into(),
            Error::UptaneInvalidKeyType(ref s) => format!("Uptane: invalid key type: {}", s),
            Error::UptaneInvalidSigType(ref s) => format!("Uptane: invalid signature type: {}", s),
            Error::UptaneInvalidRole           => "Uptane: invalid role".into(),
            Error::UptaneMissingSignatures     => "Uptane: missing signatures".into(),
            Error::UptaneMissingField(s)       => format!("Uptane: metadata missing field: {}", s),
            Error::UptaneRoleThreshold         => "Uptane: role threshold not met".into(),
            Error::UptaneUnknownRole           => "Uptane: unknown role".into(),
            Error::UptaneVerifySignatures      => "Uptane: invalid signature".into(),
            Error::UrlParse(ref s)  => format!("Url parse error: {}", s.clone()),
            Error::Utf8(ref e)      => format!("Utf8 error: {}", e.clone()),
            Error::Verify(ref s)    => format!("Verification error: {}", s.clone()),
            Error::Websocket(ref e) => format!("Websocket Error: {:?}", e.clone()),
        };
        write!(f, "{}", inner)
    }
}
