use chrono::ParseError as ChronoParseError;
use hex::FromHexError;
use hyper::error::Error as HyperError;
use openssl::error::ErrorStack as OpensslErrors;
use serde_json::Error as SerdeJsonError;
use std::convert::From;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::sync::PoisonError;
use std::sync::mpsc::{SendError, RecvError};
use toml::de::Error as TomlError;
#[cfg(feature = "websocket")]
use tungstenite::Error as WebsocketError;
use url::ParseError as UrlParseError;

use datatype::Event;
use http::ResponseData;
use interpreter::CommandExec;


/// System-wide errors that are returned from `Result` type failures.
#[derive(Debug)]
pub enum Error {
    ChronoParse(ChronoParseError),
    Client(String),
    Command(String),
    Config(String),
    FromUtf8(FromUtf8Error),
    Hex(FromHexError),
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
    Rvi(String),
    SendCommand(SendError<CommandExec>),
    SendEvent(SendError<Event>),
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
    #[cfg(feature = "websocket")]
    Websocket(WebsocketError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let inner: String = match *self {
            Error::ChronoParse(ref err) => format!("DateTime parse error: {}", err),
            Error::Client(ref err)      => format!("Http client error: {}", err),
            Error::Command(ref err)     => format!("Unknown Command: {}", err),
            Error::Config(ref err)      => format!("Bad Config: {}", err),
            Error::FromUtf8(ref err)    => format!("From utf8 error: {}", err),
            Error::Hex(ref err)         => format!("Not valid hex data: {}", err),
            Error::Http(ref err)        => format!("HTTP client error: {}", err),
            Error::HttpAuth(ref err)    => format!("HTTP authorization error: {}", err),
            Error::Hyper(ref err)       => format!("Hyper error: {}", err),
            Error::Io(ref err)          => format!("IO error: {}", err),
            Error::Openssl(ref err)     => format!("OpenSSL errors: {}", err),
            Error::OSTree(ref err)      => format!("OSTree error: {}", err),
            Error::Poison(ref err)      => format!("Poison error: {}", err),
            Error::PacMan(ref err)      => format!("Package manager error: {}", err),
            Error::Parse(ref err)       => format!("Parse error: {}", err),
            Error::Recv(ref err)        => format!("Recv error: {}", err),
            Error::Rvi(ref err)         => format!("RVI error: {}", err),
            Error::SendCommand(ref err) => format!("Command send error: {}", err),
            Error::SendEvent(ref err)   => format!("Event send error: {}", err),
            Error::SerdeJson(ref err)   => format!("Serde JSON error: {}", err),
            Error::Socket(ref err)      => format!("Unix Domain Socket error: {}", err),
            Error::SystemInfo(ref err)  => format!("System info error: {}", err),
            Error::Toml(ref err)        => format!("TOML error: {:?}", err),
            Error::UrlParse(ref err)    => format!("Url parse error: {}", err),
            Error::Utf8(ref err)        => format!("Utf8 error: {}", err),
            Error::Verify(ref err)      => format!("Verification error: {}", err),
            #[cfg(feature="websocket")]
            Error::Websocket(ref err)   => format!("Websocket Error: {:?}", err),

            Error::UptaneExpired                 => "Uptane: expired".into(),
            Error::UptaneInvalidKeyType(ref err) => format!("Uptane: invalid key type: {}", err),
            Error::UptaneInvalidSigType(ref err) => format!("Uptane: invalid signature type: {}", err),
            Error::UptaneInvalidRole             => "Uptane: invalid role".into(),
            Error::UptaneMissingSignatures       => "Uptane: missing signatures".into(),
            Error::UptaneMissingField(err)       => format!("Uptane: metadata missing field: {}", err),
            Error::UptaneRoleThreshold           => "Uptane: role threshold not met".into(),
            Error::UptaneUnknownRole             => "Uptane: unknown role".into(),
            Error::UptaneVerifySignatures        => "Uptane: invalid signature".into(),
        };
        write!(f, "{}", inner)
    }
}

impl<E> From<PoisonError<E>> for Error {
    fn from(err: PoisonError<E>) -> Error {
        Error::Poison(err.to_string())
    }
}


macro_rules! derive_from {
    ([ $( $from: ident => $to: ident ),* ]) => {
        $(impl From<$from> for Error {
            fn from(err: $from) -> Error {
                Error::$to(err)
            }
        })*
    };

    ([ $( $error: ident < $ty: ty > => $to: ident),* ]) => {
        $(impl From<$error<$ty>> for Error {
            fn from(err: $error<$ty>) -> Error {
                Error::$to(err)
            }
        })*
    };
}

derive_from!([
    ChronoParseError => ChronoParse,
    FromHexError     => Hex,
    FromUtf8Error    => FromUtf8,
    HyperError       => Hyper,
    IoError          => Io,
    OpensslErrors    => Openssl,
    RecvError        => Recv,
    ResponseData     => Http,
    SerdeJsonError   => SerdeJson,
    TomlError        => Toml,
    UrlParseError    => UrlParse,
    Utf8Error        => Utf8
]);

#[cfg(feature = "websocket")]
derive_from!([WebsocketError => Websocket]);

derive_from!([
    SendError<CommandExec> => SendCommand,
    SendError<Event>       => SendEvent
]);
