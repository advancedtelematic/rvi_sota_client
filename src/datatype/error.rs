use base64::Base64Error;
use chrono::ParseError as ChronoParseError;
use hex::FromHexError;
use hyper::error::Error as HyperError;
use openssl::error::ErrorStack as OpensslErrors;
use pem::Error as PemError;
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
    Base64(Base64Error),
    Client(String),
    Command(String),
    Config(String),
    DateTime(ChronoParseError),
    FromUtf8(FromUtf8Error),
    Hex(FromHexError),
    Http(ResponseData),
    HttpAuth(ResponseData),
    Hyper(HyperError),
    Io(IoError),
    Json(SerdeJsonError),
    KeyNotFound(String),
    KeySign(String),
    Openssl(OpensslErrors),
    OSTree(String),
    PacMan(String),
    Parse(String),
    Pem(PemError),
    Poison(String),
    Recv(RecvError),
    Rvi(String),
    SendCommand(SendError<CommandExec>),
    SendEvent(SendError<Event>),
    Socket(String),
    SystemInfo(String),
    Toml(TomlError),
    TufKeyId(String),
    TufKeyType(String),
    TufRole(String),
    TufSigType(String),
    UptaneExpired,
    UptaneMissingKeys,
    UptaneMissingRoles,
    UptaneRole(String),
    UptaneRoleThreshold,
    UptaneVersion,
    UrlParse(UrlParseError),
    Utf8(Utf8Error),
    #[cfg(feature = "websocket")]
    Websocket(WebsocketError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let inner: String = match *self {
            Error::Base64(ref err)      => format!("Base64 parse error: {}", err),
            Error::Client(ref err)      => format!("Http client error: {}", err),
            Error::Command(ref err)     => format!("Unknown Command: {}", err),
            Error::Config(ref err)      => format!("Bad Config: {}", err),
            Error::DateTime(ref err)    => format!("DateTime parse error: {}", err),
            Error::FromUtf8(ref err)    => format!("From utf8 error: {}", err),
            Error::Hex(ref err)         => format!("Not valid hex data: {}", err),
            Error::Http(ref err)        => format!("HTTP client error: {}", err),
            Error::HttpAuth(ref err)    => format!("HTTP authorization error: {}", err),
            Error::Hyper(ref err)       => format!("Hyper error: {}", err),
            Error::Io(ref err)          => format!("IO error: {}", err),
            Error::Json(ref err)        => format!("JSON parse error: {}", err),
            Error::KeyNotFound(ref err) => format!("Key not found: {}", err),
            Error::KeySign(ref err)     => format!("Key signing error: {}", err),
            Error::Openssl(ref err)     => format!("OpenSSL errors: {}", err),
            Error::OSTree(ref err)      => format!("OSTree error: {}", err),
            Error::Poison(ref err)      => format!("Poison error: {}", err),
            Error::PacMan(ref err)      => format!("Package manager error: {}", err),
            Error::Parse(ref err)       => format!("Parse error: {}", err),
            Error::Pem(ref err)         => format!("PEM parse error: {}", err),
            Error::Recv(ref err)        => format!("Recv error: {}", err),
            Error::Rvi(ref err)         => format!("RVI error: {}", err),
            Error::SendCommand(ref err) => format!("Command send error: {}", err),
            Error::SendEvent(ref err)   => format!("Event send error: {}", err),
            Error::Socket(ref err)      => format!("Socket error: {}", err),
            Error::SystemInfo(ref err)  => format!("System info error: {}", err),
            Error::Toml(ref err)        => format!("TOML error: {:?}", err),
            Error::TufKeyId(ref err)    => format!("Invalid TUF key id: {}", err),
            Error::TufKeyType(ref err)  => format!("Invalid TUF key type: {}", err),
            Error::TufRole(ref err)     => format!("Invalid TUF role: {}", err),
            Error::TufSigType(ref err)  => format!("Invalid TUF signature type: {}", err),
            Error::UptaneExpired        => "Uptane: metadata has expired".into(),
            Error::UptaneMissingKeys    => "Uptane: missing `keys` field".into(),
            Error::UptaneMissingRoles   => "Uptane: missing `roles` field".into(),
            Error::UptaneRole(ref err)  => format!("Uptane role: {}", err),
            Error::UptaneRoleThreshold  => "Uptane: role threshold not met".into(),
            Error::UptaneVersion        => "Uptane: metadata version older than current".into(),
            Error::UrlParse(ref err)    => format!("Url parse error: {}", err),
            Error::Utf8(ref err)        => format!("Utf8 error: {}", err),
            #[cfg(feature="websocket")]
            Error::Websocket(ref err)   => format!("Websocket Error: {:?}", err),
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
    Base64Error      => Base64,
    ChronoParseError => DateTime,
    FromHexError     => Hex,
    FromUtf8Error    => FromUtf8,
    HyperError       => Hyper,
    IoError          => Io,
    OpensslErrors    => Openssl,
    PemError         => Pem,
    RecvError        => Recv,
    ResponseData     => Http,
    SerdeJsonError   => Json,
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
