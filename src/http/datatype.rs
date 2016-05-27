use std::borrow::Cow;
use hyper::method;

use event::UpdateId;

#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub struct ClientId {
    pub get: String,
}

#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub struct ClientSecret {
    pub get: String,
}

#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub struct ClientCredentials {
    pub id:     ClientId,
    pub secret: ClientSecret,
}

pub type UpdateRequestId = UpdateId;


#[derive(RustcDecodable, Debug, PartialEq, Clone, Default)]
pub struct AccessToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
    pub scope: Vec<String>
}

impl<'a> Into<Cow<'a, AccessToken>> for AccessToken {
    fn into(self) -> Cow<'a, AccessToken> {
        Cow::Owned(self)
    }
}

use std::convert::From;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Error as IoError;
use std::string::FromUtf8Error;
use std::sync::PoisonError;
use toml::{ParserError as TomlParserError, DecodeError as TomlDecodeError};
use url::ParseError as UrlParseError;

use rustc_serialize::json::{EncoderError as JsonEncoderError, DecoderError as JsonDecoderError};
use hyper::error::Error as HyperError;


#[derive(Debug)]
pub enum Error {
    ClientError(String),
    Command(String),
    FromUtf8Error(FromUtf8Error),
    HyperError(HyperError),
    IoError(IoError),
    JsonDecoderError(JsonDecoderError),
    JsonEncoderError(JsonEncoderError),
    PoisonError(String),
    PackageError(String),
    ParseError(String),
    TomlParserErrors(Vec<TomlParserError>),
    TomlDecodeError(TomlDecodeError),
    UrlParseError(UrlParseError),
}

impl<E> From<PoisonError<E>> for Error {
    fn from(e: PoisonError<E>) -> Error {
        Error::PoisonError(format!("{}", e))
    }
}

impl From<Vec<TomlParserError>> for Error {
    fn from(e: Vec<TomlParserError>) -> Error {
        Error::TomlParserErrors(e)
    }
}

// To derive From implementations for the other errors we use the
// following macro.
macro_rules! derive_from {
    ([ $( $error: ident ),* ]) =>
    {
        $(
            impl From<$error> for Error {
                fn from(e: $error) -> Error {
                    Error::$error(e)
                }
            }
        )*
    }
}

derive_from!(
    [ JsonEncoderError
    , JsonDecoderError
    , HyperError
    , FromUtf8Error
    , IoError
    , UrlParseError
    , TomlDecodeError
    ]);


impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let inner: String = match *self {
            Error::ClientError(ref s)      => format!("Http client error: {}", s.clone()),
            Error::Command(ref e)          => format!("Unknown Command: {}", e.clone()),
            Error::FromUtf8Error(ref e)    => format!("From utf8 error: {}", e.clone()),
            Error::HyperError(ref e)       => format!("Hyper error: {}", e.clone()),
            Error::IoError(ref e)          => format!("IO error: {}", e.clone()),
            Error::JsonDecoderError(ref e) => format!("Failed to decode JSON: {}", e.clone()),
            Error::JsonEncoderError(ref e) => format!("Failed to encode JSON: {}", e.clone()),
            Error::PoisonError(ref e)      => format!("Poison error, {}", e.clone()),
            Error::PackageError(ref s)     => s.clone(),
            Error::ParseError(ref s)       => s.clone(),
            Error::TomlDecodeError(ref e)  => format!("Toml decode error: {}", e.clone()),
            Error::TomlParserErrors(ref e) => format!("Toml parser errors: {:?}", e.clone()),
            Error::UrlParseError(ref s)    => format!("Url parse error: {}", s.clone()),
        };
        write!(f, "{}", inner)
    }
}

#[macro_export]
macro_rules! exit {
    ($fmt:expr) => ({
        print!(concat!($fmt, "\n"));
        std::process::exit(1);
    });
    ($fmt:expr, $($arg:tt)*) => ({
        print!(concat!($fmt, "\n"), $($arg)*);
        std::process::exit(1);
    })
}



#[derive(Clone)]
pub enum Method {
    Get,
    Post,
    Put,
}

impl ToString for Method {
    fn to_string(&self) -> String {
        match *self {
            Method::Get  => "GET".to_string(),
            Method::Post => "POST".to_string(),
            Method::Put  => "PUT".to_string(),
        }
    }
}

impl Into<method::Method> for Method {
    fn into(self) -> method::Method {
        match self {
            Method::Get  => method::Method::Get,
            Method::Post => method::Method::Post,
            Method::Put  => method::Method::Put,
        }
    }
}

impl<'a> Into<Cow<'a, Method>> for Method {
    fn into(self) -> Cow<'a, Method> {
        Cow::Owned(self)
    }
}

use hyper::client::IntoUrl;
use hyper;
use rustc_serialize::{Decoder, Decodable};
use url::ParseError;
use url;

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Url {
    get: url::Url
}

impl Url {

    pub fn parse(s: &str) -> Result<Url, Error> {
        let url = try!(url::Url::parse(s));
        Ok(Url { get: url })
    }

    pub fn join(&self, suf: &str) -> Result<Url, Error> {
        let url = try!(self.get.join(suf));
        Ok(Url { get: url })
    }

}

impl IntoUrl for Url {

    fn into_url(self) -> Result<hyper::Url, ParseError> {
        Ok(self.get)
    }

}

impl<'a> Into<Cow<'a, Url>> for Url {
    fn into(self) -> Cow<'a, Url> {
        Cow::Owned(self)
    }
}


impl ToString for Url {

    fn to_string(&self) -> String {
        self.get.to_string()
    }

}

impl Decodable for Url {

    fn decode<D: Decoder>(d: &mut D) -> Result<Url, D::Error> {
        let s = try!(d.read_str());
        Url::parse(&s)
            .map_err(|e| d.error(&e.to_string()))
    }
}
