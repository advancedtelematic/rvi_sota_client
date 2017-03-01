use std::fmt::{self, Display, Formatter};


/// The available authentication types for communicating with the Auth server.
#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub enum Auth {
    // ready for interpreter
    None,
    Token(AccessToken),
    Certificate,

    // need to authenticate
    Credentials(ClientCredentials),
    Registration(RegistrationCredentials),
}

/// Display should not include any sensitive data for log output.
impl Display for Auth {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Auth::None => write!(f, "{}", "No authentication"),
            Auth::Token(AccessToken { token_type: ref typ, .. }) => {
                write!(f, "Token type: {}", typ)
            }
            Auth::Certificate => write!(f, "{}", "Certificate authentication"),
            Auth::Credentials(ClientCredentials { client_id: ref id, .. }) => {
                write!(f, "Getting new token for client id: {}", id)
            }
            Auth::Registration(RegistrationCredentials { client_id: ref id }) => {
                write!(f, "Getting new certificate for client id: {}", id)
            }
        }
    }
}


/// Encapsulates the client id and secret used during authentication.
#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub struct ClientCredentials {
    pub client_id:     String,
    pub client_secret: String,
}


/// Stores the returned access token data following a successful authentication.
#[derive(RustcEncodable, RustcDecodable, Debug, PartialEq, Eq, Clone, Default)]
pub struct AccessToken {
    pub access_token: String,
    pub token_type:   String,
    pub expires_in:   i32,
    pub scope:        String
}

#[derive(RustcEncodable, RustcDecodable, Debug, Clone, PartialEq, Eq)]
pub struct RegistrationCredentials {
    pub client_id: String,
}
