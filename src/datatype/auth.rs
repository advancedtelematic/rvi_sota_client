
/// The available authentication types for communicating with the Auth server.
#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub enum Auth {
    None,
    Credentials(ClientCredentials),
    Token(AccessToken),
    Registration(RegistrationCredentials),
    Certificate,
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
