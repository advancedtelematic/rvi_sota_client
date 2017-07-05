extern crate env_logger;
#[macro_use]
extern crate log;
extern crate sota;

mod datatypes;

use env_logger::LogBuilder;
use std::env;

use datatypes::Error;


const COOKIE: &'static str = "PLAY_SESSION=323b40cc97d1bd15ab9d6ba3933c921ebebca372-id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InNoYXVuKzVAYWR2YW5jZWR0ZWxlbWF0aWMuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vYXRzLWRldi5ldS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTk0Y2U0MzRiYWQ2ZjEwOWY5ZjliZGI2IiwiYXVkIjoialc1WnUyRlJsVHBnbkZkamFVSGlDTXRLbllOMWY3TkIiLCJleHAiOjE0OTkxMTIzMzQsImlhdCI6MTQ5OTA3NjMzNH0.OheHZFZu3g4lHR0dPOI2kdlAq2MQuXrKfF1JT8Qt1mQ&access_token=j90uLpcuoEVdTSo6&auth_plus_access_token=eyJhbGciOiJIUzI1NiIsImtpZCI6bnVsbH0.eyJpc3MiOiJodHRwczovL2F1dGgtcGx1cy5hZHZhbmNlZHRlbGVtYXRpYy5jb20iLCJhdWQiOlsidG9rZW4iLCJjbGllbnQiXSwianRpIjoiaktGVmk4Rm0wWDdWV0ZvOFpVekYiLCJjbGllbnRfaWQiOiJjMDYxYjEzMC0yMjYyLTQwYjMtYjc2My0zOGM0ZGY0NWIwMjAiLCJzdWIiOiJhdXRoMHw1OTRjZTQzNGJhZDZmMTA5ZjlmOWJkYjYiLCJvd25lciI6bnVsbCwiaWF0IjoxNDk5MDc2MzM0LCJleHAiOjE0OTkxNjI3MzQsInNjb3BlIjoidG9rZW4uaW50cm9zcGVjdCBjbGllbnQucmVnaXN0ZXIgY2xpZW50LnVwZGF0ZSJ9.lv9G98yZqBpkUR4WxaNFmubA3362SfDna7LHKbCHFHY&csrfToken=49597d8ca30694dbabaea81f631aa75699b2a7a0-1499076334267-77700b4244a34d06ced6e63f&namespace=auth0%7C594ce434bad6f109f9f9bdb6";


fn main() {
    start_logging();
    parse_play_session(COOKIE).expect("cookie");
}


fn start_logging() {
    let mut builder = LogBuilder::new();
    builder.format(move |log| format!("{}: {}", log.level(), log.args()));
    builder.parse(&env::var("RUST_LOG").unwrap_or_else(|_| "INFO".to_string()));
    builder.init().expect("builder already initialized");
}

fn parse_play_session(cookie: &str) -> Result<(), Error> {
    let parts = cookie.split('=').collect::<Vec<_>>()[0];
    unimplemented!()
}
