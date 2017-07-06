extern crate env_logger;
#[macro_use] extern crate hyper;
#[macro_use] extern crate log;
extern crate reqwest;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json as json;
extern crate sota;

mod datatypes;
mod http;

use env_logger::LogBuilder;
use std::env;


fn main() {
    start_logging();
}


fn start_logging() {
    let mut builder = LogBuilder::new();
    builder.format(move |log| format!("{}: {}", log.level(), log.args()));
    builder.parse(&env::var("RUST_LOG").unwrap_or_else(|_| "INFO".to_string()));
    builder.init().expect("builder already initialized");
}
