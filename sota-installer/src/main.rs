#[macro_use] extern crate clap;
extern crate env_logger;
#[macro_use] extern crate log;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json as json;
extern crate sota;
extern crate toml;
extern crate uuid;

mod config;
mod datatypes;

use env_logger::LogBuilder;
use log::LogLevelFilter;
use std::process;

use config::Secondary;
use datatypes::Text;
use sota::datatype::Error;


fn main() {
    start().unwrap_or_else(|err| {
        println!("ERROR: {}", err);
        process::exit(1);
    })
}

fn start() -> Result<(), Error> {
    let config = parse_args()?;
    Ok(())
}

fn parse_args() -> Result<Secondary, Error> {
    let matches = clap_app!(
        launcher =>
            (@arg config: -c --config +required +takes_value "Path to the secondary config file")
            (@arg level: -l --level +takes_value "Sets the logging level")
    ).get_matches();

    let secondary = match matches.value_of("config") {
        Some(file) => Text::read(file).and_then(|text| text.parse::<Secondary>()),
        None => Err(Error::Config("no config file given".to_string()).into())
    }?;

    let level = matches.value_of("level").unwrap_or("INFO");
    start_logging(level);

    Ok(secondary)
}

fn start_logging(level: &str) {
    let mut builder = LogBuilder::new();
    builder.format(move |log| format!("{}: {}", log.level(), log.args()));
    builder.parse(level);
    if level != "TRACE" {
        builder.filter(Some("hyper"), LogLevelFilter::Info);
    }
    builder.init().expect("builder already initialized");
}
