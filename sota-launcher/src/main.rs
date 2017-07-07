#[macro_use] extern crate clap;
#[macro_use] extern crate error_chain;
extern crate env_logger;
#[macro_use] extern crate log;
extern crate reqwest;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json as json;
extern crate sota;
extern crate toml;
extern crate uuid;

mod config;
mod datatypes;
mod http;

use env_logger::LogBuilder;
use log::LogLevelFilter;
use std::process;

use config::*;
use datatypes::*;
use http::*;


fn main() {
    start().unwrap_or_else(|err| {
        println!("ERROR: {}", err);
        process::exit(1);
    })
}

fn start() -> Result<()> {
    let (config, targets) = parse_args()?;
    let updates = targets.as_updates();

    let mtu = MultiTargetUpdate::new(&config)?;
    let update_id = mtu.create(&updates)?;
    info!("update_id: {}", update_id);
    mtu.launch(targets.device.device_id, update_id)?;

    Ok(())
}

fn parse_args() -> Result<(Config, Targets)> {
    let matches = clap_app!(
        launcher =>
            (@arg config: -c --config +required +takes_value "Path to the config file")
            (@arg targets: -t --targets +required +takes_value "Path to the launch targets")
            (@arg level: -l --level +takes_value "Sets the debug level")
    ).get_matches();

    let config = match matches.value_of("config") {
        Some(file) => Text::read(file).and_then(|text| text.parse::<Config>()),
        None => Err(ErrorKind::Config("no config file given".to_string()).into())
    }?;

    let targets = match matches.value_of("targets") {
        Some(file) => Text::read(file).and_then(|text| text.parse::<Targets>()),
        None => Err(ErrorKind::Config("no targets file given".to_string()).into())
    }?;

    let level = matches.value_of("level").unwrap_or("INFO");
    start_logging(level);

    Ok((config, targets))
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
