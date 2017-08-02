#[macro_use] extern crate clap;
extern crate env_logger;
#[macro_use] extern crate log;
#[macro_use] extern crate maplit;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json as json;
extern crate sota;
extern crate toml;
extern crate uuid;

mod config;
mod installer;

use clap::AppSettings;
use env_logger::LogBuilder;
use log::LogLevelFilter;
use std::path::Path;
use std::{fs, process, thread};
use std::time::Duration;

use config::{App, Config};
use installer::InstallType;
use sota::datatype::{Error, Util};


fn main() {
    start().unwrap_or_else(|err| {
        println!("ERROR: {}", err);
        process::exit(1);
    })
}

fn start() -> Result<(), Error> {
    let app = parse_args()?;
    let oneshot = app.oneshot;
    let mut secondary = app.into_secondary()?;

    loop {
        info!("Starting a new listener...");
        match secondary.listen() {
            Ok(()) => info!("Listener complete."),
            Err(err) => error!("Listener error: {}", err)
        }
        if oneshot { break } else { thread::sleep(Duration::from_secs(1)) }
    }

    Ok(())
}

fn parse_args() -> Result<App, Error> {
    let matches = clap_app!(
        installer =>
            (setting: AppSettings::InferSubcommands)
            (setting: AppSettings::SubcommandRequiredElseHelp)
            (setting: AppSettings::VersionlessSubcommands)

            (@arg level: -l --level +takes_value +global "Sets the logging level")
            (@arg config: -c --config +takes_value +global "Path to the ECU config.")
            (@arg oneshot: -o --oneshot +global "Run the installer once then exit")

            (@subcommand overwrite =>
                (about: "Overwrite a specific file each time")
                (@arg path: --path +takes_value +required "Output file path")
            )
    ).get_matches();

    let level = matches.value_of("level").unwrap_or("INFO");
    start_logging(level);

    let config = match matches.value_of("config") {
        Some(file) => Util::read_text(file).and_then(|text| text.parse::<Config>()),
        None => Err(Error::Config("--config flag required".to_string()))
    }?;

    let install_type = if let Some(cmd) = matches.subcommand_matches("overwrite") {
        let image_path = cmd.value_of("path").ok_or_else(|| Error::Config("overwrite expects a --path flag".into()))?.into();
        if let Some(dir) = Path::new(&image_path).parent() { fs::create_dir_all(dir)?; }
        InstallType::Overwrite { image_path: image_path }
    } else {
        return Err(Error::Config("no subcommand provided".into()));
    };

    Ok(App {
        install_type: install_type,
        oneshot: matches.is_present("oneshot"),
        config: config,
    })
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
