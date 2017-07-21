#[macro_use] extern crate clap;
#[macro_use] extern crate error_chain;
extern crate env_logger;
#[macro_use] extern crate log;
#[macro_use] extern crate maplit;
extern crate reqwest;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json as json;
extern crate sota;
extern crate toml;
extern crate uuid;

mod config;
mod manifests;
mod mtu;

use clap::AppSettings;
use env_logger::LogBuilder;
use log::LogLevelFilter;
use std::process;

use config::*;
use manifests::*;
use mtu::*;
use sota::datatype::Util;


fn main() {
    start().unwrap_or_else(|err| {
        println!("ERROR: {}", err);
        process::exit(1);
    })
}

fn start() -> Result<()> {
    let app = parse_args()?;
    match app {
        App::GenerateManifests { priv_keys_dir: dir } => {
            info!("Generating a manifest for each DER key in {}...", dir);
            Manifests::generate_all(&dir)
        }

        App::MultiTargetUpdate { env, session, targets } => {
            info!("Starting multi-target update...");
            let mtu = MultiTargetUpdate::new(env, session)?;
            let id = mtu.create(&UpdateTargets::from(&targets.targets))?;
            debug!("update_id: {}", id);
            mtu.launch(targets.device.device_id, id)
        }
    }
}

fn parse_args() -> Result<App> {
    let matches = clap_app!(
        launcher =>
            (setting: AppSettings::SubcommandRequiredElseHelp)
            (setting: AppSettings::VersionlessSubcommands)

            (@arg level: -l --level +takes_value +global "Sets the logging level")

            (@subcommand mtu =>
                (about: "Launch a multi-target update")
                (setting: AppSettings::ArgRequiredElseHelp)
                (@arg env: -e --env +takes_value "Set the environment type")
                (@arg session: -s --session +takes_value "Set the PLAY_SESSION cookie")
                (@arg targets: -t --targets +takes_value "Path to a TOML file containing the launch targets")
            )

            (@subcommand manifests =>
                (about: "Generate per-ECU manifest files")
                (setting: AppSettings::ArgRequiredElseHelp)
                (@arg privkeys: -k --("priv-keys") +takes_value "Directory containing private DER keys")
            )
    ).get_matches();

    let level = matches.value_of("level").unwrap_or("INFO");
    start_logging(level);

    let app = if let Some(cmd) = matches.subcommand_matches("mtu") {
        let targets = cmd.value_of("targets").ok_or_else(|| ErrorKind::Config("--targets flag required".to_string()))?;
        App::MultiTargetUpdate {
            env: cmd.value_of("env").ok_or_else(|| ErrorKind::Config("--env flag required".to_string()))?.parse()?,
            session: cmd.value_of("session").ok_or_else(|| ErrorKind::Config("--session flag required".to_string()))?.parse()?,
            targets: Util::read_text(targets)?.parse()?
        }
    } else if let Some(cmd) = matches.subcommand_matches("manifests") {
        App::GenerateManifests {
            priv_keys_dir: cmd.value_of("privkeys").ok_or_else(|| ErrorKind::Config("--priv-keys flag required".to_string()))?.into()
        }
    } else {
        Err(ErrorKind::Config("no subcommand provided".into()))?
    };

    Ok(app)
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
