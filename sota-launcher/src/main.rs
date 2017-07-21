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
            let updates = UpdateTargets::from(&targets.targets);
            let mtu = MultiTargetUpdate::new(env, session)?;
            let update_id = mtu.create(&updates)?;
            info!("update_id: {}", update_id);
            mtu.launch(targets.device.device_id, update_id)
        }
    }
}

fn parse_args() -> Result<App> {
    let matches = clap_app!(
        launcher =>
            (@arg level: -l --level +takes_value "Sets the logging level")
            (@arg mode: -m --mode +required +takes_value "Sets the launch mode")
            (@arg env: -e --env +takes_value "Set the environment type")
            (@arg session: -s --session +takes_value "Set the PLAY_SESSION cookie")
            (@arg privkeys: --privkeys +takes_value "Directory containing private DER keys")
            (@arg targets: --targets +takes_value "Path to a TOML file containing the launch targets")
    ).get_matches();

    let level = matches.value_of("level").unwrap_or("INFO");
    start_logging(level);

    let app = match matches.value_of("mode").unwrap_or("").parse()? {
        Mode::Manifests => App::GenerateManifests {
            priv_keys_dir: matches.value_of("privkeys")
                .ok_or_else(|| ErrorKind::Config("--privkeys flag required".to_string()))?.into()
        },

        Mode::Mtu => {
            let env: Environment = matches.value_of("env")
                .ok_or_else(|| ErrorKind::Config("--env flag required".to_string()))?.parse()?;
            let session: PlaySession = matches.value_of("session")
                .ok_or_else(|| ErrorKind::Config("--session flag required".to_string()))?.parse()?;

            let targets_file = matches.value_of("targets")
                .ok_or_else(|| ErrorKind::Config("--targets flag required".to_string()))?;
            let targets = Util::read_text(targets_file)?.parse()?;

            App::MultiTargetUpdate {
                env: env,
                session: session,
                targets: targets,
            }
        }
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
