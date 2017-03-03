extern crate chan;
extern crate env_logger;
extern crate getopts;
extern crate hyper;
#[macro_use] extern crate log;
extern crate rustc_serialize;
extern crate sota;
extern crate time;
extern crate url;

use std::{env, process, str, fs};
use std::fs::{File, Permissions};
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;

use env_logger::LogBuilder;
use getopts::Options;
use hyper::status::StatusCode;
use log::{LogLevelFilter, LogRecord};

use sota::http::AuthClient;
use sota::http::http_client::{Client, Response};
use sota::datatype::{Config, Auth};
use sota::datatype::network::Url;

pub struct Provisioner<'c, 'h> {
    config: &'c Config,
    http_client: &'h AuthClient,
}

impl<'c, 'h> Provisioner<'c, 'h> {
    pub fn new(config: &'c Config, http_client: &'h AuthClient) -> Self {
        Provisioner {
            config: config,
            http_client: http_client,
        }
    }

    // TODO propagate real error type upwards for logging
    // this was done lazily for faster development
    pub fn run(&mut self) -> Result<(), ()> {
        let _ = self.ensure_dir_structure_exists()?;
        self.check_root_json()
    }

    fn ensure_dir_structure_exists(&self) -> Result<(), ()> {
        let dirs = vec![
            "certs",
            "repo/director/metadata/current",
            "repo/director/metadata/previous",
            "repo/main/metadata/current",
            "repo/main/metadata/previous",
        ].iter()
            .map(|dir| format!("{}/{}", self.config.uptane.repo_path, dir))
            .collect::<Vec<String>>();

        let perms = Permissions::from_mode(0o0750);

        for dir in dirs {
            let _ = fs::create_dir_all(&dir).map_err(|_| ())?;
            let _ = fs::set_permissions(&dir, perms.clone()).map_err(|_| ())?;
        }

        Ok(())
    }

    /// If the mandatory `root.json` does not exist, talk to the API and download the current
    /// version.
    fn check_root_json(&self) -> Result<(), ()> {
        let has_root = self.check_fs_for_root_json()?;
        if !has_root {
            let root_meta_bytes = self.get_root_json()?;
            let json_path = format!("{}/repo/director/metadata/current/root.json", self.config.uptane.repo_path);
            let mut file = File::create(json_path).map_err(|_| ())?;
            let perms = Permissions::from_mode(0o0640);
            // Set safe perms before writing
            let _ = file.set_permissions(perms).map_err(|_| ())?;
            file.write_all(&root_meta_bytes).map_err(|_| ())
        } else {
            Ok(())
        }
    }

    /// Checks the local FS for the `root.json`, returns `true` if it is present, `false`
    /// if it is not, and `Err` if the check fails entirely.
    fn check_fs_for_root_json(&self) -> Result<bool, ()> {
        Ok(false) // TODO
    }

    /// Get the `root.json` from the API including creating it if it does not exist
    fn get_root_json(&self) -> Result<Vec<u8>, ()> {
        self.api_get_root_json().and_then(|opt| {
            match opt {
                Some(resp) => Ok(resp),
                None => self.api_create_root_json()
                    .and_then(|_| {
                        match self.api_get_root_json() {
                            Ok(Some(resp)) => Ok(resp),
                            _ => Err(()),
                        }
                    })
            }
        })
    }

    /// Call the API and issue a create `root.json` command. If it 409's (already exists),
    /// return `Ok`.
    fn api_create_root_json(&self) -> Result<(), ()> {
        let url_str = format!("{}/repo/root.json", self.config.core.server);
        let url = url::Url::parse(&url_str).map_err(|_| ())?;
        let body = br#"{"threshold": 1}"#.to_vec();
        match self.http_client.post(Url(url), Some(body)).recv() {
            Some(Response::Success(_)) => Ok(()),
            _ => Err(()),
        }
    }

    // TODO return json body
    /// Gets the `root.json` from the API.
    /// Returns `Ok(Some(bytes))` if it gets the JSON
    ///         `Ok(None)` if the JSON isn't ready yet
    ///         `Err(_)` if everything breaks
    fn api_get_root_json(&self) -> Result<Option<Vec<u8>>, ()> {
        let url_str = format!("{}/api/v1/repo/{}/root.json", self.config.core.server, ""); // TODO repo id
        let url = url::Url::parse(&url_str).map_err(|_| ())?;
        let resp = self.http_client.get(Url(url), None).recv();

         match resp {
            Some(Response::Success(ref r)) if r.code.is_success() => {
                Ok(Some(r.body.clone()))
            },
            Some(Response::Failed(ref r)) if r.code == StatusCode::NotFound => {
                Ok(None)
            }
            _ => Err(())
        }
    }
}

macro_rules! exit {
    ($code:expr, $fmt:expr, $($arg:tt)*) => {{
        print!(concat!($fmt, "\n"), $($arg)*);
        process::exit($code);
    }}
}


fn main() {
    let version = start_logging();
    let config = build_config(&version);
    let http_client = AuthClient::from(Auth::Certificate);
    let mut provisioner = Provisioner::new(&config, &http_client);

    match provisioner.run() {
        Ok(_) => exit!(0, "Successful provision.{}", ""),
        Err(_) => exit!(1, "Provision failed!{}", ""),
    }
}

fn start_logging() -> String {
    let version = option_env!("SOTA_VERSION").unwrap_or("unknown");

    let mut builder = LogBuilder::new();
    builder.format(move |record: &LogRecord| {
        let timestamp = format!("{}", time::now_utc().rfc3339());
        format!("{} ({}): {} - {}", timestamp, version, record.level(), record.args())
    });
    builder.filter(Some("hyper"), LogLevelFilter::Info);
    builder.parse(&env::var("RUST_LOG").unwrap_or("INFO".to_string()));
    builder.init().expect("builder already initialized");

    version.to_string()
}

fn build_config(version: &str) -> Config {
    let args     = env::args().collect::<Vec<String>>();
    let program  = args[0].clone();
    let mut opts = Options::new();

    opts.optflag("h", "help", "print this help menu then quit");
    opts.optflag("p", "print", "print the parsed config then quit");
    opts.optflag("v", "version", "print the version then quit");
    opts.optopt("c", "config", "change config path", "PATH");

    let matches = opts.parse(&args[1..]).unwrap_or_else(|err| panic!(err.to_string()));

    if matches.opt_present("help") {
        exit!(0, "{}", opts.usage(&format!("Usage: {} [options]", program)));
    } else if matches.opt_present("version") {
        exit!(0, "{}", version);
    }

    let  config = match matches.opt_str("config").or(env::var("SOTA_CONFIG").ok()) {
        Some(file) => Config::load(&file).unwrap_or_else(|err| exit!(1, "{}", err)),
        None => {
            warn!("No config file given. Falling back to defaults.");
            Config::default()
        }
    };

    if matches.opt_present("print") {
        exit!(0, "{:#?}", config);
    }

    config
}
