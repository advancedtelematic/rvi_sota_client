extern crate env_logger;
extern crate getopts;
extern crate hyper;
extern crate libotaplus;

use getopts::Options;
use hyper::Url;
use std::env;
use std::process::exit;

use libotaplus::{config, read_interpret};
use libotaplus::config::Config;
use libotaplus::read_interpret::ReplEnv;
use libotaplus::ota_plus::{Client as OtaClient};
use libotaplus::auth_plus::{Client as AuthClient};
use libotaplus::package_manager::{PackageManager, Dpkg};
use libotaplus::error::Error;

fn main() {

    env_logger::init().unwrap();

    let config_file = env::var("OTA_PLUS_CLIENT_CFG")
        .unwrap_or("/opt/ats/ota/etc/ota.toml".to_string());

    let config = config::load_config(&config_file)
        .unwrap_or_else(|err| {
            println!("{} (continuing with the default config)", err);
            return Config::default();
        });

    do_stuff(handle_flags(config));

}

fn do_stuff(config: Config) {

    fn post_installed_packages<M>(client: OtaClient, manager: M) -> Result<(), Error>
        where M: PackageManager {
            manager.installed_packages().and_then(|pkgs| client.post_packages(pkgs))
        }

    fn build_ota_client(config: Config) -> Result<OtaClient, Error> {
        AuthClient::new(config.auth.clone()).authenticate().map(|token| {
            OtaClient::new(token, config.ota.clone())
        })
    }

    let pkg_manager = Dpkg::new();
    let pkg_manager_clone = pkg_manager.clone();

    let _ = build_ota_client(config.clone()).and_then(|client| {
        post_installed_packages(client, pkg_manager)
    }).map(|_| {
        print!("Installed packages were posted successfully.");
    }).map_err(|e| {
        print!("{}", e);
    });

    if config.test.looping {
        read_interpret::read_interpret_loop(ReplEnv::new(pkg_manager_clone));
    }
}

fn handle_flags(config: Config) -> Config {

    fn print_usage(program: &str, opts: Options) {
        let brief = format!("Usage: {} [options]", program);
        print!("{}", opts.usage(&brief));
    }

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help",
                 "print this help menu");
    opts.optopt("", "auth-server",
                "change the auth server url", "URL");
    opts.optopt("", "auth-client-id",
                "change auth client id", "ID");
    opts.optopt("", "auth-secret",
                "change auth secret", "SECRET");
    opts.optopt("", "ota-server",
                "change ota server url", "URL");
    opts.optopt("", "ota-vin",
                "change ota vin", "VIN");
    opts.optflag("", "test-looping",
                 "enable read-interpret test loop");

    let matches = opts.parse(&args[1..])
        .unwrap_or_else(|err| panic!(err.to_string()));

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(1);
    }

    let mut config = config;

    if let Some(s) = matches.opt_str("auth-server") {
        match Url::parse(&s) {
            Ok(url)  => config.auth.server = url,
            Err(err) => panic!("invalid auth-server url: {}", err)
        }
    }

    if let Some(client_id) = matches.opt_str("auth-client-id") {
        config.auth.client_id = client_id;
    }

    if let Some(secret) = matches.opt_str("auth-secret") {
        config.auth.secret = secret;
    }

    if let Some(s) = matches.opt_str("ota-server") {
        match Url::parse(&s) {
            Ok(url)  => config.ota.server = url,
            Err(err) => panic!("invalid ota-server url: {}", err)
        }
    }

    if let Some(vin) = matches.opt_str("ota-vin") {
        config.ota.vin = vin;
    }

    if matches.opt_present("test-looping") {
        config.test.looping = true;
    }

    return config
}


#[cfg(test)]
mod tests {

    use std::ffi::OsStr;
    use std::process::Command;

    fn client<S: AsRef<OsStr>>(args: &[S]) -> String {
        let output = Command::new("target/debug/ota_plus_client")
            .args(args)
            .output()
            .unwrap_or_else(|e| { panic!("failed to execute child: {}", e) });

        return String::from_utf8(output.stdout).unwrap()
    }

    #[test]
    fn help() {

        assert_eq!(client(&["-h"]),
r#"Usage: target/debug/ota_plus_client [options]

Options:
    -h, --help          print this help menu
        --auth-server URL
                        change the auth server url
        --auth-client-id ID
                        change auth client id
        --auth-secret SECRET
                        change auth secret
        --ota-server URL
                        change ota server url
        --ota-vin VIN   change ota vin
        --test-looping  enable read-interpret test loop
"#);

    }

}
