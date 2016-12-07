use std::{env, str};
use std::path::Path;
use std::process::{Command, Output};


fn run_client(config: &str) -> Output {
    let out_dir = env::var("OUT_DIR").expect("expected OUT_DIR environment variable");
    let bin_dir = Path::new(&out_dir).parent().unwrap().parent().unwrap().parent().unwrap();

    Command::new(format!("{}/sota_client", bin_dir.to_str().unwrap()))
        .arg("--print")
        .arg(format!("--config={}", config))
        .output()
        .unwrap_or_else(|err| panic!("couldn't start client: {}", err))
}

fn test_config(path: &str, is_ok: bool) {
    let output = run_client(path);
    if output.status.success() != is_ok {
        panic!("{}", str::from_utf8(&output.stderr).unwrap_or(""));
    }
}


#[test]
fn default_config() {
    test_config("tests/toml/default.toml", true);
}

#[test]
fn genivi_config() {
    test_config("tests/toml/genivi.toml", true);
}

#[test]
fn old_config() {
    test_config("tests/toml/old.toml", true);
}

#[test]
fn polling_config() {
    test_config("tests/toml/polling.toml", false);
}
