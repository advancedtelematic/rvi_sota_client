extern crate sota;

use sota::datatype::Config;


fn test_config(path: &str, is_ok: bool) {
    match (Config::load(path), is_ok) {
        (Ok(_), false)       => panic!("config parsing ok but should have failed"),
        (Err(ref err), true) => panic!("config parsing failed: {}", err),
        _ => ()
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
fn certificate_config() {
    test_config("tests/toml/certificate.toml", true);
}

#[test]
fn old_config() {
    test_config("tests/toml/old.toml", true);
}

#[test]
fn polling_config() {
    test_config("tests/toml/polling.toml", false);
}
