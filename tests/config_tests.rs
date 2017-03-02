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
fn template_config() {
    test_config("tests/config/template.toml", true);
}

#[test]
fn genivi_config() {
    test_config("tests/config/genivi.toml", true);
}

#[test]
fn old_config() {
    test_config("tests/config/old.toml", true);
}

#[test]
fn polling_config() {
    test_config("tests/config/polling.toml", false);
}

#[test]
fn provision_config() {
    test_config("tests/config/provision.toml", true);
}
