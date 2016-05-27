//! Helper functions and traits for all configuration sections.

use toml;
use std::result;
use std::fmt;
use http::Url;

/// `Result` type used throughout the configuration parser.
pub type Result<T> = result::Result<T, String>;

/// Trait that provides a interface for parsing a (sub-) tree of the configuration.
pub trait ConfTreeParser<C> {
    /// Try to parse the given `tree` into the type this trait is implemented for.
    /// Returns the parsed object or a error message, with the first error encountered while
    /// parsing the `tree`.
    ///
    /// # Arguments
    /// * `tree`: The `toml` tree to parse
    fn parse(tree: &toml::Table) -> Result<C>;
}

/// Parse a required key, returning a appropriate error message, if the key can't be found in the
/// configuration.
///
/// # Arguments
/// * `subtree`: The `toml` tree to parse.
/// * `key`: The key to look for.
/// * `group`: The group, this (sub-) tree is associated with.
pub fn get_required_key<D>(subtree: &toml::Value, key: &str, group: &str)
    -> Result<D> where D: ParseTomlValue {
    let value = try!(subtree.lookup(key)
                     .ok_or(format!("Missing required key \"{}\" in \"{}\"",
                                    key, group)));
    ParseTomlValue::parse(value, key, group)
}

/// Parse a optional key, returning None if it can't be found.
///
/// This basically does a `Option<Result>` to `Result<Option>` translation
///
/// # Arguments
/// * `subtree`: The `toml` tree to parse.
/// * `key`: The key to look for.
/// * `group`: The group, this (sub-) tree is associated with.
pub fn get_optional_key<D>(subtree: &toml::Value, key: &str, group: &str)
    -> Result<Option<D>> where D: ParseTomlValue {
    match subtree.lookup(key) {
        Some(val) => {
            Ok(Some(try!(ParseTomlValue::parse(val, key, group))))
        },
        None => Ok(None)
    }
}

/// Trait that provides a interface for parsing a single `toml` value.
pub trait ParseTomlValue {
    /// Parse a `String` from a `toml` value. Returns the parsed value on success or a error
    /// message on failure.
    ///
    /// # Arguments
    /// * `val`: The `toml` value to parse.
    /// * `key`: The key this value is associated with.
    /// * `group`: The group, this (sub-) tree is associated with.
    fn parse(val: &toml::Value, key: &str, group: &str) -> Result<Self> where Self: Sized;
}

impl ParseTomlValue for String {
    fn parse(val: &toml::Value, key: &str, group: &str)
        -> Result<String> {
        val.as_str().map(|s| s.to_string())
           .ok_or(format!("Key \"{}\" in \"{}\" is not a string", key, group))
    }
}

impl ParseTomlValue for i32 {
    fn parse(val: &toml::Value, key: &str, group: &str)
        -> Result<i32> {
        val.as_integer().map(|i| i as i32)
           .ok_or(format!("Key \"{}\" in \"{}\" is not a integer", key, group))
    }
}

impl ParseTomlValue for i64 {
    fn parse(val: &toml::Value, key: &str, group: &str)
        -> Result<i64> {
        val.as_integer()
           .ok_or(format!("Key \"{}\" in \"{}\" is not a integer", key, group))
    }
}

impl ParseTomlValue for bool {
    fn parse(val: &toml::Value, key: &str, group: &str)
        -> Result<bool> {
        val.as_str().map(|s| s == "true")
           .ok_or(format!("Key \"{}\" in \"{}\" is not a string", key, group))
    }
}

impl ParseTomlValue for Url {
    fn parse(val: &toml::Value, key: &str, group: &str)
        -> Result<Url> {
        val.as_str()
            .ok_or(format!("Key \"{}\" in \"{}\" is not a string", key, group))
            .and_then(|s| Url::parse(s).map_err(|_| {
                format!("Key \"{}\" in \"{}\" is not a valid URL", key, group)
            }))
    }
}

/// Helper function to format a `toml::Parser` error message to the format used in this
/// implementation. This is only safe to call if the `parser` is associated with a *real* file on
/// disk.
///
/// # Arguments
/// * `parser`: Pointer to the `toml::Parser`, that produced a error.
#[cfg(not(test))]
pub fn format_parser_error(parser: &toml::Parser) -> String {
    let linecol = parser.to_linecol(0);
    format!("parse error: {}:{}: {:?}", linecol.0, linecol.1, parser.errors)
}

/// Helper function to format a `toml::Parser` error message to the format used in this
/// implementation. This version is always safe to call, but doesn't print the line and column
/// where the error was encountered.
///
/// # Arguments
/// * `parser`: Pointer to the `toml::Parser`, that produced a error.
#[cfg(test)]
pub fn format_parser_error(parser: &toml::Parser) -> String {
    format!("parse error: {:?}", parser.errors)
}

/// Helper function to copy anything that implements `Display` to a `String`.
pub fn stringify<T>(e: T) -> String
    where T: fmt::Display {
    format!("{}", e)
}

/// Reads the provided `tree` as a `toml::Table`. Returns the `toml::Table` on success or a error
/// message on failure.
///
/// # Arguments
/// * `tree`: Pointer to a `str`, that holds a toml configuration.
#[cfg(test)]
pub fn read_tree(tree: &str) -> Result<toml::Table> {
    let mut parser = toml::Parser::new(tree);
    parser.parse().ok_or(format_parser_error(&parser))
}
