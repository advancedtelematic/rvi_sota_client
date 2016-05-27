//! This is the client in-vehicle portion of the SOTA project. See the [main SOTA Server
//! project](https://github.com/advancedtelematic/rvi_sota_server) and [associated architecture
//! document](http://advancedtelematic.github.io/rvi_sota_server/dev/architecture.html) for more
//! information.

extern crate hyper;
extern crate rustc_serialize;
extern crate time;
extern crate url;
extern crate crypto;
extern crate toml;
extern crate dbus;
extern crate tempfile;

#[macro_use] extern crate log;
extern crate env_logger;

#[cfg(test)] extern crate rand;

#[cfg(test)]
#[macro_use]
mod test_library;

/// Try to unwrap or log the error and run the second argument
///
/// # Arguments
/// 1. Expression to evaluate, needs to return a `Result<T, E> where E: Display` type.
/// 2. Expression to run on errors, after logging the error as error message.
#[macro_export]
macro_rules! try_or {
    ($expr:expr, $finalize:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                error!("{}", e);
                $finalize;
            }
        }
    }
}

/// Try to unwrap or log the provided message and run the third argument
///
/// # Arguments
/// 1. Expression to evaluate, needs to return a `Result<T, E>` type.
/// 2. Expression that returns a Object implementing the `Display` trait. This object will be
///    logged as a error message with `error!()`
/// 3. Expression to run on errors, after printing a error message.
#[macro_export]
macro_rules! try_msg_or {
    ($expr:expr, $msg:expr, $finalize:expr) => {
        match $expr {
            Ok(val) => val,
            Err(..) => {
                error!("{}", $msg);
                $finalize;
            }
        }
    }
}

mod event;
mod remote;

pub mod configuration;
pub mod genivi;
pub mod http;
