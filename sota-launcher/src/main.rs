#[macro_use] extern crate error_chain;
extern crate env_logger;
#[macro_use] extern crate log;
#[macro_use] extern crate maplit;
extern crate reqwest;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json as json;
extern crate sota;
extern crate uuid;

mod datatypes;
mod http;

use env_logger::LogBuilder;
use log::LogLevelFilter;
use std::env;
use uuid::Uuid;

use datatypes::*;
use http::*;


macro_rules! exit {
    ($fmt:expr) => { exit!(1, "{}", $fmt) };
    ($code:expr, $fmt:expr, $($arg:tt)*) => {{
        println!($fmt, $($arg)*);
        ::std::process::exit($code);
    }}
}

fn main() {
    start_logging();

    let cookie = "PLAY_SESSION=1fcb0be8da55d6be5cf5d65cd79c88f8a976e795-id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InNoYXVuKzVAYWR2YW5jZWR0ZWxlbWF0aWMuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOi8vYXRzLWRldi5ldS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NTk0Y2U0MzRiYWQ2ZjEwOWY5ZjliZGI2IiwiYXVkIjoialc1WnUyRlJsVHBnbkZkamFVSGlDTXRLbllOMWY3TkIiLCJleHAiOjE0OTkzODk4MjQsImlhdCI6MTQ5OTM1MzgyNH0.qKFdZ0u1X8pmGeW5hj9tL7dry0-p0yAFuIMT3C4a5Sw&access_token=hzKO1gxQUO0Goi42&auth_plus_access_token=eyJhbGciOiJIUzI1NiIsImtpZCI6bnVsbH0.eyJpc3MiOiJodHRwczovL2F1dGgtcGx1cy5hZHZhbmNlZHRlbGVtYXRpYy5jb20iLCJhdWQiOlsidG9rZW4iLCJjbGllbnQiXSwianRpIjoiQmxUUFNjSllScEZHRmhtU2tFRTIiLCJjbGllbnRfaWQiOiJjMDYxYjEzMC0yMjYyLTQwYjMtYjc2My0zOGM0ZGY0NWIwMjAiLCJzdWIiOiJhdXRoMHw1OTRjZTQzNGJhZDZmMTA5ZjlmOWJkYjYiLCJvd25lciI6bnVsbCwiaWF0IjoxNDk5MzUzODI0LCJleHAiOjE0OTk0NDAyMjQsInNjb3BlIjoidG9rZW4uaW50cm9zcGVjdCBjbGllbnQucmVnaXN0ZXIgY2xpZW50LnVwZGF0ZSJ9.E2v03Xh4axRrZ8jgEaPVIOCI3Z4gkZnp6egCSNIHlJE&csrfToken=ff7aef60fa8ca75547af58119ac849333196333e-1499353825139-a475aee21ccdc7dd559bf62d&namespace=auth0%7C594ce434bad6f109f9f9bdb6".to_string();
    let targets = Targets {
        targets: hashmap![
            "123".into() => Update {
                to: Target {
                    target: "abc".into(),
                    targetLength: 100,
                    checksum: Checksum {
                        method: "sha256".into(),
                        hash: "012345678901234567890123456789012345678901234567890123456789abcd".into()
                    },
                }
            },
            "234".into() => Update {
                to: Target {
                    target: "def".into(),
                    targetLength: 0,
                    checksum: Checksum {
                        method: "sha256".into(),
                        hash: "abcd012345678901234567890123456789012345678901234567890123456789".into()
                    },
                }
            },
        ]
    };

    let exec = || -> Result<()> {
        let env = Environment::CI;
        let play = cookie.parse::<PlayCookie>()?;

        let mtu = MultiTargetUpdate::new(env, play)?;
        let update_id = mtu.create(&targets)?;

        let device_id = "72399394-1897-43df-af2e-c77613871c75".parse::<Uuid>()?;
        mtu.launch(device_id, update_id)?;

        Ok(())
    };

    exec().unwrap_or_else(|err| exit!(err))
}

fn start_logging() {
    let mut builder = LogBuilder::new();
    builder.format(move |log| format!("{}: {}", log.level(), log.args()));
    builder.filter(Some("hyper"), LogLevelFilter::Info);
    builder.parse(&env::var("RUST_LOG").unwrap_or_else(|_| "INFO".to_string()));
    builder.init().expect("builder already initialized");
}
