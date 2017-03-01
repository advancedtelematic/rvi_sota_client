use chan;
use chan::Sender;
use std::{io, thread};
use std::io::Write;
use std::string::ToString;
use std::sync::{Arc, Mutex};

use datatype::{Command, Error, Event};
use super::gateway::{Gateway, Interpret};


/// The console gateway is used for REPL-style interaction with the client.
pub struct Console;

impl Gateway for Console {
    fn initialize(&mut self, itx: Sender<Interpret>) -> Result<(), String> {
        let (etx, erx) = chan::sync::<Event>(0);
        let etx        = Arc::new(Mutex::new(etx));

        thread::spawn(move || {
            loop {
                match get_input() {
                    Ok(cmd)  => itx.send(Interpret { command: cmd, resp_tx: Some(etx.clone()) }),
                    Err(err) => error!("Console Error: {:?}", err)
                }
            }
        });

        thread::spawn(move || {
            loop {
                let e = erx.recv().expect("all console event transmitters are closed");
                info!("Console Response: {}", e.to_string());
            }
        });

        Ok(info!("Console gateway started."))
    }
}

fn get_input() -> Result<Command, Error> {
    let mut input = String::new();
    let _ = io::stdout().write(b"> ");
    io::stdout().flush().expect("couldn't flush console stdout buffer");
    let _ = io::stdin().read_line(&mut input);
    input.parse()
}
