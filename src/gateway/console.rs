use chan::{self, Sender, Receiver};
use std::{io, thread};
use std::io::Write;
use std::sync::{Arc, Mutex};

use datatype::{Command, Error, Event};
use gateway::{Gateway, Interpret};


/// The console gateway is used for REPL-style interaction with the client.
pub struct Console;

impl Gateway for Console {
    fn start(&mut self, itx: Sender<Interpret>, _: Receiver<Event>) {
        info!("Starting Console gateway.");
        let (etx, erx) = chan::sync::<Event>(0);
        let etx = Arc::new(Mutex::new(etx));

        thread::spawn(move || loop {
            let _ = get_input()
                .map(|cmd| itx.send(Interpret { cmd: cmd, etx: Some(etx.clone()) }))
                .map_err(|err| error!("Console: {:?}", err));
        });

        thread::spawn(move || loop {
            info!("Console: {}", erx.recv().expect("etx closed"));
        });
    }
}

fn get_input() -> Result<Command, Error> {
    let mut input = String::new();
    let _ = io::stdout().write(b"> ");
    io::stdout().flush().expect("couldn't flush console stdout buffer");
    let _ = io::stdin().read_line(&mut input);
    input.parse()
}
