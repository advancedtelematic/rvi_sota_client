use chan::{self, Sender, Receiver};
use std::{io, thread};
use std::io::Write;

use datatype::{Command, Error, Event};
use gateway::Gateway;
use interpreter::CommandExec;


/// The console gateway is used for REPL-style interaction with the client.
pub struct Console;

impl Gateway for Console {
    fn start(&mut self, ctx: Sender<CommandExec>, _: Receiver<Event>) {
        info!("Starting Console gateway.");
        let (etx, erx) = chan::sync::<Event>(0);

        thread::spawn(move || loop {
            get_input()
                .map(|cmd| ctx.send(CommandExec { cmd: cmd, etx: Some(etx.clone()) }))
                .unwrap_or_else(|err| error!("Console: {:?}", err));
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
