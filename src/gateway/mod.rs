pub mod console;
pub mod dbus;
pub mod http;
pub mod socket;
pub mod websocket;

pub use self::console::Console;
pub use self::dbus::DBus;
pub use self::http::Http;
pub use self::socket::Socket;
pub use self::websocket::Websocket;


use chan::{Sender, Receiver};
use std::sync::{Arc, Mutex};

use datatype::{Command, Event};


/// Forwards a `Command` for processing and optionally listens for the outcome `Event`.
#[derive(Debug)]
pub struct Interpret {
    pub cmd: Command,
    pub etx: Option<Arc<Mutex<Sender<Event>>>>,
}

/// A `Gateway` may forward commands for processing and respond to global events.
pub trait Gateway {
    fn start(&mut self, itx: Sender<Interpret>, erx: Receiver<Event>);
}
