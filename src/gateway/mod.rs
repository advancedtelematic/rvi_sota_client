pub mod console;
#[cfg(feature = "d-bus")]
pub mod dbus;
pub mod http;
#[cfg(feature = "socket")]
pub mod socket;
#[cfg(feature = "websocket")]
pub mod websocket;

pub use self::console::Console;
#[cfg(feature = "d-bus")]
pub use self::dbus::DBus;
pub use self::http::Http;
#[cfg(feature = "socket")]
pub use self::socket::Socket;
#[cfg(feature = "websocket")]
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
