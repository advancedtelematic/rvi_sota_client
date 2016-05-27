//! Receiving side of the DBus interface.

use std::sync::mpsc::Sender;

use dbus::{Connection, NameFlag, BusType, ConnectionItem, Message, FromMessageItem};
use dbus::obj::*;

use configuration::DBusConfiguration;
use event::Event;
use event::outbound::{OutBoundEvent, OperationResults, UpdateReport};
use genivi::dbus::*;


/// Encodes the state that is needed to accept incoming DBus messages.
pub struct Receiver {
    /// The configuration for the DBus interface.
    config: DBusConfiguration,
    /// A sender to forward incoming messages.
    sender: Sender<Event>
}

impl Receiver {
    /// Create a new `Receiver`.
    ///
    /// # Arguments
    /// * `c`: The configuration for the DBus interface.
    /// * `s`: A sender to forward incoming messages.
    pub fn new(c: DBusConfiguration, s: Sender<Event>) -> Receiver {
        Receiver {
            config: c,
            sender: s
        }
    }

    /// Start the listener. It will register in DBus according to the configuration, wait for
    /// incoming messages and forward them via the internal `Sender`.
    pub fn start(&self) {
        let conn = Connection::get_private(BusType::Session).unwrap();
        conn.register_name(&self.config.name, NameFlag::ReplaceExisting as u32).unwrap();

        let initiate_download = Method::new(
            "initiateDownload",
            vec!(Argument::new("update_id", "s")),
            vec!(),
            Box::new(|msg| self.handle_initiate_download(msg)));
        let abort_download = Method::new(
            "abortDownload",
            vec!(Argument::new("update_id", "s")),
            vec!(),
            Box::new(|msg| self.handle_abort_download(msg)));
        let update_report = Method::new(
            "updateReport",
            vec!(Argument::new("update_id", "s"), Argument::new("operations_results", "aa{sv}")),
            vec!(),
            Box::new(|msg| self.handle_update_report(msg)));
        let interface = Interface::new(vec!(initiate_download, abort_download, update_report), vec!(), vec!());

        let mut object_path = ObjectPath::new(&conn, &self.config.path, true);
        object_path.insert_interface(&self.config.interface, interface);
        object_path.set_registered(true).unwrap();

        for n in conn.iter(1000) {
            match n {
                ConnectionItem::MethodCall(mut m) => {
                    object_path.handle_message(&mut m);
                },
                _ => {}
            }
        }
    }

    /// Handles incoming "Initiate Download" messages.
    ///
    /// Parses the message and forwards it to the internal `Sender`.
    ///
    /// # Arguments
    /// * `msg`: The message to handle.
    fn handle_initiate_download(&self, msg: &mut Message) -> MethodResult {
        let sender = try!(get_sender(msg).ok_or(missing_arg()));
        trace!("sender: {:?}", sender);
        trace!("msg: {:?}", msg);

        let mut args = msg.get_items().into_iter();
        let arg = try!(args.next().ok_or(missing_arg()));
        let update_id: &String = try!(FromMessageItem::from(&arg).or(Err(malformed_arg())));
        let _ = self.sender.send(
            Event::OutBound(OutBoundEvent::InitiateDownload(update_id.clone())));

        Ok(vec!())
    }

    fn handle_abort_download(&self, msg: &mut Message) -> MethodResult {
        let sender = try!(get_sender(msg).ok_or(missing_arg()));
        trace!("sender: {:?}", sender);
        trace!("msg: {:?}", msg);

        let mut args = msg.get_items().into_iter();
        let arg = try!(args.next().ok_or(missing_arg()));
        let update_id: &String = try!(FromMessageItem::from(&arg).or(Err(malformed_arg())));
        let _ = self.sender.send(
            Event::OutBound(OutBoundEvent::AbortDownload(update_id.clone())));

        Ok(vec!())
    }

    fn handle_update_report(&self, msg: &mut Message) -> MethodResult {
        let sender = try!(get_sender(msg).ok_or(missing_arg()));
        trace!("sender: {:?}", sender);
        trace!("msg: {:?}", msg);

        let mut args = msg.get_items().into_iter();
        let arg = try!(args.next().ok_or(missing_arg()));
        let update_id: &String = try!(FromMessageItem::from(&arg).or(Err(malformed_arg())));

        let arg = try!(args.next().ok_or(missing_arg()));
        let operation_results: OperationResults = try!(FromMessageItem::from(&arg).or(Err(malformed_arg())));

        let report = UpdateReport::new(update_id.clone(), operation_results);
        let _ = self.sender.send(
            Event::OutBound(OutBoundEvent::UpdateReport(report)));

        Ok(vec!())
    }
}

fn get_sender(msg: &Message) -> Option<String> {
    msg.sender().map(|s| s.to_string())
}
