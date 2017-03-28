use chan::{self, Sender, Receiver};


/// Receive a message and broadcast to all current peers.
pub struct Broadcast<A: Clone> {
    rx:    Receiver<A>,
    peers: Vec<Sender<A>>,
}

impl<A: Clone> Broadcast<A> {
    /// Instantiate a new broadcaster for the given `Receiver`.
    pub fn new(rx: Receiver<A>) -> Broadcast<A> {
        Broadcast { rx: rx, peers: Vec::new() }
    }

    /// Start forwarding received messages to every peer.
    pub fn start(&self) {
        while let Some(msg) = self.rx.recv() {
            for peer in &self.peers {
                peer.send(msg.clone());
            }
        }
    }

    /// Subscribe to all subsequent broadcast messages.
    pub fn subscribe(&mut self) -> Receiver<A> {
        let (tx, rx) = chan::sync::<A>(0);
        self.peers.push(tx);
        rx
    }
}


#[cfg(test)]
mod tests {
    use chan;
    use std::thread;

    use super::*;


    #[test]
    fn test_broadcast() {
        let (tx, rx) = chan::sync(0);
        let mut bc = Broadcast::new(rx);

        let one = bc.subscribe();
        let two = bc.subscribe();
        thread::spawn(move || bc.start());

        tx.send(123);
        assert_eq!(123, one.recv().unwrap());
        assert_eq!(123, two.recv().unwrap());
    }
}
