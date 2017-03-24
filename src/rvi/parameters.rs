use std::sync::Mutex;
use uuid::Uuid;

use datatype::{ChunkReceived, Event, DownloadComplete, UpdateAvailable};
use rvi::services::{BackendServices, RemoteServices};
use rvi::transfers::Transfers;


/// Each `Parameter` implementation handles a specific kind of RVI client request,
/// optionally responding with an `Event` on completion.
pub trait Parameter {
    fn handle(&self, remote: &Mutex<RemoteServices>, transfers: &Mutex<Transfers>)
              -> Result<Option<Event>, String>;
}


#[derive(Deserialize, Serialize)]
pub struct Notify {
    update_available: UpdateAvailable,
    services:         BackendServices
}

impl Parameter for Notify {
    fn handle(&self, remote: &Mutex<RemoteServices>, _: &Mutex<Transfers>) -> Result<Option<Event>, String> {
        remote.lock().unwrap().backend = Some(self.services.clone());
        Ok(Some(Event::UpdateAvailable(self.update_available.clone())))
    }
}


#[derive(Deserialize, Serialize)]
pub struct Start {
    update_id:   Uuid,
    chunkscount: u64,
    checksum:    String
}

impl Parameter for Start {
    fn handle(&self, remote: &Mutex<RemoteServices>, transfers: &Mutex<Transfers>) -> Result<Option<Event>, String> {
        info!("Starting transfer for update_id {}", self.update_id);
        let mut transfers = transfers.lock().unwrap();
        transfers.push(self.update_id.clone(), self.checksum.clone());

        let remote = remote.lock().unwrap();
        let chunk  = ChunkReceived {
            device:    remote.device_id.clone(),
            update_id: self.update_id.clone(),
            chunks:    Vec::new()
        };
        remote.send_chunk_received(chunk)
            .map(|_| None)
            .map_err(|err| format!("error sending start ack: {}", err))
    }
}


#[derive(Deserialize, Serialize)]
pub struct Chunk {
    update_id: Uuid,
    bytes:     String,
    index:     u64
}

impl Parameter for Chunk {
    fn handle(&self, remote: &Mutex<RemoteServices>, transfers: &Mutex<Transfers>) -> Result<Option<Event>, String> {
        let remote = remote.lock().unwrap();

        let mut transfers = transfers.lock().unwrap();
        let transfer      = try!(transfers.get_mut(self.update_id.clone())
                                 .ok_or(format!("couldn't find transfer for update_id {}", self.update_id)));
        transfer.write_chunk(&self.bytes, self.index)
            .map_err(|err| format!("couldn't write chunk: {}", err))
            .and_then(|_| {
                trace!("wrote chunk {} for package {}", self.index, self.update_id);
                let chunk = ChunkReceived {
                    device:    remote.device_id.clone(),
                    update_id: self.update_id.clone(),
                    chunks:    transfer.transferred_chunks.clone(),
                };
                remote.send_chunk_received(chunk)
                    .map(|_| None)
                    .map_err(|err| format!("error sending ChunkReceived: {}", err))
            })
    }
}


#[derive(Deserialize, Serialize)]
pub struct Finish {
    update_id: Uuid,
    signature: String
}

impl Parameter for Finish {
    fn handle(&self, _: &Mutex<RemoteServices>, transfers: &Mutex<Transfers>) -> Result<Option<Event>, String> {
        let mut transfers = transfers.lock().unwrap();
        let image = {
            let transfer = try!(transfers.get(self.update_id.clone())
                                .ok_or(format!("unknown package: {}", self.update_id)));
            let package  = try!(transfer.assemble_package()
                                .map_err(|err| format!("couldn't assemble package: {}", err)));
            try!(package.into_os_string().into_string()
                 .map_err(|err| format!("couldn't get image: {:?}", err)))
        };
        transfers.remove(self.update_id.clone());
        info!("Finished transfer of {}", self.update_id);

        let complete = DownloadComplete {
            update_id:    self.update_id.clone(),
            update_image: image,
            signature:    self.signature.clone()
        };
        Ok(Some(Event::DownloadComplete(complete)))
    }
}


#[derive(Deserialize, Serialize)]
pub struct Report;

impl Parameter for Report {
    fn handle(&self, _: &Mutex<RemoteServices>, _: &Mutex<Transfers>) -> Result<Option<Event>, String> {
        Ok(Some(Event::InstalledSoftwareNeeded))
    }
}


#[derive(Deserialize, Serialize)]
pub struct Abort;

impl Parameter for Abort {
    fn handle(&self, _: &Mutex<RemoteServices>, transfers: &Mutex<Transfers>) -> Result<Option<Event>, String> {
        transfers.lock().unwrap().clear();
        Ok(None)
    }
}
