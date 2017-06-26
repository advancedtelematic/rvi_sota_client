use base64;
use std::sync::Mutex;
use uuid::Uuid;

use datatype::{Event, DownloadComplete, UpdateAvailable};
use images::{ImageMeta, ImageWriter, Transfers};
use rvi::json_rpc::ChunkReceived;
use rvi::services::{BackendServices, RemoteServices};


/// Each `Parameter` implementation handles a specific kind of RVI client request.
pub trait Parameter {
    fn handle(&self, remote: &Mutex<RemoteServices>, transfers: &Mutex<Transfers>) -> Result<Option<Event>, String>;
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
        let remote = remote.lock().unwrap();
        let mut transfers = transfers.lock().unwrap();
        let image_name = format!("{}", self.update_id);
        let meta = ImageMeta::new(image_name.clone(), self.checksum.clone(), self.chunkscount);
        let images_dir = transfers.images_dir.clone();
        transfers.push(image_name, ImageWriter::new(meta, images_dir));

        let chunk = ChunkReceived {
            device:    remote.device_id.clone(),
            update_id: self.update_id,
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

        let writer = transfers.get_mut(&format!("{}", self.update_id))
            .ok_or_else(|| format!("couldn't find transfer for update_id {}", self.update_id))?;
        let chunk = base64::decode(&self.bytes)
            .map_err(|err| format!("couldn't decode chunk for index {}: {}", self.index, err))?;
        writer.write_chunk(&chunk, self.index)
            .map_err(|err| format!("couldn't write chunk: {}", err))
            .and_then(|_| {
                trace!("wrote chunk {} for package {}", self.index, self.update_id);
                let mut chunks = writer.chunks_written.iter().map(|n| *n).collect::<Vec<_>>();
                chunks.sort();
                chunks.dedup();
                let chunk = ChunkReceived {
                    device: remote.device_id.clone(),
                    update_id: self.update_id,
                    chunks: chunks,
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
        let image_path = {
            let chunks = transfers.get(&format!("{}", self.update_id))
                .ok_or_else(|| format!("unknown package: {}", self.update_id))?;
            chunks.assemble().map_err(|err| format!("couldn't assemble package: {}", err))?
        };
        transfers.remove(&format!("{}", self.update_id));
        info!("Finished transfer of {}", self.update_id);

        let complete = DownloadComplete {
            update_id:    self.update_id,
            update_image: image_path,
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
