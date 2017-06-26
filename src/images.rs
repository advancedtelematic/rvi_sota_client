use chrono::{DateTime, Utc};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::str::FromStr;
use std::time::Duration;

use datatype::{Error, Util};


/// Metadata regarding an image to be transferred between ECUs in chunks.
#[derive(Serialize, Deserialize)]
pub struct ImageMeta {
    pub image_name: String,
    pub sha1sum: String,
    pub num_chunks: u64,
}

impl ImageMeta {
    pub fn new(image_name: String, sha1sum: String, num_chunks: u64) -> Self {
        ImageMeta { image_name: image_name, sha1sum: sha1sum, num_chunks: num_chunks }
    }
}


/// Read a local image in chunks for sending to a `Secondary` ECU.
#[derive(Serialize, Deserialize)]
pub struct ImageReader {
    pub image_name: String,
    pub image_dir: String,
    pub image_size: u64,
    pub chunk_size: u64,
    pub num_chunks: u64,
}

impl ImageReader {
    /// Create a new chunk reader for an image.
    pub fn new(image_name: String, image_dir: String, chunk_size: u64) -> Result<Self, Error> {
        let meta = fs::metadata(&format!("{}/{}", image_dir, image_name))?;
        Ok(ImageReader {
            image_name: image_name,
            image_dir: image_dir,
            image_size: meta.len(),
            chunk_size: chunk_size,
            num_chunks: (meta.len() as f64 / chunk_size as f64).ceil() as u64
        })
    }

    /// Read a chunk of the image at the given index.
    pub fn read_chunk(&self, index: u64) -> Result<Vec<u8>, Error> {
        if index >= self.num_chunks {
            return Err(Error::Image(format!("invalid chunk index: {}", index)));
        }
        let mut buf = Vec::with_capacity(self.chunk_size as usize);
        let mut file = File::open(&format!("{}/{}", self.image_dir, self.image_name))?;
        file.seek(SeekFrom::Start(index * self.chunk_size))?;
        file.take(self.chunk_size).read_to_end(&mut buf)?;
        if index == self.num_chunks - 1 { // last chunk
            buf.truncate((self.image_size % self.chunk_size) as usize);
        }
        Ok(buf)
    }

    /// Generate a SHA1 checksum of the image data.
    pub fn sha1sum(&self) -> Result<String, Error> {
        let mut hash = Sha1::new();
        for index in 0..self.num_chunks {
            hash.input(&self.read_chunk(index)?);
        }
        Ok(hash.result_str())
    }

    /// Generate metadata about the image.
    pub fn image_meta(&self) -> Result<ImageMeta, Error> {
        Ok(ImageMeta {
            image_name: self.image_name.clone(),
            sha1sum: self.sha1sum()?,
            num_chunks: self.num_chunks,
        })
    }
}


/// Re-build an image from individual chunks.
#[derive(Serialize, Deserialize)]
pub struct ImageWriter {
    pub meta: ImageMeta,
    pub images_dir: String,
    pub chunks_dir: String,
    pub last_written: DateTime<Utc>,
    pub chunks_written: HashSet<u64>,
}

impl ImageWriter {
    /// Prepare to read an image file in chunks.
    pub fn new(meta: ImageMeta, images_dir: String) -> Self {
        let chunks_dir = format!("{}/chunks/{}", images_dir, meta.image_name);
        fs::create_dir_all(&chunks_dir).expect("couldn't create chunks dir");
        ImageWriter {
            meta: meta,
            images_dir: images_dir,
            chunks_dir: chunks_dir,
            last_written: Utc::now(),
            chunks_written: HashSet::new(),
        }
    }

    /// Write a chunk of the image to the disk.
    pub fn write_chunk(&mut self, data: &[u8], index: u64) -> Result<(), Error> {
        trace!("writing chunk {} for {}", index, self.meta.image_name);
        let mut file = File::create(format!("{}/{}", self.chunks_dir, index))?;
        file.write_all(data)?;
        file.flush()?;
        self.chunks_written.insert(index);
        self.last_written = Utc::now();
        Ok(())
    }

    /// Boolean indicating whether all chunks have been written.
    pub fn is_complete(&self) -> bool {
        self.chunks_written.len() == self.meta.num_chunks as usize
    }

    /// Assemble the received chunks into an image and return the path.
    pub fn assemble(&self) -> Result<String, Error> {
        debug!("assembling chunks for `{}`", self.meta.image_name);
        let mut indices = fs::read_dir(&self.chunks_dir)?.map(|entry| {
            entry.map_err(|err| Error::Image(format!("bad entry: {}", err)))
                .and_then(|entry| {
                    entry.file_name().to_str()
                        .ok_or_else(|| Error::Image(format!("invalid filename: {:?}", entry)))
                        .and_then(|name| u64::from_str(name).map_err(|err| Error::Image(format!("bad index: {}", err))))
                })
        }).collect::<Result<Vec<u64>, _>>()?;
        indices.sort();

        let image_path = format!("{}/{}", self.images_dir, self.meta.image_name);
        let mut file = File::create(&image_path)?;
        let mut hash = Sha1::new();
        for index in indices {
            let chunk = Util::read_file(&format!("{}/{}", self.chunks_dir, index))?;
            file.write(&chunk)?;
            hash.input(&chunk);
        }

        if hash.result_str() != self.meta.sha1sum {
            Err(Error::Image(format!("sha1sum expected {}, got {}", self.meta.sha1sum, hash.result_str())))
        } else {
            Ok(image_path)
        }
    }
}

impl Drop for ImageWriter {
    fn drop(&mut self) {
        let _ = fs::read_dir(&self.chunks_dir).map(|entries| {
            for entry in entries { let _ = entry.map(|entry| fs::remove_file(entry.path())); }
            fs::remove_dir(&self.chunks_dir).unwrap_or_else(|err| error!("couldn't remove chunks dir: {}", err));
        });
    }
}


/// All currently active transfers of images being rebuilt from chunks.
#[derive(Serialize, Deserialize)]
pub struct Transfers {
    pub active: HashMap<String, ImageWriter>,
    pub images_dir: String,
    pub timeout: Duration,
}

impl Transfers {
    pub fn new(images_dir: String, timeout: Duration) -> Self {
        Transfers {
            active: HashMap::new(),
            images_dir: images_dir,
            timeout: timeout,
        }
    }

    pub fn get(&self, image_name: &str) -> Option<&ImageWriter> {
        self.active.get(image_name)
    }

    pub fn get_mut(&mut self, image_name: &str) -> Option<&mut ImageWriter> {
        self.active.get_mut(image_name)
    }

    pub fn push(&mut self, image_name: String, image_writer: ImageWriter) {
        self.active.insert(image_name, image_writer);
    }

    pub fn remove(&mut self, image_name: &str) {
        self.active.remove(image_name);
    }

    pub fn clear(&mut self) {
        self.active.clear();
    }

    pub fn prune(&mut self) {
        let inactive = self.active.iter()
            .filter_map(|(name, image)| {
                let waiting = Utc::now().signed_duration_since(image.last_written).to_std().expect("last sent");
                if waiting > self.timeout { Some(name.clone()) } else { None }
            })
            .collect::<Vec<_>>();
        for image_name in inactive {
            info!("Image transfer timed out: {}", image_name);
            self.remove(&image_name);
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;


    fn new_reader(image_name: String, image_dir: String, data: &[u8], chunk_size: u64) -> ImageReader {
        fs::create_dir_all(&image_dir).expect("create dir");
        Util::write_file(&format!("{}/{}", image_dir, image_name), data).expect("write test image");
        ImageReader::new(image_name, image_dir, chunk_size).expect("test image")
    }

    #[test]
    fn reassemble_image() {
        let dir = format!("/tmp/sota-test-image-{}", Utc::now().timestamp());
        let infile = "test-image-in.dat";
        let outfile = "test-image-out.dat";
        let data = b"1234567890";
        let chunk_size = 3;
        let sha1 = "01b307acba4f54f55aafc33bb06bbbf6ca803e9a";

        let reader = new_reader(infile.into(), dir.clone(), data, chunk_size);
        assert_eq!(reader.image_size, 10);
        assert_eq!(reader.num_chunks, 4);
        assert_eq!(reader.sha1sum().expect("sha1sum"), sha1);

        let meta = ImageMeta::new(outfile.into(), sha1.into(), reader.num_chunks);
        let mut writer = ImageWriter::new(meta, dir.clone());
        for index in 0..reader.num_chunks {
            let chunk = reader.read_chunk(index).expect("read chunk");
            writer.write_chunk(&chunk, index).expect("write chunk");
        }

        let _ = writer.assemble().expect("assemble chunks");
        let written = Util::read_file(&format!("{}/{}", dir, outfile)).expect("written");
        assert_eq!(&written, data);
    }
}
