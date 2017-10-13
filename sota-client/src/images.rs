use chrono::{DateTime, Utc};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::os::unix::fs::FileExt;
use std::str::FromStr;
use std::time::Duration;

use datatype::{Error, Util};


const CHUNK_DIR: &'static str = "/tmp/sota-image-chunks";
const CHUNK_SIZE: usize = 64*1024;


struct Chunk([u8; CHUNK_SIZE]);

impl Default for Chunk {
    fn default() -> Self {
        Chunk([0; CHUNK_SIZE])
    }
}


/// Metadata regarding an image to be transferred between ECUs in chunks.
#[derive(Serialize, Deserialize, Clone)]
pub struct ImageMeta {
    pub image_name: String,
    pub image_size: u64,
    pub num_chunks: u64,
    pub sha256sum: String,
}

impl ImageMeta {
    pub fn new(image_name: String, image_size: u64, num_chunks: u64, sha256sum: String) -> Self {
        ImageMeta {
            image_name: image_name,
            image_size: image_size,
            num_chunks: num_chunks,
            sha256sum: sha256sum,
        }
    }
}


/// Read a local image in chunks for sending to a `Secondary` ECU.
#[derive(Serialize, Deserialize)]
pub struct ImageReader {
    pub image_name: String,
    pub image_dir: String,
    pub image_size: u64,
    pub num_chunks: u64,

    #[serde(skip_serializing, skip_deserializing)]
    chunk: Chunk
}

impl ImageReader {
    /// Create a new chunk reader for an image.
    pub fn new(image_name: String, image_dir: String) -> Result<Self, Error> {
        let meta = fs::metadata(&format!("{}/{}", image_dir, image_name))?;
        Ok(ImageReader {
            image_name: image_name,
            image_dir: image_dir,
            image_size: meta.len(),
            num_chunks: (meta.len() as f64 / CHUNK_SIZE as f64).ceil() as u64,
            chunk: Chunk::default(),
        })
    }

    /// Read a chunk of the image at the given index.
    pub fn read_chunk(&mut self, index: u64) -> Result<&[u8], Error> {
        if index >= self.num_chunks {
            return Err(Error::Image(format!("invalid chunk index: {}", index)));
        }
        let file = File::open(&format!("{}/{}", self.image_dir, self.image_name))?;
        let len = file.read_at(&mut self.chunk.0, index * CHUNK_SIZE as u64)?;
        Ok(&self.chunk.0[..len])
    }

    /// Generate a SHA256 checksum of the image data.
    pub fn sha256sum(&mut self) -> Result<String, Error> {
        let mut hasher = Sha256::new();
        for index in 0..self.num_chunks {
            hasher.input(self.read_chunk(index)?);
        }
        Ok(hasher.result_str())
    }

    /// Generate metadata about the image.
    pub fn image_meta(&mut self) -> Result<ImageMeta, Error> {
        Ok(ImageMeta {
            image_name: self.image_name.clone(),
            image_size: self.image_size,
            num_chunks: self.num_chunks,
            sha256sum: self.sha256sum()?,
        })
    }
}


/// Re-build an image from individual chunks.
#[derive(Serialize, Deserialize)]
pub struct ImageWriter {
    pub meta: ImageMeta,
    pub image_dir: String,
    pub last_written: DateTime<Utc>,
    pub chunks_written: HashSet<u64>,
    pub chunks_available: HashSet<u64>,
}

impl ImageWriter {
    /// Prepare to write an image file in chunks.
    pub fn new(meta: ImageMeta, image_dir: String) -> Self {
        let chunks = (0..meta.num_chunks).collect();
        ImageWriter {
            meta: meta,
            image_dir: image_dir,
            last_written: Utc::now(),
            chunks_written: HashSet::new(),
            chunks_available: chunks,
        }
    }

    /// Write a specific chunk of an image to disk for re-assembly.
    pub fn write_chunk(&mut self, data: &[u8], index: u64) -> Result<(), Error> {
        let chunk_path = format!("{}/{}/{}", CHUNK_DIR, self.meta.image_name, index);
        let path = Path::new(&chunk_path);
        if let Some(dir) = path.parent() { fs::create_dir_all(dir)?; }
        trace!("saving chunk {} to {}", index, chunk_path);
        Util::write_file(&chunk_path, data)?;
        self.chunks_written.insert(index);
        self.chunks_available.remove(&index);
        self.last_written = Utc::now();
        Ok(())
    }

    /// Assemble all saved chunks into an output image.
    pub fn assemble_chunks(&self) -> Result<(), Error> {
        if ! self.chunks_available.is_empty() {
            return Err(Error::Image(format!("{} chunks remaining", self.chunks_available.len())))
        }
        let chunks_dir = format!("{}/{}", CHUNK_DIR, self.meta.image_name);
        let mut indices = fs::read_dir(&chunks_dir)?
            .map(|entry| {
                entry.map_err(|err| Error::Image(format!("bad entry: {}", err)))
                    .and_then(|entry| {
                        entry.file_name().to_str()
                            .ok_or_else(|| Error::Image(format!("invalid filename: {:?}", entry)))
                            .and_then(|name| u64::from_str(name)
                                      .map_err(|err| Error::Image(format!("bad index: {}", err))))
                    })
            })
            .collect::<Result<Vec<u64>, _>>()?;
        indices.sort();

        let image_path = format!("{}/{}", self.image_dir, self.meta.image_name);
        let path = Path::new(&image_path);
        if let Some(dir) = path.parent() { fs::create_dir_all(dir)?; }
        debug!("re-assembling chunks at `{}`", image_path);
        let mut file = File::create(&image_path)?;
        let mut hasher = Sha256::new();
        for index in indices {
            let chunk = Util::read_file(&format!("{}/{}", chunks_dir, index))?;
            file.write_all(&chunk)?;
            hasher.input(&chunk);
        }

        if hasher.result_str() != self.meta.sha256sum {
            Err(Error::Image(format!("expected sha256 of `{}`, got `{}`", self.meta.sha256sum, hasher.result_str())))
        } else {
            Ok(())
        }
    }

    /// Write a single chunk directly to the output image.
    pub fn write_direct(&mut self, data: &[u8], index: u64) -> Result<(), Error> {
        let image_path = format!("{}/{}", self.image_dir, self.meta.image_name);
        trace!("writing chunk {} to {}", index, image_path);
        let path = Path::new(&image_path);
        let mut file = if path.exists() {
            OpenOptions::new().write(true).open(&image_path)?
        } else {
            if let Some(dir) = path.parent() { fs::create_dir_all(dir)?; }
            let file = File::create(&image_path)?;
            file.set_len(self.meta.image_size)?;
            file
        };
        file.write_at(data, index * CHUNK_SIZE as u64)?;
        file.flush()?;
        self.chunks_written.insert(index);
        self.chunks_available.remove(&index);
        self.last_written = Utc::now();
        Ok(())
    }

    /// Verify the checksum of all directly written chunks is correct.
    pub fn verify_direct(&self) -> Result<(), Error> {
        let mut hasher = Sha256::new();
        hasher.input(&Util::read_file(&format!("{}/{}", self.image_dir, self.meta.image_name))?);
        if hasher.result_str() != self.meta.sha256sum {
            Err(Error::Image(format!("expected sha256 of `{}`, got `{}`", self.meta.sha256sum, hasher.result_str())))
        } else {
            Ok(())
        }
    }

    /// Return the index of an unwritten chunk.
    pub fn next_chunk(&self) -> Option<u64> {
        self.chunks_available.iter().next().cloned()
    }

    /// Verify the output image checksum.
    pub fn verify_image(&self) -> Result<(), Error> {
        let mut reader = ImageReader::new(self.meta.image_name.clone(), self.image_dir.clone())?;
        let checksum = reader.sha256sum()?;
        if checksum != self.meta.sha256sum {
            Err(Error::Image(format!("expected sha256 of `{}`, got `{}`", self.meta.sha256sum, checksum)))
        } else {
            Ok(())
        }
    }
}

impl Drop for ImageWriter {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(format!("{}/{}", CHUNK_DIR, self.meta.image_name));
    }
}


/// All currently active transfers of images being rebuilt from chunks.
#[derive(Serialize, Deserialize)]
pub struct Transfers {
    pub active: HashMap<String, ImageWriter>,
    pub image_sizes: HashMap<String, u64>,
    pub images_dir: String,
    pub timeout: Duration,
}

impl Transfers {
    pub fn new(images_dir: String, timeout: Duration) -> Self {
        Transfers {
            active: HashMap::new(),
            image_sizes: HashMap::new(),
            images_dir: images_dir,
            timeout: timeout,
        }
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
            self.active.remove(&image_name);
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};

    use datatype::Util;


    fn new_reader(image_name: String, image_dir: String, data: &[u8]) -> ImageReader {
        fs::create_dir_all(&image_dir).expect("create dir");
        Util::write_file(&format!("{}/{}", image_dir, image_name), data).expect("write test image");
        ImageReader::new(image_name, image_dir).expect("test image")
    }

    fn fill_random_then_sha256(mut buf: &mut [u8]) -> String {
        let mut hasher = Sha256::new();
        SystemRandom::new().fill(buf).expect("fill buf");
        hasher.input(&buf);
        hasher.result_str()
    }

    #[test]
    fn reassemble_image() {
        let dir = format!("/tmp/sota-test-image-{}", Utc::now().timestamp());
        let infile = "test-image-in.dat";
        let outfile = "test-image-out.dat";
        let mut buf = [0; CHUNK_SIZE+1];
        let size = (CHUNK_SIZE+1) as u64;
        let sha256 = fill_random_then_sha256(&mut buf);

        let mut reader = new_reader(infile.into(), dir.clone(), &buf);
        assert_eq!(reader.image_size, size);
        assert_eq!(reader.num_chunks, 2);
        assert_eq!(reader.sha256sum().expect("sha256sum"), sha256);

        let meta = ImageMeta::new(outfile.into(), size, reader.num_chunks, sha256.into());
        let mut writer = ImageWriter::new(meta, dir.clone());
        for index in 0..reader.num_chunks {
            let chunk = reader.read_chunk(index).expect("read chunk");
            writer.write_chunk(&chunk, index).expect("write chunk");
        }

        writer.assemble_chunks().expect("assemble");
        let written = Util::read_file(&format!("{}/{}", dir, outfile)).expect("written");
        assert_eq!(&written[..], &buf[..]);
    }
}
