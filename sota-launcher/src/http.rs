use reqwest::header::Headers;
use reqwest::Client;
use std::io::Read;
use uuid::Uuid;

use config::Config;
use datatypes::*;


pub struct MultiTargetUpdate<'c> {
    client: Client,
    config: &'c Config,
}

impl<'c> MultiTargetUpdate<'c> {
    pub fn new(config: &'c Config) -> Result<Self> {
        Ok(MultiTargetUpdate { client: Client::new()?, config: config })
    }

    pub fn create(&self, targets: &UpdateTargets) -> Result<Uuid> {
        let mut resp = self.client
            .post(&format!("{}/multi_target_updates", self.config.environment))
            .json(targets)
            .headers(self.headers())
            .send()?;

        let mut body = String::new();
        resp.read_to_string(&mut body)?;
        debug!("create mtu response: {}", body);
        let uuid = body.trim_matches('"').parse::<Uuid>()?;
        Ok(uuid)
    }

    pub fn launch(&self, device_id: Uuid, update_id: Uuid) -> Result<()> {
        let mut resp = self.client
            .put(&format!("{}/admin/devices/{}/multi_target_update/{}",
                          self.config.environment, device_id, update_id))
            .headers(self.headers())
            .send()?;

        let mut body = String::new();
        resp.read_to_string(&mut body)?;
        debug!("launch response: {}", body);
        Ok(())
    }

    fn headers(&self) -> Headers {
        let mut headers = Headers::new();
        headers.set_raw("Cookie", vec![self.config.play_session.into_bytes()]);
        headers.set_raw("Csrf-Token", vec![self.config.play_session.csrf_token.as_bytes().to_vec()]);
        headers
    }
}
