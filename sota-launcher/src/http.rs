use reqwest::header::{ContentType, Headers};
use reqwest::mime::{Mime, SubLevel, TopLevel};
use reqwest::Client;
use std::io::Read;
use uuid::Uuid;

use datatypes::*;


pub struct MultiTargetUpdate {
    client: Client,
    env: Environment,
    play: PlayCookie,
}

impl MultiTargetUpdate {
    pub fn new(env: Environment, play: PlayCookie) -> Result<Self> {
        Ok(MultiTargetUpdate {
            client: Client::new()?,
            env: env,
            play: play,
        })
    }

    pub fn create(&self, targets: &Targets) -> Result<Uuid> {
        let mut resp = self.client
            .post(&format!("{}/multi_target_updates", self.env))
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
            .put(&format!("{}/admin/devices/{}/multi_target_update/{}", self.env, device_id, update_id))
            .headers(self.headers())
            .send()?;

        let mut body = String::new();
        resp.read_to_string(&mut body)?;
        debug!("launch response: {}", body);
        Ok(())
    }

    fn headers(&self) -> Headers {
        let mut headers = Headers::new();
        headers.set_raw("Cookie", vec![self.play.into_bytes()]);
        headers.set_raw("Csrf-Token", vec![self.play.csrf_token.as_bytes().to_vec()]);
        headers.set(ContentType(Mime(TopLevel::Application, SubLevel::Json, vec![])));
        headers
    }
}
