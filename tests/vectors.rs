extern crate chan;
extern crate hyper;
extern crate sota;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json as json;
extern crate url;

use chan::Sender;
use hyper::status::StatusCode;
use sota::datatype::config::UptaneConfig;
use sota::datatype::network::Url;
use sota::datatype::signature::SignatureType;
use sota::datatype::tuf::{RoleName, PrivateKey};
use sota::http::{http_client, Request, Response, ResponseData};
use sota::uptane::{Uptane, Verifier, Service};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn load_vector_meta() -> String {
    let mut file = File::open("./tests/vectors/vector-meta.json")
        .expect("couldn't open vector meta");
    let mut buf = String::new();
    file.read_to_string(&mut buf).expect("couldn't read vector meta");
    buf
}

struct VectorClient {
    path: PathBuf,
}

impl http_client::Client for VectorClient {
    fn chan_request(&self, req: Request, resp_tx: Sender<Response>) {
        let mut path = self.path.clone();

        for s in req.url.path_segments().expect("bad url") {
            path = path.join(s);
        }

        let mut buf = Vec::new();
        let mut file = File::open(path).expect("could not open file");
        file.read_to_end(&mut buf).expect("could not read file");

        let data = ResponseData {
            code: StatusCode::Ok,
            body: buf,
        };
        resp_tx.send(Response::Success(data))
    }
}

#[derive(Deserialize)]
struct VectorMeta {
    repo: String,
    error: Option<String>,
}

fn run_test_vector(test_path: &str) {
    let vectors: Vec<VectorMeta> = json::from_str(&load_vector_meta()).expect("couldn't deserialize meta");

    let test_vector = vectors.iter()
        .filter(|v| v.repo == test_path)
        .collect::<Vec<&VectorMeta>>()
        .pop()
        .expect(format!("No repo named {}", test_path).as_str());

    let vector_path = format!("./tests/vectors/{}/repo", test_vector.repo);

    let mut config = UptaneConfig::default();
    config.metadata_path = vector_path.clone();
    config.director_server = Url(url::Url::parse("file://director/repo").unwrap());
    config.repo_server = Url(url::Url::parse("file://repo/repo").unwrap());

    let mut uptane = Uptane {
        director_server:  "http://localhost:8001".parse().unwrap(),
        repo_server:      "http://localhost:8002".parse().unwrap(),
        metadata_path:    "tests/uptane".into(),
        persist_metadata: false,

        primary_ecu: "test-primary-serial".into(),
        private_key: PrivateKey {
            keyid: "".to_string(),
            der_key: Vec::new(),

        },
        sig_type: SignatureType::Ed25519,

        director_verifier: Verifier::default(),
        repo_verifier:     Verifier::default(),
    };

    let client = VectorClient {
        path: PathBuf::from(vector_path),
    };

    // TODO this should be replaced by the generic update() function
    let res = uptane.get_director(&client, RoleName::Root);

    match (res, &test_vector.error) {
        (Ok(_), &None) => {
            panic!("TODO");
        },
        (Err(e), &None) => {
            panic!("Unexpected failure: {:?}", e)
        },
        _ => panic!("bad times"),
    }
}

#[ignore]
fn vector_001() { run_test_vector("001") }
