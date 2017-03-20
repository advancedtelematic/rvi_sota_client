use serde_json as json;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;
use std::str;

use datatype::{EcuCustom, EcuVersion, Error, TufImage, TufMeta, UpdateResultCode as Code, Url};
use package_manager::{Credentials, InstallOutcome};
use uptane::{read_file, write_file};


const NEW_PACKAGE: &'static str = "/tmp/sota-package";
const BOOT_BRANCH: &'static str = "/usr/share/sota/branchname";


/// Details of a remote OSTree package.
#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
#[allow(non_snake_case)]
pub struct OstreePackage {
    pub refName:     String,
    pub commit:      String,
    pub description: String,
    pub pullUri:     String,
}

impl OstreePackage {
    pub fn new(refname: String, commit: String, desc: String, treehub: &Url) -> Self {
        OstreePackage {
            refName:     refname,
            commit:      commit,
            description: desc,
            pullUri:     format!("{}", treehub),
        }
    }

    /// Shell out to the ostree command to install this package.
    pub fn install(&self, creds: &Credentials) -> Result<InstallOutcome, Error> {
        debug!("installing ostree package: {:?}", self);

        let mut cmd = Command::new("sota_ostree.sh");
        cmd.env("COMMIT", self.commit.clone());
        cmd.env("REF_NAME", self.refName.clone());
        cmd.env("DESCRIPTION", self.description.clone());
        cmd.env("PULL_URI", self.pullUri.clone());
        creds.access_token.as_ref().map(|t| cmd.env("AUTHPLUS_ACCESS_TOKEN", t.clone()));
        creds.ca_file.as_ref().map(|f| cmd.env("TLS_CA_CERT", f.clone()));
        creds.cert_file.as_ref().map(|f| cmd.env("TLS_CLIENT_CERT", f.clone()));
        creds.pkey_file.as_ref().map(|f| cmd.env("TLS_CLIENT_KEY", f.clone()));

        let output = cmd.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        match output.status.code() {
            Some(0) => {
                write_file(NEW_PACKAGE, &json::to_vec(self)?)?;
                Ok((Code::OK, stdout))
            }
            Some(99) => Ok((Code::ALREADY_PROCESSED, stdout)),
            _        => Ok((Code::INSTALL_FAILED, format!("stdout: {}\nstderr: {}", stdout, stderr)))
        }
    }

    /// Consume the current OstreePackage and return an EcuVersion.
    pub fn ecu_version(&self, ecu_serial: String, custom: Option<EcuCustom>) -> EcuVersion {
        let mut hashes = HashMap::new();
        hashes.insert("sha256".to_string(), self.commit.clone());

        EcuVersion {
            attacks_detected: "".to_string(),
            ecu_serial: ecu_serial,
            installed_image: TufImage {
                filepath: self.refName.clone(),
                fileinfo: TufMeta {
                    length: 0,
                    hashes: hashes,
                    custom: None
                }
            },
            previous_timeserver_time: "1970-01-01T00:00:00Z".to_string(),
            timeserver_time: "1970-01-01T00:00:00Z".to_string(),
            custom: custom
        }
    }

    /// Get the current OSTree package based on the last successful installation
    /// if it exists, or from running `ostree admin status` otherwise.
    pub fn get_current() -> Result<Self, Error> {
        let branch = if Path::new(NEW_PACKAGE).exists() {
            debug!("getting ostree package from `{}`", NEW_PACKAGE);
            return Ok(json::from_reader(BufReader::new(File::open(NEW_PACKAGE)?))?);
        } else if Path::new(BOOT_BRANCH).exists() {
            debug!("getting ostree branch from `{}`", BOOT_BRANCH);
            String::from_utf8(read_file(BOOT_BRANCH)?).unwrap_or("[error]".into())
        } else {
            debug!("unknown ostree branch");
            "[error]".into()
        };

        debug!("getting ostree branch with `ostree admin status`");
        Command::new("ostree").arg("admin").arg("status").output()
            .map_err(|err| Error::Command(format!("couldn't run `ostree admin status`: {}", err)))
            .and_then(|output| OstreeBranch::parse(&branch, str::from_utf8(&output.stdout)?))
            .and_then(|branches| {
                branches.into_iter()
                    .filter_map(|branch| if branch.current { Some(branch.package) } else { None })
                    .nth(0)
                    .ok_or_else(|| Error::Command("current branch unknown".to_string()))
            })
    }
}


struct OstreeBranch {
    current: bool,
    package: OstreePackage,
}

impl OstreeBranch {
    /// Parse the output from `ostree admin status`
    fn parse(branch_name: &str, stdout: &str) -> Result<Vec<OstreeBranch>, Error> {
        stdout.lines()
            .map(str::trim)
            .filter(|line| line.len() > 0)
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|branch| {
                let first  = branch[0].split(" ").collect::<Vec<_>>();
                let second = branch[1].split(" ").collect::<Vec<_>>();

                let (current, desc, commit) = match first.len() {
                    2 => (false, first[0], first[1]),
                    3 if first[0].trim() == "*" => (true, first[1], first[2]),
                    _ => return Err(Error::Parse(format!("couldn't parse branch: {:?}", first)))
                };
                let refspec = match second.len() {
                    3 if second[0].trim() == "origin" && second[1].trim() == "refspec:" => second[2],
                    _ => return Err(Error::Parse(format!("couldn't parse branch: {:?}", second)))
                }.split(":").last().expect("couldn't split refname");

                Ok(OstreeBranch {
                    current: current,
                    package: OstreePackage {
                        refName:     format!("{}-{}", branch_name, refspec),
                        commit:      commit.split(".").collect::<Vec<_>>()[0].into(),
                        description: desc.into(),
                        pullUri:     "".into(),
                    },
                })
            })
            .collect()
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    const OSTREE_ADMIN_STATUS: &'static str = r#"
          gnome-ostree 67e382b11d213a402a5313e61cbc69dfd5ab93cb07.0
            origin refspec: gnome-ostree/buildmaster/x86_64-runtime
        * gnome-ostree ce19c41036cc45e49b0cecf6b157523c2105c4de1c.0
            origin refspec: osname:gnome-ostree/buildmaster/x86_64-runtime
          gnome-ostree ce19c41036cc45e49b0cecf6b157523c2105c4de1c.0
            origin refspec: one:two:three
        "#;

    #[test]
    fn test_parse_branches() {
        let branches = OstreeBranch::parse("test", OSTREE_ADMIN_STATUS)
            .unwrap_or_else(|err| panic!("couldn't parse branches: {}", err));
        assert_eq!(branches.len(), 3);
        assert_eq!(branches[0].current, false);
        assert_eq!(branches[0].package.refName, "test-gnome-ostree/buildmaster/x86_64-runtime");
        assert_eq!(branches[0].package.description, "gnome-ostree");
        assert_eq!(branches[0].package.commit, "67e382b11d213a402a5313e61cbc69dfd5ab93cb07");
        assert_eq!(branches[1].current, true);
        assert_eq!(branches[1].package.refName,"test-gnome-ostree/buildmaster/x86_64-runtime");
        assert_eq!(branches[2].current, false);
        assert_eq!(branches[2].package.refName,"test-three");
    }
}
