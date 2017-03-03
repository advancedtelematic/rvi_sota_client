use std::collections::HashMap;
use std::process::Command;

use datatype::{AccessToken, Error, Package, SignedImage, SignedMeta, SignedVersion,
               UpdateResultCode as Code};
use package_manager::package_manager::{InstallOutcome, parse_package};


/// Details of an OSTree branch.
#[derive(RustcDecodable, Debug)]
#[allow(non_snake_case)]
pub struct OstreeBranch {
    pub current:     bool,
    pub refName:     String,
    pub commit:      String,
    pub description: String
}

impl OstreeBranch {
    pub fn signed_version(self, ecu_serial: String) -> SignedVersion {
        let mut hashes = HashMap::new();
        hashes.insert("sha256".to_string(), self.commit);

        SignedVersion {
            timeserver_time: "1970-01-01T00:00:00Z".to_string(),
            installed_image: SignedImage {
                filepath: self.refName,
                fileinfo: SignedMeta {
                    length: 0,
                    hashes: hashes,
                    custom: None
                }
            },
            previous_timeserver_time: "1970-01-01T00:00:00Z".to_string(),
            ecu_serial: ecu_serial,
            attacks_detected: "".to_string()
        }

    }
}


/// Details of a remote OSTree package.
#[derive(RustcDecodable, RustcEncodable, PartialEq, Eq, Debug, Clone)]
#[allow(non_snake_case)]
pub struct OstreePackage {
    pub commit:      String,
    pub refName:     String,
    pub description: String,
    pub pullUri:     String
}

impl Default for OstreePackage {
    fn default() -> Self {
        OstreePackage {
            commit:      "".to_string(),
            refName:     "".to_string(),
            description: "".to_string(),
            pullUri:     "".to_string()
        }
    }
}

impl OstreePackage {
    /// Shell out to the ostree command to install this package.
    pub fn install(self, token: Option<&AccessToken>) -> Result<InstallOutcome, InstallOutcome> {
        debug!("installing ostree package: {:?}", self);

        let mut command = Command::new("sota_ostree.sh");
        command
            .env("COMMIT",      self.commit)
            .env("REF_NAME",    self.refName)
            .env("DESCRIPTION", self.description)
            .env("PULL_URI",    self.pullUri);
        token.map(|t| command.env("AUTHPLUS_ACCESS_TOKEN", t.access_token.clone()));

        let output = command.output().map_err(|err| (Code::GENERAL_ERROR, format!("ostree install: {}", err)))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        match output.status.code() {
            Some(0)  => Ok((Code::OK, stdout)),
            Some(99) => Ok((Code::ALREADY_PROCESSED, stdout)),
            _ => Err((Code::INSTALL_FAILED, format!("stdout: {}\nstderr: {}", stdout, stderr)))
        }
    }
}


/// Static functions for working with OSTree data.
pub struct Ostree;

impl Ostree {
    /// Return a list of installed ostree packages from `/usr/package.manifest`.
    pub fn get_installed() -> Result<Vec<Package>, Error> {
        Command::new("cat")
            .arg("/usr/package.manifest")
            .output()
            .map_err(|err| Error::Package(format!("Error fetching packages: {}", err)))
            .and_then(|c| {
                String::from_utf8(c.stdout)
                    .map_err(|err| Error::Parse(format!("Error parsing package: {}", err)))
                    .map(|s| s.lines().map(String::from).collect::<Vec<String>>())
            })
            .and_then(|lines| {
                lines.iter()
                    .map(|line| parse_package(line))
                    .filter(|pkg| pkg.is_ok())
                    .collect::<Result<Vec<Package>, _>>()
            })
    }

    /// Get the current OSTree branch.
    pub fn get_current_branch() -> Result<OstreeBranch, Error> {
        for branch in Self::get_branches()? {
            if branch.current {
                return Ok(branch);
            }
        }
        Err(Error::OstreeCommand("no current branch".to_string()))
    }

    /// Run `ostree admin status` to get a list of branches.
    pub fn get_branches() -> Result<Vec<OstreeBranch>, Error> {
        debug!("getting ostree branches with `ostree admin status`");
        let output = Command::new("ostree").arg("admin").arg("status").output()?;
        let stdout = String::from_utf8(output.stdout)?;
        Self::parse_branches(&stdout)
    }

    fn parse_branches(stdout: &str) -> Result<Vec<OstreeBranch>, Error> {
        stdout.lines()
            .map(str::trim)
            .filter(|line| line.len() > 0)
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|branch| {
                let first  = branch[0].split(" ").collect::<Vec<_>>();
                let second = branch[1].split(" ").collect::<Vec<_>>();

                let (current, refname, commit) = match first.len() {
                    2 => (false, first[0], first[1]),
                    3 if first[0].trim() == "*" => (true, first[1], first[2]),
                    _ => return Err(Error::Parse(format!("couldn't parse branch: {:?}", first)))
                };
                let desc = match second.len() {
                    3 if second[0].trim() == "origin" && second[1].trim() == "refspec:" => second[2],
                    _ => return Err(Error::Parse(format!("couldn't parse branch: {:?}", second)))
                };

                Ok(OstreeBranch {
                    current:     current,
                    refName:     refname.into(),
                    commit:      commit.split(".").collect::<Vec<_>>()[0].into(),
                    description: desc.into()
                })
            })
            .collect()
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    const OSTREE_ADMIN_STATUS: &'static str = r#"
        * gnome-ostree 67e382b11d213a402a5313e61cbc69dfd5ab93cb07.0
            origin refspec: gnome-ostree/buildmaster/x86_64-runtime
          gnome-ostree ce19c41036cc45e49b0cecf6b157523c2105c4de1c.0
            origin refspec: osname:gnome-ostree/buildmaster/x86_64-runtime
        "#;

    #[test]
    fn test_parse_branches() {
        let branches = Ostree::parse_branches(OSTREE_ADMIN_STATUS)
            .unwrap_or_else(|err| panic!("couldn't parse branches: {}", err));
        assert_eq!(branches.len(), 2);

        assert_eq!(branches[0].current, true);
        assert_eq!(branches[0].refName, "gnome-ostree");
        assert_eq!(branches[0].commit, "67e382b11d213a402a5313e61cbc69dfd5ab93cb07");

        assert_eq!(branches[1].current, false);
        assert_eq!(branches[1].description,"osname:gnome-ostree/buildmaster/x86_64-runtime");
    }
}