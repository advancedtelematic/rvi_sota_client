use base64;
use hex::FromHex;
use serde_json as json;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::Path;
use std::process::{Command, Output};
use std::str;
use tar::Archive;

use datatype::{EcuCustom, EcuVersion, Error, InstallCode, InstallOutcome, TufImage,
               TufMeta, Url, Util};
use http::{Client, Response};
use pacman::Credentials;


const NEW_PACKAGE: &'static str = "/tmp/sota-package";
const BOOT_BRANCH: &'static str = "/usr/share/sota/branchname";
const REMOTE_PATH: &'static str = "/etc/ostree/remotes.d/sota-remote.conf";


/// Empty container for static `OSTree` functions.
pub struct Ostree;

impl Ostree {
    fn run<S: AsRef<OsStr> + Debug>(args: &[S]) -> Result<Output, Error> {
        debug!("running `ostree` command with args: {:?}", args);
        Command::new("ostree")
            .args(args)
            .env("OSTREE_REPO", "/sysroot/ostree/repo")
            .env("OSTREE_BOOT_PARTITION", "/boot")
            .output()
            .map_err(|err| Error::OSTree(err.to_string()))
            .and_then(|output| {
                if output.status.success() {
                    Ok(output)
                } else {
                    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                    Err(Error::OSTree(format!("stdout: {}\nstderr: {}", stdout, stderr)))
                }
            })
    }

    fn hash(commit: &str) -> Result<String, Error> {
        let data = Vec::from_hex(commit)?;
        Ok(base64::encode(&data).replace('/', "_").trim_right_matches('=').into())
    }
}


/// Details of a remote `OSTree` package.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
#[allow(non_snake_case)]
pub struct OstreePackage {
    #[serde(default)]
    pub ecu_serial:  String,
    pub refName:     String,
    pub commit:      String,
    pub description: String,
    pub pullUri:     String,
}

impl OstreePackage {
    pub fn new(ecu_serial: String, refname: String, commit: String, desc: String, treehub: &Url) -> Self {
        OstreePackage {
            ecu_serial:  ecu_serial,
            refName:     refname,
            commit:      commit,
            description: desc,
            pullUri:     format!("{}", treehub),
        }
    }

    /// Convert the current `OstreePackage` into an `EcuVersion`.
    pub fn into_version(self, custom: Option<EcuCustom>) -> EcuVersion {
        let mut hashes = HashMap::new();
        hashes.insert("sha256".to_string(), self.commit);

        EcuVersion {
            attacks_detected: "".to_string(),
            custom: custom,
            ecu_serial: self.ecu_serial,
            installed_image: TufImage {
                filepath: self.refName,
                fileinfo: TufMeta {
                    length: 0,
                    hashes: hashes,
                    custom: None
                }
            },
            previous_timeserver_time: "1970-01-01T00:00:00Z".to_string(),
            timeserver_time: "1970-01-01T00:00:00Z".to_string(),
        }
    }

    /// Install this package using the `ostree` command.
    pub fn install(&self, creds: &Credentials) -> Result<InstallOutcome, Error> {
        debug!("installing ostree commit {}", self.commit);
        let from = Self::get_latest(&self.ecu_serial)?;
        if from.commit == self.commit {
            return Ok(InstallOutcome::new(InstallCode::ALREADY_PROCESSED, "".into(), "".into()));
        }
        self.get_delta(creds.client, &self.pullUri, &from.commit)
            .and_then(|dir| Ostree::run(&["static-delta", "apply-offline", &dir]))
            .or_else(|_| self.pull_commit("sota-remote", creds))
            .map(|_| ())?;

        let output = Ostree::run(&["admin", "deploy", "--karg-proc-cmdline", &self.commit])?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if output.status.success() {
            Util::write_file(NEW_PACKAGE, &json::to_vec(self)?).unwrap_or_else(|err| error!("couldn't save package info: {}", err));
            Ok(InstallOutcome::new(InstallCode::OK, stdout, stderr))
        } else {
            Ok(InstallOutcome::new(InstallCode::INSTALL_FAILED, stdout, stderr))
        }
    }

    /// Get the latest OSTree package (including any new updates pending a reboot).
    pub fn get_latest(serial: &str) -> Result<OstreePackage, Error> {
        if Path::new(NEW_PACKAGE).exists() {
            trace!("getting ostree package from `{}`", NEW_PACKAGE);
            Ok(json::from_reader(BufReader::new(File::open(NEW_PACKAGE)?))?)
        } else if Path::new(BOOT_BRANCH).exists() {
            trace!("getting ostree branch from `{}`", BOOT_BRANCH);
            Ok(Self::get_current(serial, str::from_utf8(&Util::read_file(BOOT_BRANCH)?)?)?)
        } else {
            trace!("unknown ostree branch");
            Ok(Self::get_current(serial, "<unknown>")?)
        }
    }

    /// Get the current OSTree package with `ostree admin status`.
    pub fn get_current(serial: &str, branch: &str) -> Result<OstreePackage, Error> {
        Ostree::run(&["admin", "status"])
            .and_then(|output| OstreeBranch::parse(serial, branch, str::from_utf8(&output.stdout)?))
            .and_then(|branches| {
                branches.into_iter()
                    .filter(|branch| branch.current)
                    .map(|branch| branch.package)
                    .nth(0)
                    .ok_or_else(|| Error::OSTree("current branch unknown".to_string()))
            })
    }

    /// Extract a static delta between two commits (if it exists) and return the path.
    pub fn get_delta(&self, client: &Client, server: &str, current_commit: &str) -> Result<String, Error> {
        debug!("getting a static delta from {}", current_commit);
        let (current, next)  = (Ostree::hash(current_commit)?, Ostree::hash(&self.commit)?);
        let (prefix, suffix) = current.split_at(2);
        let url  = format!("{}/deltas/{}/{}-{}/apply-offline.tar", server, prefix, suffix, next);
        let data = match client.get(url.parse()?, None).recv().expect("get_delta") {
            Response::Success(data) => Ok(data),
            Response::Failed(data)  => Err(data.into()),
            Response::Error(err)    => Err(err)
        }?;

        let tar = format!("/tmp/sota-delta-{}-{}.tar", current_commit, self.commit);
        let mut file = File::create(&tar)?;
        let _ = io::copy(&mut &*data.body, &mut file)?;
        Archive::new(File::open(&tar)?).unpack("/tmp/sota-delta")?;
        Ok(format!("/tmp/sota-delta/{}/{}-{}", prefix, suffix, next))
    }

    /// Pull a commit from a remote repository with `ostree pull`.
    pub fn pull_commit(&self, remote: &str, creds: &Credentials) -> Result<Output, Error> {
        debug!("pulling from ostree remote: {}", remote);
        if ! Path::new(REMOTE_PATH).exists() {
            let output = Ostree::run(&["remote", "list"])?;
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            if stdout.contains(remote) {
                debug!("`ostree remote list`'s stdout, '{}', contains '{}'", stdout, remote);
            } else {
                let _ = self.add_remote(remote, creds)?;
            }
        }

        let mut args = vec!["pull".into(), remote.into()];
        if let Some(token) = creds.token {
            args.push(format!("--http-header='Authorization=Bearer {}'", token));
        }
        args.push(self.commit.clone());
        Ostree::run(&args)
    }

    /// Add a remote repository with `ostree remote add`.
    pub fn add_remote(&self, remote: &str, creds: &Credentials) -> Result<Output, Error> {
        debug!("adding ostree remote: {}", remote);
        if Path::new(REMOTE_PATH).exists() {
            fs::remove_file(REMOTE_PATH)?;
        }

        let mut args = vec!["remote".into(), "add".into(), "--no-gpg-verify".into()];
        if let Some(ca) = creds.ca_file {
            args.push(format!("--set=tls-ca-path={}", ca));
        }
        if let Some(pkey) = creds.pkey_file {
            args.push(format!("--set=tls-client-cert-path={}", pkey));
            args.push(format!("--set=tls-client-key-path={}", pkey));
        }
        args.push(remote.into());
        args.push(self.pullUri.clone());
        Ostree::run(&args)
    }
}


#[derive(Debug)]
struct OstreeBranch {
    current: bool,
    os_name: String,
    package: OstreePackage,
}

impl OstreeBranch {
    /// Parse the output from `ostree admin status`
    fn parse(ecu_serial: &str, branch_name: &str, stdout: &str) -> Result<Vec<OstreeBranch>, Error> {
        stdout.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|branch| {
                let first  = branch[0].split(' ').collect::<Vec<_>>();
                let second = branch[1].split(' ').collect::<Vec<_>>();

                let (current, os_name, commit_name) = match first.len() {
                    2 => (false, first[0], first[1]),
                    3 if first[0].trim() == "*" => (true, first[1], first[2]),
                    _ => return Err(Error::Parse(format!("couldn't parse branch: {:?}", first)))
                };
                let commit = commit_name.split('.').collect::<Vec<_>>()[0];
                let desc = match second.len() {
                    3 if second[0].trim() == "origin" && second[1].trim() == "refspec:" => second[2],
                    _ => return Err(Error::Parse(format!("couldn't parse branch: {:?}", second)))
                };

                Ok(OstreeBranch {
                    current: current,
                    os_name: os_name.into(),
                    package: OstreePackage {
                        ecu_serial:  ecu_serial.into(),
                        refName:     format!("{}-{}", branch_name, commit),
                        commit:      commit.into(),
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
        "#;

    #[test]
    fn test_parse_branches() {
        let branches = OstreeBranch::parse("test-serial".into(), "<branch>", OSTREE_ADMIN_STATUS).expect("couldn't parse branches");
        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0].current, false);
        assert_eq!(branches[0].os_name, "gnome-ostree");
        assert_eq!(branches[0].package.commit, "67e382b11d213a402a5313e61cbc69dfd5ab93cb07");
        assert_eq!(branches[0].package.refName, "<branch>-67e382b11d213a402a5313e61cbc69dfd5ab93cb07");
        assert_eq!(branches[0].package.description, "gnome-ostree/buildmaster/x86_64-runtime");
        assert_eq!(branches[1].current, true);
        assert_eq!(branches[1].package.refName, "<branch>-ce19c41036cc45e49b0cecf6b157523c2105c4de1c");
    }
}
