use super::UpdateId;

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct InstalledFirmware {
    pub module: String,
    pub firmware_id: String,
    pub last_modified: u64
}

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct InstalledFirmwares(pub Vec<InstalledFirmware>);

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct InstalledPackage {
    pub package_id: String,
    pub name: String,
    pub description: String,
    pub last_modified: u64
}

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct InstalledPackages(pub Vec<InstalledPackage>);

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct InstalledSoftware {
    pub packages: Vec<InstalledPackage>,
    pub firmware: Vec<InstalledFirmware>
}

impl InstalledSoftware {
    pub fn new(p: InstalledPackages, f: InstalledFirmwares) -> InstalledSoftware {
        InstalledSoftware {
            packages: p.0,
            firmware: f.0
        }
    }
}

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct OperationResult {
    pub id: String,
    pub result_code: u32,
    pub result_text: String
}

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct OperationResults(pub Vec<OperationResult>);

#[derive(RustcDecodable, RustcEncodable, Clone)]
pub struct UpdateReport {
    pub update_id: String,
    pub operation_results: Vec<OperationResult>
}

impl UpdateReport {
    pub fn new(id: String, res: OperationResults) -> UpdateReport {
        UpdateReport {
            update_id: id,
            operation_results: res.0
        }
    }
}

#[derive(RustcEncodable, Clone)]
pub struct UpdateResult {
    pub vin: String,
    pub update_report: UpdateReport
}

pub enum OutBoundEvent {
    InitiateDownload(UpdateId),
    AbortDownload(UpdateId),
    UpdateReport(UpdateReport)
}
