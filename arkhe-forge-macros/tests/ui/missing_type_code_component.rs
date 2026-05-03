use arkhe_forge_core::ArkheComponent;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheComponent)]
#[arkhe(schema_version = 1)]
pub struct MissingTypeCode {
    pub schema_version: u16,
}

fn main() {}
