use arkhe_forge_core::ArkheAction;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0001, schema_version = 1, band = 4)]
pub struct InvalidBand {
    pub schema_version: u16,
    pub payload: u32,
}

fn main() {}
