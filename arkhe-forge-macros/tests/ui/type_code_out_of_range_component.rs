use arkhe_forge_core::ArkheComponent;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0001_0001, schema_version = 1)]
pub struct OutOfRangeComponent {
    pub schema_version: u16,
    pub value: u32,
}

fn main() {}
