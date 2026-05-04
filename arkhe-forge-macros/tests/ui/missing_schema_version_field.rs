use arkhe_forge_core::ArkheComponent;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0001, schema_version = 1)]
pub struct MissingSchemaVersionField {
    pub created_tick: u64,
}

fn main() {}
