use arkhe_forge_core::ArkheEvent;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0003_0F01, schema_version = 1)]
pub struct BadCanonicalSort {
    pub schema_version: u16,
    #[arkhe(canonical_sort)]
    pub not_a_collection: u32,
}

fn main() {}
