//! Entry primitive — persistent content unit.

use arkhe_kernel::abi::{EntityId, Tick};
use serde::{Deserialize, Serialize};

use crate::actor::ActorId;
use crate::brand::ShellId;
use crate::component::BoundedString;
use crate::pii::{AeadKind, DekId};
use crate::space::SpaceId;
use crate::ArkheComponent;

/// Opaque handle into the runtime Entry namespace.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryId(EntityId);

impl EntryId {
    /// Construct an `EntryId` from a runtime-allocated `EntityId`. Callers
    /// must hold proof (spawn event, admin scope, or test fixture) that the
    /// id belongs to the Entry namespace — this constructor does not verify.
    #[inline]
    #[must_use]
    pub fn new(id: EntityId) -> Self {
        Self(id)
    }

    /// Underlying entity handle.
    #[inline]
    #[must_use]
    pub fn get(self) -> EntityId {
        self.0
    }
}

/// Relay relation kind — single-level only (E-entry-4).
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum RelayKind {
    /// Reblog / simple forward with no added content.
    Plain = 0,
    /// Quote-relay — relay plus own commentary.
    Quote = 1,
}

/// Entry core Component — exactly one per Entry (E-entry-1).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0301, schema_version = 1)]
pub struct EntryCore {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Shell identity — immutable.
    pub shell_id: ShellId,
    /// Home Space.
    pub space_id: SpaceId,
    /// Authoring actor.
    pub author_id: ActorId,
    /// Parent (reply target). Immutable after creation (E-entry-7 / P5).
    pub parent_entry: Option<EntryId>,
    /// Relay source. Immutable after creation (E-entry-7 / P5).
    pub relay_of: Option<EntryId>,
    /// Relay kind — present iff `relay_of.is_some()`.
    pub relay_kind: Option<RelayKind>,
    /// Creation tick.
    pub created_tick: Tick,
}

/// Entry body Component — content hash plus optional cipher metadata.
/// `DeleteEntry` removes this Component while preserving `EntryCore` (soft
/// delete, E-entry-5).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0302, schema_version = 1)]
pub struct EntryBody {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Optional title — bounded to 256 UTF-8 bytes.
    pub title: Option<BoundedString<256>>,
    /// `BLAKE3(body || user_salt || entry_nonce)`.
    pub body_hash: [u8; 32],
    /// Cipher metadata — present iff the body plaintext is AEAD-sealed in a
    /// shell-side channel.
    pub body_cipher_meta: Option<BodyCipherMeta>,
    /// Monotone edit counter (E-entry-6).
    pub edit_seq: u32,
}

/// Body encryption metadata — references the DEK and AEAD algorithm used.
/// Ciphertext itself lives in the shell's side-channel (outside the WAL).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BodyCipherMeta {
    /// DEK handle (HSM/KMS-managed).
    pub dek_id: DekId,
    /// AEAD algorithm family.
    pub aead_kind: AeadKind,
    /// 24-byte XChaCha20-Poly1305 nonce (or 12-byte AES-GCM nonce, zero-padded).
    pub nonce: [u8; 24],
}

/// Cached parent-chain depth (E-entry-3). 0 = root, max [`MAX_ENTRY_DEPTH`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0303, schema_version = 1)]
pub struct EntryParentDepth {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Depth value.
    pub depth: u8,
}

/// Maximum reply-chain depth (E-entry-3).
pub const MAX_ENTRY_DEPTH: u8 = 64;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::component::ArkheComponent;

    fn ent(v: u64) -> EntityId {
        EntityId::new(v).unwrap()
    }

    #[test]
    fn entry_core_serde_roundtrip_postcard() {
        let ec = EntryCore {
            schema_version: 1,
            shell_id: ShellId([0u8; 16]),
            space_id: SpaceId::new(ent(1)),
            author_id: ActorId::new(ent(2)),
            parent_entry: None,
            relay_of: None,
            relay_kind: None,
            created_tick: Tick(10),
        };
        let bytes = postcard::to_stdvec(&ec).unwrap();
        let back: EntryCore = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ec, back);
    }

    #[test]
    fn entry_body_serde_roundtrip_with_cipher_meta() {
        let body = EntryBody {
            schema_version: 1,
            title: Some(BoundedString::<256>::new("hello").unwrap()),
            body_hash: [0xABu8; 32],
            body_cipher_meta: Some(BodyCipherMeta {
                dek_id: DekId([0x11u8; 16]),
                aead_kind: AeadKind::XChaCha20Poly1305,
                nonce: [0x22u8; 24],
            }),
            edit_seq: 1,
        };
        let bytes = postcard::to_stdvec(&body).unwrap();
        let back: EntryBody = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn entry_component_type_codes() {
        assert_eq!(EntryCore::TYPE_CODE, 0x0003_0301);
        assert_eq!(EntryBody::TYPE_CODE, 0x0003_0302);
        assert_eq!(EntryParentDepth::TYPE_CODE, 0x0003_0303);
    }

    #[test]
    fn max_entry_depth_is_sixty_four() {
        assert_eq!(MAX_ENTRY_DEPTH, 64);
    }
}
