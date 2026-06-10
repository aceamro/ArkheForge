//! Forge L1 Action + Event for the 3D6 provably-fair dice roll.
//!
//! `RecordDiceRoll` is the canonical Action submitted to
//! `arkhe_forge_platform::RuntimeService::dispatch`; on successful
//! compute it emits `DiceRollLanded` whose `chain_hash` anchors the
//! `(dice, user_input)` pair. The chain anchor is independent of the
//! kernel's L0 WAL chain (which already runs at the WAL-record layer)
//! — pattern parallel to `card_primitives::shuffle_proof::ShowdownReceipt`.
//!
//! ## Provably-fair binding
//!
//! 1. **Server commit**  `commitment_server = BLAKE3(DOMAIN_DICE_COMMIT || server_seed)`.
//! 2. **User input**     raw UTF-8 bytes (`user_input.as_bytes()`).
//! 3. **Combined PRF**   `combined_seed = BLAKE3(DOMAIN_DICE_COMBINED || server_seed || user_input.as_bytes() || nonce.to_le_bytes())`.
//! 4. **Roll**           `RngSource::from_seed(&combined_seed)` → 3× `gen_range_inclusive(rng, 1u32..=6)`.
//! 5. **Anchor**         `chain_hash = BLAKE3(DOMAIN_DICE_CHAIN || dice || user_input.as_bytes())`.
//!
//! The compute body re-derives every byte from the recorded inputs so
//! audience-side replay produces a byte-identical event payload. The
//! `nonce.to_le_bytes()` byte order is deliberate (wire-stable LE,
//! kernel WAL precedent) — replay determinism would break under a
//! native-endian conversion.

use serde::{Deserialize, Serialize};

use arkhe_forge_core::action::{ActionCompute, ArkheAction as _};
use arkhe_forge_core::context::{ensure_schema_version, ActionContext, ActionError};
use arkhe_forge_core::{arkhe_pure, ArkheAction, ArkheEvent};

/// Domain tag for the server-side commitment hash. Mirrors the
/// `arkhe-forge::<protocol>::v1::<purpose>::` shape used by
/// `card_primitives::shuffle_proof::DOMAIN_SHOWDOWN`.
pub const DOMAIN_DICE_COMMIT: &[u8] = b"arkhe-forge::dice::v1::commit::";

/// Domain tag for the combined-seed PRF input. Distinct from
/// `DOMAIN_DICE_COMMIT` so a substitution attack cannot reuse a commit
/// hash as a combined-seed and vice versa (cross-protocol substitution
/// defence by domain separation).
pub const DOMAIN_DICE_COMBINED: &[u8] = b"arkhe-forge::dice::v1::combined::";

/// Domain tag for the per-roll chain-hash anchor written into the
/// emitted `DiceRollLanded` event.
pub const DOMAIN_DICE_CHAIN: &[u8] = b"arkhe-forge::dice::v1::chain::";

/// L1 Action — record a single 3D6 dice roll into the WAL.
///
/// All input bytes are recorded verbatim so a replay re-derives the
/// commitment, the combined seed, and the dice values. The audience
/// only needs the `(commitment_server, server_seed, user_input, nonce,
/// combined_seed, dice)` tuple to verify both bindings.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0200_0001, schema_version = 2, band = 1)]
pub struct RecordDiceRoll {
    /// Wire schema version. Must match the derive-macro literal —
    /// `compute()` rejects mismatches via `ActionError::SchemaMismatch`
    /// as its first check, before any provably-fair binding is verified.
    pub schema_version: u16,
    /// 32-byte BLAKE3 commitment broadcast pre-roll: hash of
    /// `DOMAIN_DICE_COMMIT || server_seed`. Audience verifies the
    /// server did not equivocate by recomputing this from the revealed
    /// `server_seed`.
    pub commitment_server: [u8; 32],
    /// Server-side seed revealed post-commit. 32 OS-entropy bytes from
    /// `getrandom` (no derived intermediate). Recorded plaintext in WAL
    /// — by design for the reveal phase of commit-reveal protocols.
    pub server_seed: [u8; 32],
    /// User-supplied input string (UTF-8 verbatim, no normalisation).
    /// Bound to ≤256 bytes by `read_user_seed` upstream so postcard
    /// payload size stays predictable.
    pub user_input: String,
    /// Caller-side monotonic counter (set to `history.len() as u64` at
    /// dispatch time). Replay-deterministic because reconstruction
    /// re-dispatches in stored order and the history len at step N
    /// matches the original run's nonce N.
    pub nonce: u64,
    /// 32-byte combined PRF output:
    /// `BLAKE3(DOMAIN_DICE_COMBINED || server_seed || user_input.as_bytes() || nonce.to_le_bytes())`.
    /// The compute body recomputes this and rejects a mismatch — the
    /// caller cannot lie about `combined_seed` because every input
    /// component is recorded.
    pub combined_seed: [u8; 32],
    /// Three dice faces, each `1..=6`. Caller-supplied; the compute
    /// body re-rolls from `combined_seed` and rejects a mismatch.
    pub dice: [u8; 3],
}

/// L1 Event — emitted by `RecordDiceRoll::compute` on success. The
/// `chain_hash` field binds `(dice, user_input)` so the audience-side
/// log consumer can reconstruct the per-roll anchor without re-running
/// `compute()`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 0x0200_0002, schema_version = 2)]
pub struct DiceRollLanded {
    /// Wire schema version.
    pub schema_version: u16,
    /// 32-byte BLAKE3 chain anchor:
    /// `BLAKE3(DOMAIN_DICE_CHAIN || dice || user_input.as_bytes())`.
    pub chain_hash: [u8; 32],
    /// Echo of the user's input string — display layer reads this
    /// field rather than the Action input (event-driven UI).
    pub user_input: String,
    /// Echo of the rolled dice.
    pub dice: [u8; 3],
    /// Tick the kernel scheduled for the executing step (kernel-canonical
    /// metadata; preserved for `--verify` paths even though the display
    /// uses a sequence number instead).
    pub tick: u64,
}

impl ActionCompute for RecordDiceRoll {
    #[arkhe_pure]
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        // Stage 0 — wire schema gate. Fires before any provably-fair
        // binding check so a stale wire shape never reaches Stage 1.
        ensure_schema_version(Self::SCHEMA_VERSION, self.schema_version)?;

        // Stage 1 — server commitment binding.
        // BLAKE3 generic mode (`Hasher::new`) is correct here: the
        // commitment is a public binding, not key-derivation material;
        // `Hasher::new_derive_key` would change the PRF mode without
        // adding security and would diverge from the
        // `card_primitives::shuffle_proof` precedent.
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_DICE_COMMIT);
        h.update(&self.server_seed);
        if h.finalize().as_bytes() != &self.commitment_server {
            return Err(ActionError::InvalidInput("server commitment mismatch"));
        }

        // Stage 2 — combined-seed PRF re-derivation.
        // Order: domain || server_seed || user_input.as_bytes() || nonce.to_le_bytes()
        // — replay determinism depends on this order. The wire byte
        // order is little-endian to keep the stream stable across
        // host endianness, matching the kernel WAL convention.
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_DICE_COMBINED);
        h.update(&self.server_seed);
        h.update(self.user_input.as_bytes());
        h.update(&self.nonce.to_le_bytes());
        if h.finalize().as_bytes() != &self.combined_seed {
            return Err(ActionError::InvalidInput("combined seed mismatch"));
        }

        // Stage 3 — dice replay.
        // 3× sequential calls — replay determinism depends on call
        // order (die 1, die 2, die 3). `gen_range_inclusive` is
        // Lemire-unbiased.
        let mut rng = arkhe_rand::RngSource::from_seed(&self.combined_seed);
        let d1 = arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8;
        let d2 = arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8;
        let d3 = arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8;
        if [d1, d2, d3] != self.dice {
            return Err(ActionError::InvalidInput("dice mismatch"));
        }

        // Stage 4 — chain anchor.
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_DICE_CHAIN);
        h.update(&self.dice);
        h.update(self.user_input.as_bytes());
        let chain_hash = *h.finalize().as_bytes();

        // Stage 5 — emit event.
        ctx.emit_event(&DiceRollLanded {
            schema_version: 2,
            chain_hash,
            user_input: self.user_input.clone(),
            dice: self.dice,
            tick: ctx.tick().0,
        })?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use arkhe_kernel::abi::{CapabilityMask, InstanceId, Principal, Tick};

    fn test_ctx() -> ActionContext<'static> {
        ActionContext::new(
            [0u8; 32],
            InstanceId::new(1).unwrap(),
            Tick(7),
            Principal::System,
            CapabilityMask::SYSTEM,
        )
    }

    /// Re-derive a fully valid roll from a fixed server seed so the only
    /// variable under test is the wire `schema_version`.
    fn valid_roll() -> RecordDiceRoll {
        let server_seed = [0x42u8; 32];
        let user_input = "lucky".to_owned();
        let nonce = 3u64;

        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_DICE_COMMIT);
        h.update(&server_seed);
        let commitment_server = *h.finalize().as_bytes();

        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_DICE_COMBINED);
        h.update(&server_seed);
        h.update(user_input.as_bytes());
        h.update(&nonce.to_le_bytes());
        let combined_seed = *h.finalize().as_bytes();

        let mut rng = arkhe_rand::RngSource::from_seed(&combined_seed);
        let dice = [
            arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
            arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
            arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
        ];

        RecordDiceRoll {
            schema_version: 2,
            commitment_server,
            server_seed,
            user_input,
            nonce,
            combined_seed,
            dice,
        }
    }

    #[test]
    fn compute_accepts_matching_schema_version() {
        let mut c = test_ctx();
        valid_roll().compute(&mut c).expect("valid roll → Ok");
        assert_eq!(c.events().len(), 1, "one DiceRollLanded emitted");
    }

    #[test]
    fn compute_rejects_wire_schema_mismatch_before_bindings() {
        let mut roll = valid_roll();
        roll.schema_version = 0xBEEF;
        // Corrupt the commitment too: the schema gate must fire FIRST, so
        // the error is SchemaMismatch, not the Stage 1 commitment rejection.
        roll.commitment_server = [0u8; 32];
        let mut c = test_ctx();
        let err = roll
            .compute(&mut c)
            .expect_err("wire schema mismatch must reject");
        assert!(
            matches!(
                err,
                ActionError::SchemaMismatch {
                    expected: 2,
                    got: 0xBEEF,
                }
            ),
            "got {err:?}",
        );
        assert!(c.events().is_empty(), "no event on rejection");
    }
}
