//! Shell Manifest TOML loader.
//!
//! The manifest is the single source of ground-truth shell policy: which
//! audit signature class to require, which compliance tier applies, what
//! the runtime version bound is. This module ships the loader surface:
//!
//! 1. [`ManifestSnapshot`] — typed view of a parsed manifest.
//! 2. [`ManifestLoader::load`] — parse + validate + BLAKE3 digest in one
//!    step, returning the snapshot and a canonical digest suitable for the
//!    `RuntimeBootstrap` chain anchor (E12).
//! 3. [`emit_runtime_bootstrap`] — helper that turns a loaded snapshot into
//!    an `Op::EmitEvent`-bound [`RuntimeBootstrap`] event on an
//!    [`ActionContext`].
//!
//! The canonical digest is computed as
//! `blake3::keyed_hash(derive_key("arkhe-forge-manifest-digest", &[]),
//! toml_canonical_bytes)` — domain-separated.

use arkhe_forge_core::context::{ActionContext, ActionError};
use arkhe_forge_core::event::{RuntimeBootstrap, SemVer};
use arkhe_kernel::abi::{Tick, TypeCode};
use serde::{Deserialize, Serialize};

/// 32-byte canonical digest of a [`ManifestSnapshot`] (anchor C5).
pub type ManifestDigest = [u8; 32];

/// BLAKE3 domain separator for canonical manifest digest.
const DIGEST_DOMAIN: &str = "arkhe-forge-manifest-digest";

// ===================== Sections =====================

/// Shell identity + public presentation metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellSection {
    /// Shell identifier — stable across releases (max 32 bytes UTF-8).
    pub shell_id: String,
    /// Human-readable shell name shown to end users.
    pub display_name: String,
}

/// Runtime version bounds for this shell.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSection {
    /// Highest Runtime semver the shell promises compatibility with
    /// (e.g. `"0.15"`). Must be ≥ `runtime_current`.
    pub runtime_max: String,
    /// Runtime semver the manifest author tested against (e.g. `"0.13"`).
    pub runtime_current: String,
}

/// Audit / crypto stance — compliance tier classification.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// PII AEAD family identifier — e.g. `"xchacha20-poly1305"`,
    /// `"aes-256-gcm"`, `"aes-256-gcm-siv"`.
    pub pii_cipher: String,
    /// DEK backend identifier — `"software-kek"` (Tier-0 dev only),
    /// `"hsm"`, `"aws-kms"`, `"gcp-kms"`, etc.
    pub dek_backend: String,
    /// KMS auto-promote policy — `"manual"` (operator approval) or
    /// `"after_60min"` (auto-promote after 60 minutes of health-check
    /// consensus).
    pub kms_auto_promote: String,
    /// Audit receipt signature class (the E13 axiom). Wire format
    /// accepts `"ed25519"` / `"ml-dsa-65"` / `"hybrid"`. Forge L2
    /// attestation emits `"ed25519"`.
    pub signature_class: String,
    /// Compliance tier — `0` (software KEK, dev), `1` (single KMS
    /// free-tier), `2` (production Multi-KMS + threshold HSM).
    pub compliance_tier: u8,
}

/// Frontend / TLS / credential policy. Defaults apply when the TOML omits
/// the `[frontend]` table entirely or any sub-field.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FrontendSection {
    /// TLS is mandatory on the public ingress (default `true`).
    pub tls_required: bool,
    /// Alpha-tier credentials must rotate on promotion (default `true`).
    pub alpha_credential_rotation_required: bool,
}

impl Default for FrontendSection {
    fn default() -> Self {
        Self {
            tls_required: true,
            alpha_credential_rotation_required: true,
        }
    }
}

/// Typed view of a loaded shell manifest.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSnapshot {
    /// Wire schema version.
    pub schema_version: u16,
    /// `[shell]` table.
    pub shell: ShellSection,
    /// `[runtime]` table.
    pub runtime: RuntimeSection,
    /// `[audit]` table.
    pub audit: AuditSection,
    /// `[frontend]` table (optional in TOML, filled via `Default`).
    #[serde(default)]
    pub frontend: FrontendSection,
}

// ===================== Errors =====================

/// Manifest-loading failure taxonomy.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// TOML parse or UTF-8 decode failure.
    #[error("parse error: {0}")]
    ParseError(String),

    /// A required field was absent (reserved for future custom checks
    /// beyond what `serde(deny_unknown_fields)` already enforces).
    #[error("missing required field: {0}")]
    MissingRequired(&'static str),

    /// Compliance-tier / DEK-backend pair is inconsistent.
    #[error("tier {tier} incompatible with backend '{backend}'")]
    TierBackendMismatch {
        /// Declared tier.
        tier: u8,
        /// Declared backend.
        backend: String,
    },

    /// `software-kek` is allowed only on Tier-0 dev runs; production
    /// runtimes (`runtime_current > 0.15`) reject it.
    #[error("software-kek rejected: runtime_current {current} > 0.15")]
    SoftwareKekProductionRefused {
        /// Declared current runtime version.
        current: String,
    },

    /// `runtime_max` lexicographically precedes `runtime_current` (illegal
    /// because the shell would claim forward-compat to a version less than
    /// the one it tested).
    #[error("version mismatch: runtime_max < runtime_current")]
    VersionMismatch,

    /// Reserved — future custom deserializer returns this when extracting
    /// the offending key from a `deny_unknown_fields` failure.
    #[error("unknown field: {0}")]
    UnknownField(String),

    /// Field failed a validation predicate (e.g. malformed semver).
    #[error("invalid value for {field}: {reason}")]
    InvalidValue {
        /// Field name whose value was rejected.
        field: &'static str,
        /// Human-readable reason.
        reason: String,
    },
}

// ===================== Loader =====================

/// Zero-state manifest loader.
pub struct ManifestLoader;

impl ManifestLoader {
    /// Parse + validate + digest a TOML-encoded manifest in one call.
    pub fn load(toml_bytes: &[u8]) -> Result<(ManifestSnapshot, ManifestDigest), ManifestError> {
        let text = core::str::from_utf8(toml_bytes)
            .map_err(|e| ManifestError::ParseError(format!("utf-8: {}", e)))?;
        let snapshot: ManifestSnapshot =
            toml::from_str(text).map_err(|e| ManifestError::ParseError(e.to_string()))?;
        Self::validate(&snapshot)?;
        let digest = Self::canonical_digest(&snapshot)?;
        Ok((snapshot, digest))
    }

    /// Run cross-field validators on a parsed snapshot. Called by
    /// [`ManifestLoader::load`]; exposed for callers that construct
    /// `ManifestSnapshot` directly.
    pub fn validate(m: &ManifestSnapshot) -> Result<(), ManifestError> {
        // shell_id length — stays within BoundedString<32> budget.
        if m.shell.shell_id.len() > 32 {
            return Err(ManifestError::InvalidValue {
                field: "shell.shell_id",
                reason: format!("length {} > 32", m.shell.shell_id.len()),
            });
        }

        // Parseability of runtime versions.
        let current =
            parse_version(&m.runtime.runtime_current).ok_or(ManifestError::InvalidValue {
                field: "runtime.runtime_current",
                reason: format!(
                    "not a 'M.N' or 'M.N.P' semver: {}",
                    m.runtime.runtime_current
                ),
            })?;
        let max = parse_version(&m.runtime.runtime_max).ok_or(ManifestError::InvalidValue {
            field: "runtime.runtime_max",
            reason: format!("not a 'M.N' or 'M.N.P' semver: {}", m.runtime.runtime_max),
        })?;
        if max < current {
            return Err(ManifestError::VersionMismatch);
        }

        // Tier ↔ backend cross-check.
        match (m.audit.compliance_tier, m.audit.dek_backend.as_str()) {
            (0, "software-kek") => {}
            (0, other) => {
                return Err(ManifestError::TierBackendMismatch {
                    tier: 0,
                    backend: other.to_string(),
                });
            }
            (1 | 2, "software-kek") => {
                return Err(ManifestError::TierBackendMismatch {
                    tier: m.audit.compliance_tier,
                    backend: "software-kek".to_string(),
                });
            }
            (1 | 2, _) => {}
            _ => {
                return Err(ManifestError::InvalidValue {
                    field: "audit.compliance_tier",
                    reason: format!("unsupported tier {}", m.audit.compliance_tier),
                });
            }
        }

        // software-kek refused past runtime 0.15.
        if m.audit.dek_backend == "software-kek" && (current.0, current.1) > (0, 15) {
            return Err(ManifestError::SoftwareKekProductionRefused {
                current: m.runtime.runtime_current.clone(),
            });
        }

        Ok(())
    }

    /// Compute the canonical BLAKE3 digest of a snapshot. The manifest is
    /// re-serialized to TOML through serde (struct field order is
    /// deterministic), then hashed under the `arkhe-forge-manifest-digest`
    /// domain.
    ///
    /// # `toml` crate dependency note
    ///
    /// The digest depends on the underlying `toml` crate's serialise output —
    /// specifically its `BTreeMap` traversal order, key spacing, and string
    /// quoting style. `Cargo.lock` pins the `toml` minor version so the
    /// emitted bytes stay stable across builds within the pinned-toml
    /// version window.
    ///
    /// A future `toml` **major** version bump (currently `1.x`, hypothetical
    /// `2.x`) is allowed to change those low-level emit details and must be
    /// accompanied by:
    ///
    /// 1. A regression sentinel update in the `digest_invariant` test module
    ///    (`TIER0_DEV_DIGEST_V0_11` constant; test will surface the byte
    ///    drift on first run).
    /// 2. A manifest schema micro-patch documenting the digest re-pin —
    ///    the manifest `schema_version` is **not** bumped on its own (the
    ///    schema itself did not change); the spec patch records the toml
    ///    crate bump as the cause.
    ///
    /// Design: regression sentinel + spec drift correction. The digest
    /// input keeps wire-bytes pure (no toml-version literal mixed into the
    /// keyed_hash key); the regression test catches any drift and turns it
    /// into an explicit operator decision rather than a silent re-pin.
    pub fn canonical_digest(m: &ManifestSnapshot) -> Result<ManifestDigest, ManifestError> {
        let canonical = toml::to_string(m)
            .map_err(|e| ManifestError::ParseError(format!("toml serialize: {}", e)))?;
        let key = blake3::derive_key(DIGEST_DOMAIN, &[]);
        let hash = blake3::keyed_hash(&key, canonical.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        Ok(out)
    }
}

// ===================== RuntimeBootstrap helper =====================

/// Emit a `RuntimeBootstrap` event onto `ctx` using `digest` as the
/// manifest anchor (the E12 axiom). The caller supplies the L0 and
/// Runtime semver plus the active TypeCode pin set — downstream boot code
/// plugs in the live registry.
pub fn emit_runtime_bootstrap(
    digest: &ManifestDigest,
    l0_semver: SemVer,
    runtime_semver: SemVer,
    typecode_pins: Vec<TypeCode>,
    bootstrap_tick: Tick,
    ctx: &mut ActionContext<'_>,
) -> Result<(), ActionError> {
    let event = RuntimeBootstrap {
        schema_version: 1,
        l0_semver,
        runtime_semver,
        manifest_digest: *digest,
        typecode_pins,
        bootstrap_tick,
    };
    ctx.emit_event(&event)
}

// ===================== Helpers =====================

/// Parse `"M.N"` or `"M.N.P"` into `(major, minor, patch)`. Rejects
/// pre-release / build-metadata suffixes (Runtime does
/// not accept SemVer 2.0 suffixes for canonical-bytes stability).
fn parse_version(s: &str) -> Option<(u16, u16, u16)> {
    let mut parts = s.splitn(3, '.');
    let major: u16 = parts.next()?.parse().ok()?;
    let minor: u16 = parts.next()?.parse().ok()?;
    let patch: u16 = match parts.next() {
        Some(p) => p.parse().ok()?,
        None => 0,
    };
    Some((major, minor, patch))
}

// ===================== Tests =====================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use arkhe_kernel::abi::{CapabilityMask, InstanceId, Principal};

    pub(super) const TIER0_DEV_TOML: &str = r#"
schema_version = 1

[shell]
shell_id = "shell.dev.example"
display_name = "Dev Sandbox"

[runtime]
runtime_max = "0.15"
runtime_current = "0.13"

[audit]
pii_cipher = "xchacha20-poly1305"
dek_backend = "software-kek"
kms_auto_promote = "manual"
signature_class = "ed25519"
compliance_tier = 0
"#;

    const TIER1_PROD_TOML: &str = r#"
schema_version = 1

[shell]
shell_id = "shell.prod.example"
display_name = "Prod Shell"

[runtime]
runtime_max = "0.20"
runtime_current = "0.13"

[audit]
pii_cipher = "aes-256-gcm-siv"
dek_backend = "aws-kms"
kms_auto_promote = "after_60min"
signature_class = "hybrid"
compliance_tier = 1

[frontend]
tls_required = true
alpha_credential_rotation_required = true
"#;

    #[test]
    fn load_valid_tier0_dev_manifest() {
        let (snap, digest) = ManifestLoader::load(TIER0_DEV_TOML.as_bytes()).unwrap();
        assert_eq!(snap.schema_version, 1);
        assert_eq!(snap.audit.compliance_tier, 0);
        assert_eq!(snap.audit.dek_backend, "software-kek");
        assert_eq!(digest.len(), 32);
        assert!(snap.frontend.tls_required); // default
    }

    #[test]
    fn load_valid_tier1_prod_manifest() {
        let (snap, digest) = ManifestLoader::load(TIER1_PROD_TOML.as_bytes()).unwrap();
        assert_eq!(snap.audit.compliance_tier, 1);
        assert_eq!(snap.audit.dek_backend, "aws-kms");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn digest_is_deterministic_across_loads() {
        let (_, d1) = ManifestLoader::load(TIER1_PROD_TOML.as_bytes()).unwrap();
        let (_, d2) = ManifestLoader::load(TIER1_PROD_TOML.as_bytes()).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_is_whitespace_and_comment_invariant() {
        let a = TIER0_DEV_TOML;
        // Add comments + trailing whitespace; canonicalization should erase them.
        let b = r#"
# comment block
schema_version = 1

[shell]
shell_id = "shell.dev.example"   # trailing comment
display_name = "Dev Sandbox"

[runtime]
runtime_max = "0.15"
runtime_current = "0.13"

[audit]
pii_cipher = "xchacha20-poly1305"
dek_backend = "software-kek"
kms_auto_promote = "manual"
signature_class = "ed25519"
compliance_tier = 0
"#;
        let (_, da) = ManifestLoader::load(a.as_bytes()).unwrap();
        let (_, db) = ManifestLoader::load(b.as_bytes()).unwrap();
        assert_eq!(da, db, "comments / whitespace must not affect digest");
    }

    #[test]
    fn digest_differs_for_semantically_different_manifest() {
        let (_, d0) = ManifestLoader::load(TIER0_DEV_TOML.as_bytes()).unwrap();
        let (_, d1) = ManifestLoader::load(TIER1_PROD_TOML.as_bytes()).unwrap();
        assert_ne!(d0, d1);
    }

    #[test]
    fn print_tier0_dev_digest_for_pin() {
        // One-shot helper to discover the sentinel bytes; left in the
        // suite so maintainers can re-run it after a deliberate schema
        // bump and copy the new bytes into
        // `digest_invariant::TIER0_DEV_DIGEST_V0_11`.
        let (_, d) = ManifestLoader::load(TIER0_DEV_TOML.as_bytes()).unwrap();
        eprintln!(
            "tier0_dev digest = {:?}",
            d.iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>()
        );
    }

    #[test]
    fn tier0_with_kms_backend_rejected() {
        let bad = TIER0_DEV_TOML.replace("software-kek", "aws-kms");
        let err = ManifestLoader::load(bad.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::TierBackendMismatch { tier: 0, .. }
        ));
    }

    #[test]
    fn tier1_with_software_kek_rejected() {
        let bad = TIER1_PROD_TOML.replace("aws-kms", "software-kek");
        let err = ManifestLoader::load(bad.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::TierBackendMismatch { tier: 1, .. }
        ));
    }

    #[test]
    fn software_kek_past_0_15_refused() {
        let bad = TIER0_DEV_TOML
            .replace("runtime_current = \"0.13\"", "runtime_current = \"0.16\"")
            // runtime_max also must be >= current for version ordering to pass.
            .replace("runtime_max = \"0.15\"", "runtime_max = \"0.20\"");
        let err = ManifestLoader::load(bad.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::SoftwareKekProductionRefused { .. }
        ));
    }

    #[test]
    fn runtime_max_less_than_current_rejected() {
        let bad = TIER0_DEV_TOML.replace("runtime_max = \"0.15\"", "runtime_max = \"0.5\"");
        let err = ManifestLoader::load(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, ManifestError::VersionMismatch));
    }

    #[test]
    fn parse_error_on_malformed_toml() {
        let err = ManifestLoader::load(b"this is not toml == invalid").unwrap_err();
        assert!(matches!(err, ManifestError::ParseError(_)));
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        let bad = format!("{}\nunknown_field = 42\n", TIER0_DEV_TOML);
        let err = ManifestLoader::load(bad.as_bytes()).unwrap_err();
        // `deny_unknown_fields` surfaces the serde error inside ParseError.
        assert!(matches!(err, ManifestError::ParseError(_)));
    }

    #[test]
    fn bad_semver_rejected() {
        let bad = TIER0_DEV_TOML.replace(
            "runtime_current = \"0.13\"",
            "runtime_current = \"not-a-version\"",
        );
        let err = ManifestLoader::load(bad.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::InvalidValue {
                field: "runtime.runtime_current",
                ..
            }
        ));
    }

    #[test]
    fn shell_id_over_32_bytes_rejected() {
        let long_id = "a".repeat(33);
        let bad = TIER0_DEV_TOML.replace("shell.dev.example", &long_id);
        let err = ManifestLoader::load(bad.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::InvalidValue {
                field: "shell.shell_id",
                ..
            }
        ));
    }

    #[test]
    fn emit_runtime_bootstrap_appends_event() {
        let (_, digest) = ManifestLoader::load(TIER0_DEV_TOML.as_bytes()).unwrap();
        let mut ctx = ActionContext::new(
            [0x11u8; 32],
            InstanceId::new(1).unwrap(),
            Tick(1),
            Principal::System,
            CapabilityMask::SYSTEM,
        );
        emit_runtime_bootstrap(
            &digest,
            SemVer::new(0, 11, 0),
            SemVer::new(0, 11, 0),
            vec![TypeCode(0x0003_0001), TypeCode(0x0003_0002)],
            Tick(1),
            &mut ctx,
        )
        .unwrap();
        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].type_code, 0x0003_0F01);
        assert_eq!(events[0].tick, Tick(1));

        // The serialized payload round-trips and carries the supplied digest.
        let bootstrap: RuntimeBootstrap = postcard::from_bytes(&events[0].payload).unwrap();
        assert_eq!(bootstrap.manifest_digest, digest);
        assert_eq!(bootstrap.l0_semver, SemVer::new(0, 11, 0));
    }

    #[test]
    fn frontend_defaults_when_omitted() {
        let (snap, _) = ManifestLoader::load(TIER0_DEV_TOML.as_bytes()).unwrap();
        // TIER0_DEV_TOML omits [frontend]; defaults apply.
        assert!(snap.frontend.tls_required);
        assert!(snap.frontend.alpha_credential_rotation_required);
    }

    #[test]
    fn parse_version_accepts_two_or_three_components() {
        assert_eq!(parse_version("0.13"), Some((0, 13, 0)));
        assert_eq!(parse_version("0.13.3"), Some((0, 13, 3)));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("0.13.3.4"), None); // 3-part splitn leaves "3.4"
        assert_eq!(parse_version("abc.def"), None);
    }
}

/// Manifest digest sentinel pin.
///
/// The canonical digest depends on the underlying `toml` crate's serialise
/// output. `Cargo.lock` pins the toml minor version, so within the pinned
/// toml-version window the bytes below are stable. A toml major bump
/// (`1.x → 2.x`) is expected to change these bytes — the test then surfaces
/// the drift, the operator updates the sentinel and writes a manifest schema
/// manifest schema micro-patch documenting the re-pin.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod digest_invariant {
    use super::tests::TIER0_DEV_TOML;
    use super::ManifestLoader;

    /// SHA equivalent: `blake3::keyed_hash(derive_key("arkhe-forge-manifest-digest", &[]),
    /// toml::to_string(TIER0_DEV_TOML_snapshot))` under the
    /// `Cargo.lock`-pinned `toml` crate version.
    const TIER0_DEV_DIGEST_V0_11: [u8; 32] = [
        0xa1, 0xbf, 0xe8, 0x2a, 0x57, 0xe1, 0xde, 0x55, 0x05, 0x7e, 0x47, 0x51, 0xd0, 0xeb, 0xed,
        0x3d, 0x48, 0x82, 0xdb, 0xd5, 0x95, 0x2d, 0x83, 0xcd, 0x52, 0x10, 0x6c, 0x0f, 0xae, 0x3b,
        0xab, 0x3c,
    ];

    #[test]
    fn tier0_dev_digest_matches_v0_11_sentinel() {
        let (_, digest) = ManifestLoader::load(TIER0_DEV_TOML.as_bytes())
            .expect("TIER0_DEV_TOML must parse cleanly");
        assert_eq!(
            digest, TIER0_DEV_DIGEST_V0_11,
            "manifest canonical_digest drifted from the pinned sentinel — check toml crate \
             version, ManifestSnapshot field order, and DIGEST_DOMAIN. Update the sentinel + \
             write a manifest schema micro-patch if the change is intentional."
        );
    }
}
