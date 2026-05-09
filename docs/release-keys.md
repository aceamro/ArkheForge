# Release Keys

This file is **intentionally a forward-pointer**. The authoritative release-keys
inventory lives in the operator-side repository
[`aceamro/arkhe-release-keys`](https://github.com/aceamro/arkhe-release-keys),
external to this runtime workspace.

## Authoritative sections (external repository)

- **§1 — Audit-receipt key inventory**: maps each
  `AuditReceiptKeyPolicy.key_id` (`[u8; 16]`) to its physical key material.
  The `key_id ↔ key material` mapping MUST NOT be checked into this repo.
- **§3 — HW-key co-custody**: 2-of-N HW signing arrangement
  (YubiKey / NitroKey) for `JournalSigner` production binding (spec
  §14.11.3 / §12.4 chain-tip signature).
- **§5.2 — `release-signing-v1` rotation manifest**: 1-year rotation
  cadence, successor / retirement annotations, parallel to the journal
  key's in-band chain-of-trust.

## Emission-gate posture

The Cargo features `audit-receipt-key-identified` and
`federation-archive-hardened` ship with `default = []` and remain OFF
until the corresponding §1 / §3 / §5.2 prerequisites are discharged in
the external repository. Enabling either feature only opens the type
surface (compile-time inclusion of `ReplicaIdAllocation` /
`AuditReceiptKeyPolicy` definitions). The self-enforcing contract:
emission additions MUST land the corresponding `*-emission` sub-feature
concurrently with the emission code; no emission code can land without
the sub-feature landing in the same change.

## Canonical citation form

Code and documentation cite this anchor as `docs/release-keys.md §N`
(full path with the `docs/` prefix).
