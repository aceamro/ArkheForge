#!/usr/bin/env bash
#
# scripts/verify-axiom-cite.sh — Axiom inventory ↔ TLA+ INV + Rust impl test 1:1 grep gate
#
# Companion to formal/axiom-test-cite.toml. Verifies that every
# axiom's cited TLA+ INV (or theorem) appears literally in the cited tla_module file,
# and every cited impl_test appears as `fn <name>` in at least one cited impl_path.
#
# Mismatch → CI fail (catches: axiom defined but test missing, or test renamed but
# inventory not updated).
#
# Composite/descriptive tla_inv names (containing `_via_` or starting with `CONSTANTS_`)
# are skipped — these are documentation aliases per inventory convention (E1
# definitional foundation, E2 subsumption-by-E14).
#
# Exit codes:
#   0 — all axiom cites verified
#   1 — one or more mismatches detected
#   2 — environment error (Python missing, tomllib unavailable, etc.)

set -euo pipefail

# Resolve repo root via git
ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
INVENTORY="${ROOT_DIR}/formal/axiom-test-cite.toml"

if [[ ! -f "${INVENTORY}" ]]; then
    echo "ERROR: ${INVENTORY} not found" >&2
    exit 2
fi

# Delegate to Python for TOML parsing + grep verification
# (Python 3.11+ tomllib preferred; tomli library is an acceptable fallback)
python3 - "${INVENTORY}" "${ROOT_DIR}" <<'PYEOF'
import re
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        print(
            "ERROR: Python 3.11+ tomllib or tomli library required",
            file=sys.stderr,
        )
        sys.exit(2)

INVENTORY = Path(sys.argv[1])
ROOT_DIR = Path(sys.argv[2])

with open(INVENTORY, "rb") as f:
    data = tomllib.load(f)

errors = 0
verified_invs = 0
verified_tests = 0
skipped_descriptive = 0


def iter_axioms():
    """Yield (axiom_id, axiom_dict) pairs for every MC axiom + non-MC axiom."""
    # Non-axiom sections to skip at the top level
    skip = {
        "meta",
        "kani_5_property",
        "layer_a_items",
        "layer_a_item_3",
        "formal_verification_inventory",
        "non_mc_axioms",
    }
    for key, val in data.items():
        if key in skip or not isinstance(val, dict):
            continue
        yield (key, val)

    # Non-MC axioms live under [non_mc_axioms.E*]
    non_mc = data.get("non_mc_axioms", {})
    for key, val in non_mc.items():
        if isinstance(val, dict):
            yield (f"non_mc.{key}", val)


def is_descriptive(name: str) -> bool:
    """Composite/documentation names that aren't literal TLA+ identifiers.

    Skip patterns:
      - `_via_`     — subsumption documentation (e.g., E2 subsumed by E14)
      - `CONSTANTS_` — definitional foundation (e.g., E1 primitive set)
      - `_implies_`  — lemma documented in comment block, not declared as
                       TLA+ theorem entity (e.g., `SealedTrait_implies_E15.b`,
                       `SealedHostLinker_implies_4_set` from M2.4/M2.5
                       paired commit). Lemma names follow
                       `<premise>_implies_<conclusion>` convention; the
                       comment block carries the proof sketch + anchors.
    """
    return (
        "_via_" in name
        or "_implies_" in name
        or name.startswith("CONSTANTS_")
    )


for axiom_id, axiom in iter_axioms():
    # --- TLA+ INV / theorem cite verify ---
    tla_module = axiom.get("tla_module")
    if tla_module:
        module_path = ROOT_DIR / tla_module
        if not module_path.is_file():
            print(f"FAIL {axiom_id}: tla_module file not found: {tla_module}")
            errors += 1
            continue
        module_content = module_path.read_text()

        tla_names = []
        if "tla_inv" in axiom:
            tla_names.append(("tla_inv", axiom["tla_inv"]))
        if "tla_invs" in axiom:
            for inv in axiom["tla_invs"]:
                tla_names.append(("tla_invs", inv))
        if "tla_theorem" in axiom:
            tla_names.append(("tla_theorem", axiom["tla_theorem"]))
        if "tla_lemma" in axiom:
            tla_names.append(("tla_lemma", axiom["tla_lemma"]))

        for kind, name in tla_names:
            if is_descriptive(name):
                skipped_descriptive += 1
                continue
            pattern = rf"\b{re.escape(name)}\b"
            if re.search(pattern, module_content):
                verified_invs += 1
            else:
                print(
                    f"FAIL {axiom_id}: {kind} '{name}' NOT FOUND in {tla_module}"
                )
                errors += 1

    # --- impl_test cite verify ---
    impl_tests = axiom.get("impl_tests", [])
    impl_paths = axiom.get("impl_paths", [])

    # impl_paths entries may use "file:line" format — use the file portion
    test_files = []
    seen = set()
    for p in impl_paths:
        f = p.split(":", 1)[0]
        if f not in seen:
            seen.add(f)
            test_files.append(f)

    for test_name in impl_tests:
        found_in = None
        for f in test_files:
            file_path = ROOT_DIR / f
            if not file_path.is_file():
                continue
            content = file_path.read_text()
            # Match `fn <test_name>` (with optional `pub `, `async `, modifiers)
            if re.search(rf"\bfn\s+{re.escape(test_name)}\b", content):
                found_in = f
                break
        if found_in:
            verified_tests += 1
        else:
            print(
                f"FAIL {axiom_id}: impl_test 'fn {test_name}' NOT FOUND in any of {test_files}"
            )
            errors += 1

# --- Summary ---
print()
print(f"Verified: {verified_invs} TLA+ identifier(s), {verified_tests} impl test(s)")
print(f"Skipped (descriptive name): {skipped_descriptive}")

if errors:
    print(f"\nFAIL: {errors} verification error(s)")
    sys.exit(1)
print("\nOK: all axiom cites verified")
sys.exit(0)
PYEOF
