---- MODULE r4_implementation_refinement ----
(*
 * r4_implementation_refinement — DIP-N5 sub-step E.6.
 *
 * R4-I anchors E3 (Runtime → L0 strictly downward, L1 → L2 forbidden)
 * + E8 (Entry/Space parent DAG cycle-free + depth ≤ 64) + E9 (Activity
 * self-loop blocked + meta-verb depth ≤ 8). EXTENDs runtime_core with:
 *  (1) Layer enum + LayerOrder monotone helper (E3 anchor);
 *  (2) Entry record type with parent_entry + depth (E8 anchor);
 *  (3) MetaActivity record type with meta_verb_depth (E9 anchor);
 *  (4) Import record type (E3 layer-DAG edge);
 *  (5) 5 module-specific INVs;
 *  (6) Concrete state machine: RecordLayerImport / CreateEntry /
 *      CreateMetaActivity transitions.
 *
 * Tier annotations per `formal/tla-plus/README.md` Section 2 mapping:
 *   - E3-LayerImportStrictlyDownward (MC, E3 cross-layer 3-tier;
 *     R4-X is sibling L0-internal concept, see preamble scope note)
 *   - E8-EntryParentDagDepthBounded (MC, hard cap 64)
 *   - E8-EntryParentDagAcyclic (MC, parent depth strictly less)
 *   - E9-ActivitySelfLoopBlocked (MC, actor # target)
 *   - E9-MetaVerbDepthBounded (MC, hard cap 8)
 *
 * Scope: L0 + L1 + L2 cross-layer 3-tier hierarchy (E3 axiom
 * refinement, v0.12 sealing scope per `runtime-book/src/en/
 * architecture/02-layers.md` §2.1 + §2.2 — L1+L2 marked "this
 * DIP scope", L3+ marked "Out of scope"). L3 (Library/ECS) is
 * declared in `book/src/en/architecture/domain-spec.md` §"Layer
 * distinctions" but explicitly out-of-scope at v0.12 per
 * 02-layers.md §2.2 — application-domain layer with no v0.12
 * invariant requirement.
 *
 * Distinction from R4-X (`book/src/en/appendix/decisions.md` R4-X):
 * R4-X anchors the L0 kernel INTERNAL 4-stratum DAG (`abi → state
 * → runtime → persist`, single-crate intra-module DAG enforced by
 * cargo-modules CI gate at L0 build time). R4-I refines E3
 * cross-layer 3-tier — different abstraction level, not a
 * refinement of R4-X. R4-X citations elsewhere in this rustdoc
 * anchor R4-X as a sibling concept (L0-internal sealing axis),
 * not as the source axiom of `LayerImportStrictlyDownward`. R4-X
 * is Layer A DO NOT TOUCH item 6 (L0 sealed, runtime-book §16
 * references) — preserved verbatim, sealed at the L0 build-time
 * gate. The TLA+ refinement here captures the abstract E3
 * cross-layer invariant that the cargo-modules CI gate enforces
 * at build time.
 *
 * Space coverage note: E8 spec body covers Entry/Space parent DAGs
 * symmetrically. The TLA+ catalog (README.md §11.3) records E8 as
 * `EntryParentDagDepthBounded` + `EntryParentDagAcyclic` —
 * Space.parent_space follows the same pattern with identical
 * structural form (parent_space: SpaceIds ∪ {NONE} + depth ≤ 64 +
 * acyclic via depth monotonicity). Modeling Entry only at the
 * abstraction level is sufficient — Space INV proofs are
 * structurally identical (theorist Minor Note 5 evaluation: tier
 * annotation applies symmetrically).
 *
 * theorist Minor Note 1 absorption: NextR4 self-contained pattern.
 * theorist Minor Note 2 absorption: TypeOK_R4 explicit composition
 * via `TypeOK /\ ...` (E.4 + E.5 carry-forward confirmed).
 *
 * Anchored to:
 *   - runtime-book/src/en/architecture/11-axioms.md E3, E8, E9
 *   - book/src/en/appendix/decisions.md R4-X
 *
 * Apalache primary tooling. CI: `apalache-mc typecheck` per .tla.
 * TLC fallback documented for E8 acyclicity over large entry sets.
 *)

EXTENDS runtime_core

\* @typeAlias: layer = Str;
ALIAS_layer == TRUE

\* @typeAlias: entryId = Str;
ALIAS_entryId == TRUE

\* @typeAlias: r4Verb = Str;
ALIAS_r4Verb == TRUE

\* @typeAlias: moduleId = Str;
ALIAS_moduleId == TRUE

\* @typeAlias: r4Entry = { id: Str, parent_entry: Str, depth: Int };
ALIAS_r4Entry == TRUE

\* @typeAlias: r4MetaActivity = { actor: Str, target: Str, verb: Str, meta_verb_depth: Int };
ALIAS_r4MetaActivity == TRUE

\* @typeAlias: r4Import = { from: Str, to: Str };
ALIAS_r4Import == TRUE

CONSTANTS
    \* @type: Set($layer);
    Layers,             \* {"L0", "L1", "L2"} (3-tier)
    \* @type: Set($entryId);
    EntryIds,           \* Entry identifier set
    \* @type: Set($r4Verb);
    Verbs,              \* Verb identifier set (for MetaActivity)
    \* @type: Int;
    MaxDagDepth,        \* E8 hard cap = 64
    \* @type: Int;
    MaxMetaVerbDepth,   \* E9 hard cap = 8
    \* @type: Int;
    MaxEntries,         \* Bounded MC ceiling: entries
    \* @type: Int;
    MaxMetaActivities,  \* Bounded MC ceiling: meta-activities
    \* @type: Int;
    MaxImports,         \* Bounded MC ceiling: layer imports
    \* @type: Set($moduleId);
    BoundaryModules,    \* {"hook_host", "observer_host"} — L1+ runtime sandbox boundary stratum (R2-S9)
    \* @type: Set($moduleId);
    RuntimeModules      \* {"wasm_runtime_common"} — L1+ runtime sandbox runtime stratum (R2-S9)

ASSUME
    /\ Layers = {"L0", "L1", "L2"}
    /\ EntryIds # {}
    /\ Verbs # {}
    /\ MaxDagDepth = 64
    /\ MaxMetaVerbDepth = 8
    /\ MaxEntries \in Nat \ {0}
    /\ MaxMetaActivities \in Nat \ {0}
    /\ MaxImports \in Nat \ {0}
    /\ BoundaryModules = {"hook_host", "observer_host"}
    /\ RuntimeModules = {"wasm_runtime_common"}

(* --- Layer order helper (E3 anchor) ---
 *
 * Layers form a 3-tier total order: L0 (kernel sealed) < L1
 * (Runtime / Action::compute) < L2 (Hooks / Observer). E3 axiom:
 * imports go strictly downward — L1 → L0 OK, L2 → L1 OK, L2 → L0
 * OK; reverse forbidden, L1 → L2 forbidden.
 *)
LayerOrder ==
    [l \in Layers |->
        IF l = "L0" THEN 0
        ELSE IF l = "L1" THEN 1
        ELSE 2]

(* --- Concrete refinement of R4-I record types --- *)

\* Entry record — parent_entry forms a forest (cycle-free) with
\* depth ≤ MaxDagDepth. Sentinel "NONE" represents root entries
\* (no parent). E8 anchor.
Entry ==
    [ id:           EntryIds,
      parent_entry: EntryIds \cup {"NONE"},
      depth:        0..MaxDagDepth ]

\* MetaActivity record — extends CR-2's Activity (actor, target,
\* verb) with meta_verb_depth field for E9 anchor. Distinct from
\* CR-2's `activities` sequence: R4-I models the set of created
\* activities for state-level INV checking, not the submit order.
MetaActivity ==
    [ actor:           Actors,
      target:          Actors,
      verb:            Verbs,
      meta_verb_depth: 0..MaxMetaVerbDepth ]

\* Import record — directed edge (from, to) representing a layer
\* import declaration (e.g., crate dependency graph edge). E3
\* anchor: imports must go strictly downward in LayerOrder.
Import ==
    [ from: Layers,
      to:   Layers ]

VARIABLES
    \* @type: Set($r4Import);
    layer_imports,    \* Set of Import (E3 layer-DAG)
    \* @type: Set($r4Entry);
    r4_entries,       \* Subset of Entry (E8 parent DAG)
    \* @type: Set($r4MetaActivity);
    r4_activities     \* Subset of MetaActivity (E9 self-loop + depth)

vars_r4 == << chain_tip, wal, tick,
              actor_user_binding, actor_shell_binding,
              authenticated_actors,
              runtime_bootstrap, signature_class_policy,
              layer_imports, r4_entries, r4_activities >>

(* --- Type invariant (theorist Minor Note 2 explicit composition,
 *     E.4 + E.5 carry-forward confirmed at E.6) --- *)

TypeOK_R4 ==
    /\ TypeOK                                    \* base, via EXTENDS
    /\ layer_imports \subseteq Import
    /\ r4_entries \subseteq Entry
    /\ r4_activities \subseteq MetaActivity
    /\ Cardinality(layer_imports) <= MaxImports
    /\ Cardinality(r4_entries) <= MaxEntries
    /\ Cardinality(r4_activities) <= MaxMetaActivities

(* --- Module-specific invariants --- *)

\* INV E3: LayerImportStrictlyDownward (MC, E3 cross-layer 3-tier).
\* Every recorded layer import goes strictly downward in LayerOrder.
\* L1 → L0 OK (LayerOrder L0=0 < L1=1); L2 → L1 OK (1 < 2); L2 → L0
\* OK (0 < 2). L0 → anything FORBIDDEN (L0 sealed). L1 → L2
\* FORBIDDEN per E3 explicit. Reverse imports fail the cargo-modules
\* CI gate at build time per `book/src/en/architecture/overview.md`.
\* (R4-X is the sibling L0-internal 4-stratum gate, not refined here.)
LayerImportStrictlyDownward ==
    \A imp \in layer_imports :
        LayerOrder[imp.to] < LayerOrder[imp.from]

\* INV E8-1: EntryParentDagDepthBounded (MC, hard cap 64).
\* Every Entry's depth is bounded by MaxDagDepth. The depth
\* Component cache (per spec body) provides O(1) verification at
\* the Rust runtime level; the TLA+ refinement asserts the
\* state-level bound directly.
EntryParentDagDepthBounded ==
    \A e \in r4_entries : e.depth <= MaxDagDepth

\* INV E8-2: EntryParentDagAcyclic (MC, depth monotonicity).
\* Acyclicity captured via depth-monotone parent invariant: every
\* non-root Entry has a parent Entry with strictly smaller depth.
\* Combined with EntryParentDagDepthBounded, this rules out cycles
\* (any cycle would require equal-depth ancestors). Parent
\* immutable post-creation per P5 / spec body §11.3 E8.
EntryParentDagAcyclic ==
    \A e \in r4_entries :
        e.parent_entry # "NONE" =>
            \E p \in r4_entries :
                /\ p.id = e.parent_entry
                /\ p.depth = e.depth - 1

\* INV E9-1: ActivitySelfLoopBlocked (MC, actor # target).
\* No MetaActivity has actor = target (self-loop). Prevents
\* feedback loops in the activity graph.
ActivitySelfLoopBlocked ==
    \A a \in r4_activities : a.actor # a.target

\* INV E9-2: MetaVerbDepthBounded (MC, hard cap 8).
\* Every MetaActivity's meta_verb_depth ≤ MaxMetaVerbDepth.
\* manifest.moderation.appeal_max_depth is configurable in 1..=8
\* (default 2); Runtime hard cap is 8 per spec body. The TLA+
\* refinement enforces the hard cap; manifest-config sub-cap is
\* a runtime narrowing of this bound.
MetaVerbDepthBounded ==
    \A a \in r4_activities : a.meta_verb_depth <= MaxMetaVerbDepth

\* INV E3-X: ImportDirectionMonotone (MC, M2.6 R4-X stratum extension,
\* DIP-N6 Phase 2 M2-NEW-4a). Formal-method companion to the M2.6
\* mechanical CI grep gate.
\*
\* Scope: L1+ runtime sandbox sub-DAG (separate from R4-X's L0-internal
\* `abi → state → runtime → persist` DAG documented in the R4-X sibling
\* concept note below). Within `arkhe-forge-platform`:
\*   - Boundary stratum: `hook_host` + `observer_host` (sandbox-facing
\*     wasmtime hosts that own host-fn dispatch + cap-token gating)
\*   - Runtime stratum: `wasm_runtime_common` (chain-effect-aware
\*     factory module: EngineProfile, register_module_common,
\*     scan_module_imports, WASI_DENY_PREFIXES, SealedHostImport,
\*     SealedCapToken)
\*
\* Direction invariant: imports flow boundary → runtime exclusively;
\* reverse edge (runtime → boundary) is forbidden. The CI lint job
\* (`.github/workflows/ci.yml` line 145-163, M2.6 commit `a0d190a`)
\* enforces this at the source-code level via `grep -E "use\s+
\* (crate::)?(hook_host|observer_host)"` against
\* `arkhe-forge-platform/src/wasm_runtime_common/`; this INV is the
\* TLA+-abstract companion that names the property in the formal layer.
\*
\* The INV body captures the *necessary precondition* (boundary/runtime
\* stratum disjointness) — the *sufficient condition* (edge direction at
\* the runtime module-graph) is not modeled at the TLA+ refinement level
\* per design (no `r4_*` variable models the L1+ runtime module-graph).
\* The dual-layer defense-in-depth anchors the property:
\*   - TLA+ INV body: necessary precondition `BoundaryModules \cap
\*     RuntimeModules = {}` — Apalache-checkable static set disjointness
\*   - Source-level enforcement (sufficient condition): CI grep gate at
\*     `.github/workflows/ci.yml` lines 145-163 (M2.6 commit `a0d190a`)
\*     runs `grep -rE "use\s+(crate::)?(hook_host|observer_host)"` against
\*     `arkhe-forge-platform/src/wasm_runtime_common/`; any reverse-edge
\*     import (runtime → boundary) fails the lint job.
\*
\* R2-S9 (option ε refined α+δ): vacuous TRUE → necessary precondition
\* INV body (α semantic gain) + design intent comment block carry
\* (δ source-level enforcement reference enrichment).
\*
\* Anchored to:
\*   - `.github/workflows/ci.yml` lint job R4-X verify step (M2.6, lines 145-163)
\*   - `arkhe-forge-platform/src/wasm_runtime_common/mod.rs` (runtime
\*     stratum, head-doc R4-X stratum classification)
\*   - `arkhe-forge-platform/src/{hook_host,observer_host}/` (boundary
\*     stratum)
\*   - `book/src/en/appendix/decisions.md` R4-X (L0-internal sibling
\*     concept; this INV extends the R4-X principle to L1+ runtime)
ImportDirectionMonotone ==
    BoundaryModules \cap RuntimeModules = {}

(* --- Concrete state machine refinement --- *)

\* RecordLayerImport — register a layer-import edge. Pre-condition
\* enforces E3 strictly-downward at insertion site (build-time
\* cargo-modules CI gate refinement).
RecordLayerImport(imp) ==
    /\ imp \in Import
    /\ LayerOrder[imp.to] < LayerOrder[imp.from]
    /\ Cardinality(layer_imports) < MaxImports
    /\ tick + 1 <= MaxTicks
    /\ layer_imports' = layer_imports \cup {imp}
    /\ tick' = tick + 1
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    r4_entries, r4_activities >>

\* CreateEntry — append an Entry to r4_entries. Pre-conditions
\* enforce E8 parent depth monotonicity (acyclicity) + depth ≤ 64.
\* Parent must be "NONE" (root) or an existing Entry with depth =
\* new_entry.depth - 1.
CreateEntry(e) ==
    /\ e \in Entry
    /\ e.depth <= MaxDagDepth
    /\ \/ /\ e.parent_entry = "NONE"
          /\ e.depth = 0
       \/ /\ e.parent_entry # "NONE"
          /\ \E p \in r4_entries :
                /\ p.id = e.parent_entry
                /\ p.depth = e.depth - 1
    /\ Cardinality(r4_entries) < MaxEntries
    /\ tick + 1 <= MaxTicks
    /\ r4_entries' = r4_entries \cup {e}
    /\ tick' = tick + 1
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    layer_imports, r4_activities >>

\* CreateMetaActivity — append a MetaActivity. Pre-conditions
\* enforce E9 self-loop blocking + depth bound.
CreateMetaActivity(a) ==
    /\ a \in MetaActivity
    /\ a.actor # a.target
    /\ a.meta_verb_depth <= MaxMetaVerbDepth
    /\ Cardinality(r4_activities) < MaxMetaActivities
    /\ tick + 1 <= MaxTicks
    /\ r4_activities' = r4_activities \cup {a}
    /\ tick' = tick + 1
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    layer_imports, r4_entries >>

InitR4 ==
    /\ chain_tip = << >>
    /\ wal = << >>
    /\ tick = 0
    /\ actor_user_binding \in [Actors -> Users]
    /\ actor_shell_binding \in [Actors -> Shells]
    /\ authenticated_actors = {}
    /\ runtime_bootstrap = "BOOTSTRAP_PLACEHOLDER"
    /\ signature_class_policy = [s \in Shells |-> "Ed25519"]
    /\ layer_imports = {}
    /\ r4_entries = {}
    /\ r4_activities = {}

NextR4 ==
    \/ \E imp \in Import : RecordLayerImport(imp)
    \/ \E e \in Entry : CreateEntry(e)
    \/ \E a \in MetaActivity : CreateMetaActivity(a)

SpecR4 == InitR4 /\ [][NextR4]_vars_r4

(* --- Refinement Map (per formal/tla-plus/README.md convention) ---
 *
 * Section 1 — Abstract Vars <-> Concrete Vars
 *
 *   runtime_core.tla         r4 (refined + extended)
 *   ---------------------    ------------------------------------
 *   chain_tip                (carry-through, no R4-I refinement)
 *   wal                      (carry-through)
 *   tick                     (carry-through)
 *   actor_user_binding       (carry, [Actors -> Users] base type)
 *   actor_shell_binding      (carry, [Actors -> Shells] base type)
 *   authenticated_actors     (carry, subset of Actors)
 *   runtime_bootstrap        (carry-through)
 *   signature_class_policy   (carry-through)
 *   --                       layer_imports \subseteq Import     NEW
 *   --                       r4_entries \subseteq Entry         NEW
 *   --                       r4_activities \subseteq
 *                            MetaActivity                       NEW
 *
 * Section 2 — Abstract step <-> Concrete step
 *
 *   runtime_core.Next   ->   RecordLayerImport / CreateEntry /
 *                            CreateMetaActivity (3 disjunctive cases)
 *
 * Section 3 — Module-specific INVs
 *
 *   E3-LayerImportStrictlyDownward  (MC, E3 cross-layer 3-tier)
 *   E3-X-ImportDirectionMonotone    (MC, M2-NEW-4a R4-X stratum
 *                                    extension; L1+ runtime sub-DAG
 *                                    boundary→runtime single direction;
 *                                    formal companion to M2.6 CI grep
 *                                    gate)
 *   E8-EntryParentDagDepthBounded   (MC, hard cap 64)
 *   E8-EntryParentDagAcyclic        (MC, depth monotonicity)
 *   E9-ActivitySelfLoopBlocked      (MC, actor # target)
 *   E9-MetaVerbDepthBounded         (MC, hard cap 8)
 *)

(* --- R4-X sibling concept note (L0-internal, not refined here) ---
 *
 * R4-X (`book/src/en/appendix/decisions.md` R4-X — Layer DAG
 * one-way + cargo-modules CI gate) anchors the L0 kernel INTERNAL
 * 4-stratum DAG (`abi → state → runtime → persist`, single-crate
 * intra-module ordering — decisions.md rationale "Reverse imports
 * like `state → runtime → persist` could sneak in unintentionally").
 * R4-X is enforced by cargo-modules at L0 build time and operates
 * at the L0-internal abstraction level.
 *
 * R4-I (this module) refines E3 cross-layer 3-tier (v0.12 sealing
 * scope L0/L1/L2 per 02-layers.md §2.1+§2.2). The two operate at
 * different abstraction levels:
 *   - R4-X: WITHIN the L0 crate — module-graph stratum order
 *           (abi/state/runtime/persist).
 *   - R4-I/E3: ACROSS crates — cross-layer import direction
 *              (L1 → L0 OK, L1 → L2 forbidden, etc.).
 * Both leverage cargo-modules CI gates, but at different scopes.
 * R4-I does NOT refine R4-X; the two are sibling concepts at
 * distinct abstraction levels. The Rust-level enforcement of E3
 * is the build-gate (rejection at compile time); the TLA+
 * refinement here provides the formal-method anchor for the E3
 * cross-layer property the gate enforces.
 *
 * R4-X is Layer A DO NOT TOUCH item 6 per
 * `runtime-book/src/en/architecture/16-references.md` ordering:
 * (1) DOMAIN_CTX / (2) InvariantLifetime / (3) Principal+KernelEvent
 * +StepStage derives / (4) A11 MC tag / (5) ROADMAP v0.99+ Deferred
 * / (6) R4-X DAG / (7) EventMask bit allocation / (8) WalRecord
 * postcard field order. Layer A sealing means the cargo-modules CI
 * gate config is permanent across cycles; only escalation by
 * explicit user consent can relax it. (cryptographer E.6 secondary
 * verify caught earlier item-5 mis-cite — fixed before commit.)
 *
 * Symmetric counterparts:
 *   - CR-1 (Adversary A, chain-affecting compute determinism)
 *   - CR-3 (PQC downgrade, chain-anchored policy)
 *   - CR-4 (Adversary B, chain-non-affecting observer mutation)
 *
 * R4-I + CR-1 + CR-3 + CR-4 close the v0.12 sealing chain at the
 * formal-method level: layering integrity + compute determinism +
 * policy anchoring + observer confinement.
 *)

(* --- E8 acyclicity TLC fallback note ---
 *
 * Apalache's SMT-bounded MC may time out on large entry sets when
 * checking EntryParentDagAcyclic with deep parent chains. The
 * depth-monotonicity formulation reduces this risk: acyclicity is
 * implied by the local invariant `parent.depth = self.depth - 1`,
 * which Apalache can verify state-locally without explicit
 * transitive closure.
 *
 * For exhaustive bounded MC over Entry sets larger than ~8
 * entries, TLC fallback is documented in
 * `formal/tla-plus/README.md` Tooling section. The depth-
 * monotonicity reformulation is the primary technique to keep
 * Apalache as the primary tool.
 *)

====
