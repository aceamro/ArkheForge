---- MODULE runtime_core ----
(*
 * runtime_core — base module for ArkheKernel Runtime formal verification.
 *
 * DIP-N5 cycle plan Track E sub-step E.1 (scaffold). Declares the abstract
 * state vector + CONSTANTS shared across the CR-1, CR-2, CR-3, CR-4, and
 * R4-I refinement modules. Each refinement module EXTENDs runtime_core
 * and adds its module-specific invariant set.
 *
 * Anchored to runtime-book/src/en/architecture/11-axioms.md (E1-E15).
 * Apalache primary tooling per formal/tla-plus/README.md.
 *)

EXTENDS Naturals, Sequences, FiniteSets

(* --- Apalache type alias bindings (Snowcat strict mode) ---
 *
 * Identifier-set aliases keep Actors / Users / Shells distinct at the
 * type level even though all three concretize to opaque strings. The
 * walRecord alias mirrors cr1's WalRecord refinement so wal can be
 * typed at the base layer (Seq($walRecord)) while EXTENDing modules
 * inherit the structure. chainTip mirrors cr1's ChainTipBytes
 * (Seq(0..255)) so cr1 InitCR1 chain_tip = InitialChainTipBytes
 * typechecks; runtime_core Init seeds chain_tip = << >> (empty bytes)
 * accordingly. bootstrap stays an opaque string placeholder matching
 * runtime_core Init "BOOTSTRAP_PLACEHOLDER"; cr3 declares a separate
 * concrete bootstrap_event variable for the record refinement.
 *)

\* @typeAlias: actor = Str;
ALIAS_actor == TRUE

\* @typeAlias: user = Str;
ALIAS_user == TRUE

\* @typeAlias: shell = Str;
ALIAS_shell == TRUE

\* @typeAlias: signatureClass = Str;
ALIAS_signatureClass == TRUE

\* @typeAlias: walRecord = { seq: Int, tick: Int, payload: Seq(Int) };
ALIAS_walRecord == TRUE

\* @typeAlias: chainTip = Seq(Int);
ALIAS_chainTip == TRUE

\* @typeAlias: bootstrap = Str;
ALIAS_bootstrap == TRUE

CONSTANTS
    \* @type: Set($actor);
    Actors,            \* Actor identifier set (E1 primitive)
    \* @type: Set($user);
    Users,             \* User identifier set (E1 primitive)
    \* @type: Set($shell);
    Shells,            \* Shell identifier set (E7 brand)
    \* @type: Set($signatureClass);
    SignatureClasses,  \* {"Ed25519", "Hybrid"} (E13)
    \* @type: Int;
    MaxTicks,          \* Bounded MC ceiling (Apalache)
    \* @type: Int;
    MaxWalLen          \* Bounded MC ceiling (Apalache)

ASSUME
    /\ Actors # {}
    /\ Users # {}
    /\ Shells # {}
    /\ SignatureClasses = {"Ed25519", "Hybrid"}
    /\ MaxTicks \in Nat \ {0}
    /\ MaxWalLen \in Nat \ {0}

VARIABLES
    \* @type: $chainTip;
    chain_tip,              \* Opaque chain hash (L0 A1 anchor)
    \* @type: Seq($walRecord);
    wal,                    \* Sequence of WalRecord events
    \* @type: Int;
    tick,                   \* Current tick (E11 cascade ordering)
    \* @type: $actor -> $user;
    actor_user_binding,     \* Actor -> User mapping (E5 immutability)
    \* @type: $actor -> $shell;
    actor_shell_binding,    \* Actor -> Shell mapping (E5 immutability)
    \* @type: Set($actor);
    authenticated_actors,   \* Set of Actor<S, Authenticated> (E6)
    \* @type: $bootstrap;
    runtime_bootstrap,      \* Most recent RuntimeBootstrap event (E12)
    \* @type: $shell -> $signatureClass;
    signature_class_policy  \* Per-shell SignatureClassPolicy snapshot (E13)

vars == << chain_tip, wal, tick,
           actor_user_binding, actor_shell_binding, authenticated_actors,
           runtime_bootstrap, signature_class_policy >>

(* --- Type invariant (Apalache type-check anchor) --- *)
TypeOK ==
    /\ tick \in 0..MaxTicks
    /\ Len(wal) <= MaxWalLen
    /\ actor_user_binding \in [Actors -> Users]
    /\ actor_shell_binding \in [Actors -> Shells]
    /\ authenticated_actors \subseteq Actors
    /\ signature_class_policy \in [Shells -> SignatureClasses]

(* --- Abstract state machine frame --- *)
Init ==
    /\ chain_tip = << >>
    /\ wal = << >>
    /\ tick = 0
    /\ actor_user_binding \in [Actors -> Users]
    /\ actor_shell_binding \in [Actors -> Shells]
    /\ authenticated_actors = {}
    /\ runtime_bootstrap = "BOOTSTRAP_PLACEHOLDER"
    /\ signature_class_policy = [s \in Shells |-> "Ed25519"]

\* Abstract step — refinement modules concretize specific transitions
\* (e.g., RuntimeBootstrapEmit, AuthenticateActor, AppendWal,
\* CascadeReSubmit, ObserverNominalStep, ObserverPanicTransition).
Next ==
    /\ tick' = tick + 1
    /\ tick + 1 <= MaxTicks
    /\ Len(wal) < MaxWalLen
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy >>

Spec == Init /\ [][Next]_vars

(* --- Refinement Map placeholder ---
 *
 * Each refinement module (cr1 / cr2 / cr3 / cr4 / r4i) declares:
 *   (1) Abstract Vars <-> Concrete Vars mapping
 *   (2) Abstract step <-> Concrete step refinement predicate
 *   (3) Module-specific INVs (sealed-completeness chain anchors)
 *
 * Apalache type-checker verifies the mapping's type-soundness at
 * `apalache-mc typecheck` time.
 *
 * See formal/tla-plus/README.md for the E1-E15 <-> TLA+ INV mapping
 * table and the Adversary A/B residual reduction lemma anchors.
 *)

====
