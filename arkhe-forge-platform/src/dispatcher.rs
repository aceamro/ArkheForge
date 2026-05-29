//! L2 service layer — drives forge actions through the kernel's
//! authorize → dispatch → WAL append loop.
//!
//! `RuntimeService` wraps a [`Kernel`] (with WAL) and exposes a single
//! `dispatch` method that takes a forge `ArkheAction`, postcard-encodes
//! its canonical bytes, calls [`Kernel::submit`] + [`Kernel::step`] in
//! one shot, and returns the kernel's `StepReport`. The kernel handles
//! the L0 work — authorization, dispatch, WAL append — internally.
//!
//! Forge actions are made kernel-compatible by the
//! `arkhe-forge-macros::ArkheAction` derive: it emits both the
//! forge-side sealed-trait stack **and** the kernel-side `Sealed +
//! ActionDeriv + ActionCompute` stack, with the kernel-side
//! `ActionCompute::compute` body delegating to
//! `arkhe_forge_core::bridge::kernel_compute`. The bridge runs the
//! forge `compute()` on a fresh forge `ActionContext` and returns the
//! drained `Vec<Op>` to the kernel.
//!
//! ## WAL export
//!
//! After one or more `dispatch` calls, the caller may extract the
//! kernel's internal WAL via [`RuntimeService::export_wal`] (consumes
//! the service). Each [`arkhe_kernel::WalRecord`] in the returned
//! [`arkhe_kernel::Wal`] can be streamed into a
//! [`crate::wal_export::BufferedWalSink`] via [`wal_to_sink`] for
//! durable backup; the sink frames each record
//! with the standard magic + length-prefix shape per the firm
//! requirements pinned in `wal_export`.
//!
//! ## Current scope
//!
//! Manifest-driven authz policy, the PG-UNIQUE-INDEX-backed
//! idempotency dedup, and full
//! [`ActorHandleIndex`](arkhe_forge_core::context::ActorHandleIndex)
//! production paths are not yet wired through `RuntimeService` — a
//! forge action's idempotency / actor-handle paths run with the L1
//! defaults (no view, no index). Callers who need those layers attach
//! them through the forge `ActionContext` builder directly while the
//! L2 layer matures.

use arkhe_forge_core::action::GdprGuard;
use arkhe_forge_core::actor::ActorId;
use arkhe_forge_core::context::{ActionContext, ActionError};
use arkhe_forge_core::user::UserId;
use arkhe_kernel::abi::{ArkheError, CapabilityMask, InstanceId, Principal, Tick};
use arkhe_kernel::state::traits::Action;
use arkhe_kernel::state::InstanceConfig;
use arkhe_kernel::{Kernel, StepReport, Wal};

use crate::wal_export::{BufferedWalSink, WalExportError, WalRecordSink};

/// Error surface for [`RuntimeService::dispatch`].
///
/// `dispatch` is forge's own maturing L2 API, so it returns this richer
/// enum rather than the kernel's [`ArkheError`] directly: the GDPR
/// `ErasurePending` admission gate (C3) is an L2 concern with no kernel
/// error variant, so it is surfaced as its own arm. Kernel-level errors
/// pass through [`DispatchError::Kernel`] unchanged.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DispatchError {
    /// Kernel-side error from `submit` / `step` (e.g. `InstanceNotFound`).
    #[error("kernel error: {0}")]
    Kernel(#[from] ArkheError),

    /// The action's wire-supplied actor (`GdprGuard::gdpr_actor`) does not
    /// match the caller identity the auth layer above forge authenticated.
    /// Forge refuses the action before `submit` so a wire-controlled actor
    /// field cannot be substituted to attack a different user's scope
    /// (closes the C3 actor-substitution bypass). `authenticated == None`
    /// means the caller was unauthenticated / system but the action claims
    /// a user-scoped actor — also a mismatch.
    #[error(
        "actor mismatch: action claims {claimed:?}, caller authenticated as {authenticated:?}"
    )]
    ActorMismatch {
        /// Actor the action's wire payload claims to act as.
        claimed: ActorId,
        /// Actor the auth layer authenticated for this caller (`None` =
        /// unauthenticated / system caller).
        authenticated: Option<ActorId>,
    },

    /// L2 admission gate rejected the action: the actor's backing user is
    /// in `GdprStatus::ErasurePending`, so the action is refused before it
    /// reaches the WAL (E-user-3 C3 — admission control at the L2 boundary).
    #[error("user erasure pending: {user:?} scheduled at {tick:?}")]
    ErasurePending {
        /// Backing user whose erasure is in flight.
        user: UserId,
        /// Tick at which the action was attempted.
        tick: Tick,
    },

    /// The admission-gate probe read corrupt view bytes while resolving the
    /// actor's `UserBinding` / `UserProfile`. Fail closed rather than admit.
    #[error("GDPR admission probe failed: corrupt view state")]
    ProbeViewCorrupt,
}

/// Errors surfaced by [`wal_to_sink`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WalSinkError {
    /// `WalRecord` failed postcard encoding (should be unreachable —
    /// `WalRecord` is `derive(Serialize)` on a stable wire shape).
    #[error("WalRecord postcard encode failed: {0}")]
    Encode(#[from] postcard::Error),
    /// Sink rejected the framed record (length / append-only / overflow).
    #[error("BufferedWalSink rejected record: {0}")]
    Sink(#[from] WalExportError),
}

/// Service-layer wrapper around [`arkhe_kernel::Kernel`]. Builds a
/// kernel with WAL configured and exposes a forge-shaped dispatch API.
pub struct RuntimeService {
    kernel: Kernel,
}

impl RuntimeService {
    /// Construct a service backed by a chain-only WAL writer (L0
    /// `SignatureClass::None`). `world_id` and `manifest_digest` are
    /// pinned into the WAL header.
    #[must_use]
    pub fn new(world_id: [u8; 32], manifest_digest: [u8; 32]) -> Self {
        Self {
            kernel: Kernel::new_with_wal(world_id, manifest_digest),
        }
    }

    /// Register a forge `ArkheAction` so the kernel will execute it
    /// when scheduled. Any forge action whose type bears
    /// `#[derive(ArkheAction)]` automatically satisfies the kernel
    /// [`Action`] bound through the derive's emitted kernel-side
    /// stack.
    pub fn register_action<A: Action>(&mut self) {
        self.kernel.register_action::<A>();
    }

    /// Create a fresh kernel instance and return its `InstanceId`.
    pub fn create_instance(&mut self, config: InstanceConfig) -> InstanceId {
        self.kernel.create_instance(config)
    }

    /// Dispatch a forge action — authenticate the actor against the caller,
    /// run the L2 GDPR admission gate, postcard-encode its canonical bytes,
    /// submit at tick `at`, then step the kernel once with `caps`. Returns
    /// the kernel's `StepReport` so the caller can inspect `actions_executed`
    /// / `effects_applied` / `effects_denied`.
    ///
    /// ## Caller authentication contract
    ///
    /// `authenticated_actor` is the caller identity the integrator's
    /// auth / session layer (which sits ABOVE forge) has already verified —
    /// e.g. resolved from a login session, bearer token, or passkey
    /// assertion. `None` denotes a system / anonymous caller with no
    /// authenticated actor.
    ///
    /// Forge does NOT resolve a kernel `Principal` to an
    /// [`ActorId`] — that binding (`External(ExternalId)` ↔ `ActorId`)
    /// belongs to the auth layer. What forge ENFORCES is the converse: a
    /// user-scoped action (one whose [`GdprGuard::gdpr_actor`] returns
    /// `Some`) carries a *wire-controlled* actor field
    /// (`CreateSpace.config.creator`, `SubmitActivity.record.actor`, …).
    /// Before any further processing, `dispatch` requires that claimed
    /// actor to equal `authenticated_actor`; otherwise it rejects with
    /// [`DispatchError::ActorMismatch`] before `submit`. This closes the
    /// C3 actor-substitution bypass: an attacker can no longer set the
    /// wire actor to a victim's `ActorId` and have forge treat the action
    /// as that victim's. A non-user-scoped / system action
    /// (`gdpr_actor() == None`) skips the check and ignores
    /// `authenticated_actor`.
    ///
    /// ## GDPR `ErasurePending` admission gate (C3)
    ///
    /// The kernel `compute` path drives a forge action through a viewless
    /// [`ActionContext`] (see [`arkhe_forge_core::bridge`]), so the
    /// in-compute `ensure_actor_eligible` check soft-passes — it cannot
    /// read the actor's `UserBinding` / `UserProfile` without a bound
    /// view. This method closes that gap at the L2 boundary: once the
    /// actor-authentication check above has passed (so the actor is the
    /// verified caller, not a wire substitution), the service binds a
    /// fresh `InstanceView`, runs the existing `ensure_actor_eligible`
    /// logic on that verified actor, and REJECTS the action before
    /// `submit` if the backing user is `ErasurePending`. The gate is
    /// SOUND — the actor it gates on is the authenticated caller, so
    /// actor-substitution cannot bypass it. Its LIVENESS, however, depends
    /// on a production path transitioning the profile to `ErasurePending`;
    /// today none does — the L2 erasure cascade has no write channel into
    /// the kernel-stored `UserProfile` — so the gate is sound-but-inert in
    /// production (a tracked limitation). When the status IS set, the
    /// action is rejected before `submit` (never reaches the WAL), as this
    /// method's tests demonstrate.
    ///
    /// # Errors
    ///
    /// * [`DispatchError::ActorMismatch`] — the action's wire actor does
    ///   not match `authenticated_actor` (actor-substitution rejected).
    /// * [`DispatchError::ErasurePending`] — the L2 gate rejected the
    ///   action (backing user in `GdprStatus::ErasurePending`).
    /// * [`DispatchError::Kernel`] — kernel-side error from `submit`
    ///   (`InstanceNotFound` if `instance` is not live). Capability denial
    ///   happens inside `step` and is reflected in the returned report's
    ///   `effects_denied` count rather than as an `Err`.
    pub fn dispatch<A>(
        &mut self,
        instance: InstanceId,
        principal: Principal,
        action: &A,
        at: Tick,
        caps: CapabilityMask,
        authenticated_actor: Option<ActorId>,
    ) -> Result<StepReport, DispatchError>
    where
        A: Action + GdprGuard,
    {
        // Actor authentication — runs BEFORE the erasure gate so the gate
        // only ever evaluates a caller-verified actor. A user-scoped
        // action's wire actor (`gdpr_actor()`) must equal the actor the
        // auth layer authenticated for this caller; otherwise the action
        // is a substitution attempt and is refused before `submit`.
        if let Some(claimed) = action.gdpr_actor() {
            match authenticated_actor {
                Some(auth) if auth == claimed => { /* authenticated as the claimed actor — proceed */
                }
                _ => {
                    return Err(DispatchError::ActorMismatch {
                        claimed,
                        authenticated: authenticated_actor,
                    })
                }
            }

            // L2 admission gate (C3) — runs on the now-verified actor,
            // BEFORE submit, with the view dropped before the
            // `&mut self.kernel` step call. Reuses the forge-core in-compute
            // eligibility check; the probe context is read-only (zero
            // world_seed, no Op emission).
            let view = self
                .kernel
                .instance_view(instance)
                .ok_or(ArkheError::InstanceNotFound)?;
            let probe = ActionContext::new([0u8; 32], instance, at, principal.clone(), caps)
                .with_view(&view);
            if let Err(err) = probe.ensure_actor_eligible(claimed, at) {
                return match err {
                    ActionError::UserErasurePending { user, .. } => {
                        Err(DispatchError::ErasurePending { user, tick: at })
                    }
                    // `ensure_actor_eligible` otherwise only fails with an
                    // `InvalidInput` on corrupt view bytes; fail closed.
                    _ => Err(DispatchError::ProbeViewCorrupt),
                };
            }
        }

        let bytes = action.canonical_bytes();
        self.kernel
            .submit(instance, principal, None, at, A::TYPE_CODE, bytes)?;
        Ok(self.kernel.step(at, caps))
    }

    /// Drain the kernel's internal WAL (consumes the service so the
    /// kernel cannot continue stepping after export).
    #[must_use]
    pub fn export_wal(self) -> Option<Wal> {
        self.kernel.export_wal()
    }
}

/// Append every record of `wal` into the buffered sink, then flush.
/// Each record is postcard-serialized via the kernel's stable
/// [`arkhe_kernel::WalRecord`] wire shape (DO NOT TOUCH #7 —
/// `seq: u64` first declared field) and the sink frames with the
/// standard magic + length-prefix per `wal_export`'s firm
/// requirements.
///
/// # Errors
///
/// Returns [`WalSinkError::Encode`] if a record fails postcard
/// serialization (unreachable in practice — `WalRecord` derives
/// `Serialize` over a stable shape) or [`WalSinkError::Sink`] if the
/// sink rejects the framed record (length, append-only, overflow).
pub fn wal_to_sink<W: std::io::Write>(
    wal: &Wal,
    sink: &mut BufferedWalSink<W>,
) -> Result<(), WalSinkError> {
    for record in &wal.records {
        let bytes = postcard::to_allocvec(record)?;
        sink.append_record(&bytes)?;
    }
    sink.flush()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use arkhe_kernel::abi::{Principal, Tick};

    /// Smoke — `RuntimeService::new` returns a service whose underlying
    /// kernel reports zero records (the WAL header has been pinned but
    /// no `step` has fired yet).
    #[test]
    fn fresh_service_has_zero_wal_records() {
        let svc = RuntimeService::new([0x11u8; 32], [0x22u8; 32]);
        assert_eq!(svc.kernel.wal_record_count(), Some(0));
    }

    /// `create_instance` increments the kernel's instance count.
    #[test]
    fn create_instance_grows_kernel() {
        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        let _id = svc.create_instance(InstanceConfig::default());
        assert_eq!(svc.kernel.instances_len(), 1);
    }

    /// `dispatch` returns `InstanceNotFound` for an unregistered
    /// instance — verifies the `Result` plumbing without needing a
    /// concrete forge action in the platform-crate test scope (forge
    /// actions live in forge-core and downstream crates).
    #[test]
    fn dispatch_unknown_instance_returns_instance_not_found() {
        // Use a dummy kernel-Action via the kernel's own derive —
        // platform crate sees only kernel surface, no forge-core dep
        // in test scope (avoids cross-crate test churn).
        use arkhe_kernel::abi::EntityId;
        use arkhe_kernel::state::{ActionCompute, ActionContext, Op};
        use arkhe_kernel::ArkheAction;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, ArkheAction)]
        #[arkhe(type_code = 0x0001_5101, schema_version = 1)]
        struct NoopAction;

        impl ActionCompute for NoopAction {
            fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> {
                vec![Op::SpawnEntity {
                    id: EntityId::new(1).unwrap(),
                    owner: Principal::System,
                }]
            }
        }
        impl GdprGuard for NoopAction {}

        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc.register_action::<NoopAction>();
        // No `create_instance` call — InstanceId(99) is not live.
        let bogus = InstanceId::new(99).unwrap();
        let result = svc.dispatch(
            bogus,
            Principal::System,
            &NoopAction,
            Tick(1),
            CapabilityMask::SYSTEM,
            None,
        );
        assert!(matches!(
            result,
            Err(DispatchError::Kernel(ArkheError::InstanceNotFound))
        ));
    }

    /// Happy-path dispatch — register → create_instance → dispatch
    /// returns `Ok(StepReport)` with `actions_executed = 1`.
    #[test]
    fn dispatch_happy_path_executes_one_action() {
        use arkhe_kernel::abi::EntityId;
        use arkhe_kernel::state::{ActionCompute, ActionContext, Op};
        use arkhe_kernel::ArkheAction;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, ArkheAction)]
        #[arkhe(type_code = 0x0001_5102, schema_version = 1)]
        struct SpawnOne;

        impl ActionCompute for SpawnOne {
            fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> {
                vec![Op::SpawnEntity {
                    id: EntityId::new(1).unwrap(),
                    owner: Principal::System,
                }]
            }
        }
        impl GdprGuard for SpawnOne {}

        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc.register_action::<SpawnOne>();
        let inst = svc.create_instance(InstanceConfig::default());
        let report = svc
            .dispatch(
                inst,
                Principal::System,
                &SpawnOne,
                Tick(0),
                CapabilityMask::SYSTEM,
                None,
            )
            .expect("dispatch must succeed for live instance");
        assert_eq!(report.actions_executed, 1);
        assert_eq!(report.effects_applied, 1);
        assert_eq!(report.effects_denied, 0);
    }

    /// `wal_to_sink` round-trips: dispatch one action, export WAL,
    /// stream into `BufferedWalSink<Vec<u8>>` — sink buffer ends up
    /// non-empty + starts with the stream-header magic.
    #[test]
    fn wal_to_sink_round_trips_single_record() {
        use arkhe_kernel::abi::EntityId;
        use arkhe_kernel::state::{ActionCompute, ActionContext, Op};
        use arkhe_kernel::ArkheAction;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, ArkheAction)]
        #[arkhe(type_code = 0x0001_5103, schema_version = 1)]
        struct SpawnOne;

        impl ActionCompute for SpawnOne {
            fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> {
                vec![Op::SpawnEntity {
                    id: EntityId::new(1).unwrap(),
                    owner: Principal::System,
                }]
            }
        }
        impl GdprGuard for SpawnOne {}

        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc.register_action::<SpawnOne>();
        let inst = svc.create_instance(InstanceConfig::default());
        let _ = svc
            .dispatch(
                inst,
                Principal::System,
                &SpawnOne,
                Tick(0),
                CapabilityMask::SYSTEM,
                None,
            )
            .unwrap();

        let wal = svc.export_wal().expect("WAL is configured");
        assert_eq!(wal.records.len(), 1);

        let mut buffer: Vec<u8> = Vec::new();
        let mut sink = BufferedWalSink::new(&mut buffer);
        wal_to_sink(&wal, &mut sink).expect("wal_to_sink must succeed");
        // After flush the sink's internal buffer is empty; the writer
        // (our `&mut buffer`) carries the bytes.
        assert!(!buffer.is_empty(), "sink writer must hold framed bytes");
        assert!(
            buffer.starts_with(&crate::wal_export::STREAM_HEADER_MAGIC),
            "sink stream must begin with ARKHEXP1 magic",
        );
    }

    /// Multi-record dispatch + export: 3 ticks × 1 action each → 3
    /// WAL records; `wal_to_sink` frames all three.
    #[test]
    fn wal_to_sink_handles_multi_record_stream() {
        use arkhe_kernel::abi::EntityId;
        use arkhe_kernel::state::{ActionCompute, ActionContext, Op};
        use arkhe_kernel::ArkheAction;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, ArkheAction)]
        #[arkhe(type_code = 0x0001_5104, schema_version = 1)]
        struct SpawnAt(u64);

        impl ActionCompute for SpawnAt {
            fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> {
                vec![Op::SpawnEntity {
                    id: EntityId::new(self.0.max(1)).unwrap(),
                    owner: Principal::System,
                }]
            }
        }
        impl GdprGuard for SpawnAt {}

        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc.register_action::<SpawnAt>();
        let inst = svc.create_instance(InstanceConfig::default());
        for i in 1..=3 {
            svc.dispatch(
                inst,
                Principal::System,
                &SpawnAt(i),
                Tick(i),
                CapabilityMask::SYSTEM,
                None,
            )
            .unwrap();
        }
        let wal = svc.export_wal().expect("WAL configured");
        assert_eq!(wal.records.len(), 3);

        let mut buffer: Vec<u8> = Vec::new();
        let mut sink = BufferedWalSink::new(&mut buffer);
        wal_to_sink(&wal, &mut sink).unwrap();
        assert!(!buffer.is_empty());
        assert!(buffer.starts_with(&crate::wal_export::STREAM_HEADER_MAGIC));
    }

    /// End-to-end proof of the #2 L2 GDPR admission gate.
    ///
    /// A test-only seeding action writes a `UserBinding` (actor → user) plus a
    /// `UserProfile { gdpr_status }` into a live kernel instance so the
    /// `InstanceView` the gate reads is populated. A real forge `CreateSpace`
    /// for an `ErasurePending` user is then REJECTED at dispatch (no WAL
    /// record), while the same action for an `Active` user proceeds and
    /// appends a record. This exercises the full
    /// `RuntimeService::dispatch -> gdpr_actor -> instance_view ->
    /// ensure_actor_eligible` path that the viewless bridge cannot cover.
    #[test]
    fn dispatch_rejects_erasure_pending_actor_before_wal() {
        use arkhe_forge_core::actor::{ActorId, UserBinding};
        use arkhe_forge_core::brand::ShellId;
        use arkhe_forge_core::component::{ArkheComponent, BoundedString};
        use arkhe_forge_core::space::{CreateSpace, SpaceConfig, SpaceKind, Visibility};
        use arkhe_forge_core::user::{AuthKind, GdprStatus, UserId, UserProfile};
        use arkhe_kernel::abi::{EntityId, TypeCode};
        use arkhe_kernel::state::{ActionCompute, ActionContext, Op};
        use arkhe_kernel::ArkheAction;
        use serde::{Deserialize, Serialize};

        // Test-only kernel action: stage `UserBinding` on the actor entity and
        // `UserProfile` on the user entity so the gate's `InstanceView` reads
        // are populated. Carries the desired GDPR status as a wire byte.
        #[derive(Serialize, Deserialize, ArkheAction)]
        #[arkhe(type_code = 0x0001_5105, schema_version = 1)]
        struct SeedBinding {
            actor: u64,
            user: u64,
            erasing: bool,
        }

        impl ActionCompute for SeedBinding {
            fn compute(&self, _ctx: &ActionContext<'_>) -> Vec<Op> {
                let binding = UserBinding {
                    schema_version: 1,
                    user_id: UserId::new(EntityId::new(self.user).unwrap()),
                };
                let profile = UserProfile {
                    schema_version: 1,
                    created_tick: Tick(0),
                    primary_auth_kind: AuthKind::Passkey,
                    gdpr_status: if self.erasing {
                        GdprStatus::ErasurePending
                    } else {
                        GdprStatus::Active
                    },
                };
                let bb = postcard::to_allocvec(&binding).unwrap();
                let pb = postcard::to_allocvec(&profile).unwrap();
                vec![
                    Op::SetComponent {
                        entity: EntityId::new(self.actor).unwrap(),
                        type_code: TypeCode(UserBinding::TYPE_CODE),
                        size: bb.len() as u64,
                        bytes: bytes::Bytes::from(bb),
                    },
                    Op::SetComponent {
                        entity: EntityId::new(self.user).unwrap(),
                        type_code: TypeCode(UserProfile::TYPE_CODE),
                        size: pb.len() as u64,
                        bytes: bytes::Bytes::from(pb),
                    },
                ]
            }
        }
        impl GdprGuard for SeedBinding {}

        fn create_space(actor: ActorId) -> CreateSpace {
            CreateSpace {
                schema_version: 1,
                config: SpaceConfig {
                    schema_version: 1,
                    shell_id: ShellId([0xC3; 16]),
                    slug: BoundedString::<32>::new("forbidden").unwrap(),
                    kind: SpaceKind::Flat,
                    visibility: Visibility::Public,
                    creator: actor,
                    parent_space: None,
                    created_tick: Tick(100),
                },
            }
        }

        // --- ErasurePending user is rejected, no WAL record ---
        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc.register_action::<SeedBinding>();
        svc.register_action::<CreateSpace>();
        let inst = svc.create_instance(InstanceConfig::default());

        svc.dispatch(
            inst,
            Principal::System,
            &SeedBinding {
                actor: 8,
                user: 7,
                erasing: true,
            },
            Tick(1),
            CapabilityMask::SYSTEM,
            None,
        )
        .expect("seed must succeed");
        let after_seed = svc.kernel.wal_record_count();
        assert_eq!(after_seed, Some(1), "seed action appends one record");

        // Authenticated as actor 8 — passes the auth gate, then the
        // erasure gate rejects because actor 8's user is ErasurePending.
        let rejected = svc.dispatch(
            inst,
            Principal::System,
            &create_space(ActorId::new(EntityId::new(8).unwrap())),
            Tick(2),
            CapabilityMask::SYSTEM,
            Some(ActorId::new(EntityId::new(8).unwrap())),
        );
        match rejected {
            Err(DispatchError::ErasurePending { user, tick }) => {
                assert_eq!(user, UserId::new(EntityId::new(7).unwrap()));
                assert_eq!(tick, Tick(2));
            }
            other => panic!("expected ErasurePending rejection, got {:?}", other),
        }
        assert_eq!(
            svc.kernel.wal_record_count(),
            Some(1),
            "rejected action must NOT append a WAL record",
        );

        // --- Active user proceeds and appends a record ---
        let mut svc2 = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc2.register_action::<SeedBinding>();
        svc2.register_action::<CreateSpace>();
        let inst2 = svc2.create_instance(InstanceConfig::default());
        svc2.dispatch(
            inst2,
            Principal::System,
            &SeedBinding {
                actor: 8,
                user: 7,
                erasing: false,
            },
            Tick(1),
            CapabilityMask::SYSTEM,
            None,
        )
        .expect("seed must succeed");
        let report = svc2
            .dispatch(
                inst2,
                Principal::System,
                &create_space(ActorId::new(EntityId::new(8).unwrap())),
                Tick(2),
                CapabilityMask::SYSTEM,
                Some(ActorId::new(EntityId::new(8).unwrap())),
            )
            .expect("Active user must proceed");
        assert_eq!(report.actions_executed, 1);
        assert_eq!(
            svc2.kernel.wal_record_count(),
            Some(2),
            "Active-user action appends a second WAL record",
        );
    }

    // ---------- #1 actor-authentication enforcement (HIGH fix) ----------

    use arkhe_forge_core::actor::ActorId;
    use arkhe_forge_core::brand::ShellId;
    use arkhe_forge_core::component::BoundedString;
    use arkhe_forge_core::space::{CreateSpace, SpaceConfig, SpaceKind, Visibility};
    use arkhe_kernel::abi::EntityId;

    /// Build a user-scoped `CreateSpace` whose wire actor (the C3 gate key)
    /// is `creator`.
    fn create_space_by(creator: ActorId) -> CreateSpace {
        CreateSpace {
            schema_version: 1,
            config: SpaceConfig {
                schema_version: 1,
                shell_id: ShellId([0xC3; 16]),
                slug: BoundedString::<32>::new("space").unwrap(),
                kind: SpaceKind::Flat,
                visibility: Visibility::Public,
                creator,
                parent_space: None,
                created_tick: Tick(100),
            },
        }
    }

    fn actor(id: u64) -> ActorId {
        ActorId::new(EntityId::new(id).unwrap())
    }

    /// A user-scoped action whose wire actor != the authenticated caller is
    /// rejected with `ActorMismatch` and never reaches the WAL. This is the
    /// actor-substitution attack the HIGH finding describes: the wire field
    /// `config.creator` claims a victim actor while the caller is someone
    /// else.
    #[test]
    fn dispatch_rejects_actor_substitution() {
        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc.register_action::<CreateSpace>();
        let inst = svc.create_instance(InstanceConfig::default());

        // Wire claims actor 7 (victim); caller authenticated as actor 9.
        let result = svc.dispatch(
            inst,
            Principal::System,
            &create_space_by(actor(7)),
            Tick(1),
            CapabilityMask::SYSTEM,
            Some(actor(9)),
        );
        match result {
            Err(DispatchError::ActorMismatch {
                claimed,
                authenticated,
            }) => {
                assert_eq!(claimed, actor(7));
                assert_eq!(authenticated, Some(actor(9)));
            }
            other => panic!("expected ActorMismatch, got {other:?}"),
        }
        assert_eq!(
            svc.kernel.wal_record_count(),
            Some(0),
            "substituted-actor action must NOT be submitted",
        );
    }

    /// A user-scoped action dispatched with no authenticated actor
    /// (`authenticated_actor = None`, i.e. an unauthenticated / system
    /// caller) is rejected — a user-scoped action requires an
    /// authenticated caller equal to its claimed actor.
    #[test]
    fn dispatch_rejects_unauthenticated_user_action() {
        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc.register_action::<CreateSpace>();
        let inst = svc.create_instance(InstanceConfig::default());

        let result = svc.dispatch(
            inst,
            Principal::System,
            &create_space_by(actor(7)),
            Tick(1),
            CapabilityMask::SYSTEM,
            None,
        );
        match result {
            Err(DispatchError::ActorMismatch {
                claimed,
                authenticated,
            }) => {
                assert_eq!(claimed, actor(7));
                assert_eq!(authenticated, None);
            }
            other => panic!("expected ActorMismatch, got {other:?}"),
        }
        assert_eq!(
            svc.kernel.wal_record_count(),
            Some(0),
            "unauthenticated user-scoped action must NOT be submitted",
        );
    }

    /// A user-scoped action whose wire actor equals the authenticated
    /// caller passes the auth gate and (for an `Active` / unknown user)
    /// proceeds to the WAL.
    #[test]
    fn dispatch_allows_matching_actor() {
        let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
        svc.register_action::<CreateSpace>();
        let inst = svc.create_instance(InstanceConfig::default());

        // No `UserBinding` seeded → the erasure gate soft-passes (Ok(None)),
        // so a matching actor proceeds.
        let report = svc
            .dispatch(
                inst,
                Principal::System,
                &create_space_by(actor(7)),
                Tick(1),
                CapabilityMask::SYSTEM,
                Some(actor(7)),
            )
            .expect("matching actor must proceed");
        assert_eq!(report.actions_executed, 1);
        assert_eq!(
            svc.kernel.wal_record_count(),
            Some(1),
            "matching-actor action appends a WAL record",
        );
    }
}
