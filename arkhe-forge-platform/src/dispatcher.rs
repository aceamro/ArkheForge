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

use arkhe_kernel::abi::{ArkheError, CapabilityMask, InstanceId, Principal, Tick};
use arkhe_kernel::state::traits::Action;
use arkhe_kernel::state::InstanceConfig;
use arkhe_kernel::{Kernel, StepReport, Wal};

use crate::wal_export::{BufferedWalSink, WalExportError, WalRecordSink};

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

    /// Dispatch a forge action — postcard-encode its canonical bytes,
    /// submit at tick `at`, then step the kernel once with `caps`.
    /// Returns the kernel's `StepReport` so the caller can inspect
    /// `actions_executed` / `effects_applied` / `effects_denied`.
    ///
    /// # Errors
    ///
    /// Returns the kernel's [`ArkheError`] surface verbatim. The
    /// most common case is `InstanceNotFound` if `instance` is not
    /// live; capability denial happens inside `step` and is reflected
    /// in the returned report's `effects_denied` count rather than as
    /// an `Err` from this function.
    pub fn dispatch<A>(
        &mut self,
        instance: InstanceId,
        principal: Principal,
        action: &A,
        at: Tick,
        caps: CapabilityMask,
    ) -> Result<StepReport, ArkheError>
    where
        A: Action,
    {
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
        );
        assert!(matches!(result, Err(ArkheError::InstanceNotFound)));
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
}
