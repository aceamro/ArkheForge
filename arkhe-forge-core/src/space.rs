//! Space primitive — container / scope.

use std::collections::BTreeSet;

use arkhe_kernel::abi::{EntityId, Tick, TypeCode};
use serde::{Deserialize, Serialize};

use crate::action::ActionCompute;
use crate::actor::ActorId;
use crate::brand::ShellId;
use crate::component::BoundedString;
use crate::context::{ActionContext, ActionError};
use crate::ArkheAction;
use crate::ArkheComponent;
// E14.L1-Deny enforcement on Action::compute.
use crate::arkhe_pure;

/// Opaque handle into the runtime Space namespace.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpaceId(EntityId);

impl SpaceId {
    /// Construct a `SpaceId` from a runtime-allocated `EntityId`. Callers
    /// must hold proof (spawn event, admin scope, or test fixture) that the
    /// id belongs to the Space namespace — this constructor does not verify.
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

/// Space structural kind. `Extension` is an escape hatch — shell manifest must
/// register the `type_code` with a `schema_hash` pin (E-space-6 / A15).
///
/// On-wire tag is the postcard VARIANT INDEX (0..N in declaration order), not
/// the `repr(u8)` discriminant — the explicit `= 255` is a C-ABI hint, never
/// the serialized byte.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SpaceKind {
    /// Flat list (e.g. BBS board).
    Flat = 0,
    /// Tree (e.g. nested comments).
    Tree = 1,
    /// Graph (e.g. follow graph).
    Graph = 2,
    /// Hashtag aggregation.
    Hashtag = 3,
    /// Per-actor feed.
    ActorFeed = 4,
    /// Shell-defined extension kind.
    Extension {
        /// Extension dispatch code.
        type_code: TypeCode,
    } = 255,
}

/// Visibility policy for Space contents.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Visibility {
    /// World-readable.
    Public = 0,
    /// Restricted by L2 role-check.
    RestrictedByRole = 1,
    /// Readable by subscribers only.
    SubscribersOnly = 2,
    /// Private invitation list (see `SpaceMembership`).
    PrivateInvite = 3,
    /// End-to-end encrypted.
    Encrypted = 4,
}

/// Space configuration Component — exactly one per Space (E-space-1).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0201, schema_version = 1)]
pub struct SpaceConfig {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Shell identity — immutable.
    pub shell_id: ShellId,
    /// URL-safe slug — unique within shell.
    pub slug: BoundedString<32>,
    /// Structural kind.
    pub kind: SpaceKind,
    /// Visibility policy.
    pub visibility: Visibility,
    /// Creating actor (must be in same shell — E-space-5).
    pub creator: ActorId,
    /// Parent Space in the DAG. Immutable after creation (E-space-7 / P5).
    pub parent_space: Option<SpaceId>,
    /// Creation tick.
    pub created_tick: Tick,
}

/// Cached parent-chain depth — enables O(1) cycle / depth check (E-space-4).
/// Monotone, computed from parent's `depth + 1` at spawn.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0202, schema_version = 1)]
pub struct ParentChainDepth {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Depth (0 = root, max [`MAX_SPACE_DEPTH`]).
    pub depth: u8,
}

/// Membership list for `Visibility::PrivateInvite` Spaces (X3 DM support).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 0x0003_0203, schema_version = 1)]
pub struct SpaceMembership {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Permitted actor set — canonical `BTreeSet` ordering for deterministic
    /// serialization.
    pub members: BTreeSet<ActorId>,
}

/// Wire-format Space configuration MINUS the creating actor. The creator is
/// NOT a wire field: the runtime injects the authenticated identity at the
/// dispatch boundary, and [`CreateSpace::compute`] stamps it into the stored
/// [`SpaceConfig`]. This is the structural close of the actor-substitution
/// surface — there is no client-supplied `creator` to spoof.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpaceConfigDraft {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Shell identity — immutable.
    pub shell_id: ShellId,
    /// URL-safe slug — unique within shell.
    pub slug: BoundedString<32>,
    /// Structural kind.
    pub kind: SpaceKind,
    /// Visibility policy.
    pub visibility: Visibility,
    /// Parent Space in the DAG. Immutable after creation (E-space-7 / P5).
    pub parent_space: Option<SpaceId>,
    /// Creation tick.
    pub created_tick: Tick,
}

impl SpaceConfigDraft {
    /// Promote a draft to a stored [`SpaceConfig`] by stamping the
    /// authenticated `creator` — the single source of truth injected by the
    /// runtime, never a wire field.
    #[must_use]
    fn into_config(self, creator: ActorId) -> SpaceConfig {
        SpaceConfig {
            schema_version: self.schema_version,
            shell_id: self.shell_id,
            slug: self.slug,
            kind: self.kind,
            visibility: self.visibility,
            creator,
            parent_space: self.parent_space,
            created_tick: self.created_tick,
        }
    }
}

/// Spawn a fresh Space under `config`.
///
/// The payload carries no creating actor: the recorded creator is the
/// authenticated identity the runtime injects via
/// [`ActionContext::acting_actor`](crate::context::ActionContext::acting_actor),
/// so it cannot be substituted.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0201, schema_version = 1, band = 1)]
pub struct CreateSpace {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Initial configuration minus the creating actor (injected at dispatch).
    pub config: SpaceConfigDraft,
}

impl ActionCompute for CreateSpace {
    #[arkhe_pure]
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        // Single source of truth: the creating actor is the authenticated
        // identity the runtime injected at dispatch — never a wire field.
        // A user-scoped action with no injected actor cannot proceed.
        let creator = ctx.acting_actor().ok_or(ActionError::AuthorizationFailed(
            "space requires an authenticated actor",
        ))?;

        // E-user-3 C3 MC — refuse Action when the creator's backing user is
        // already in `GdprStatus::ErasurePending`. `GdprEraseUser` owns the
        // write that sets that pointer (its own `UserGdprState` component).
        ctx.ensure_actor_eligible(creator, ctx.tick())?;

        // E-space-4 MC — parent chain depth check. A parent reference that
        // would push the child past `MAX_SPACE_DEPTH` is rejected; a None
        // parent roots at depth 0. The `ParentChainDepth` O(1) cache is
        // read from the attached `InstanceView` (E8 invariant).
        let child_depth: u8 = match self.config.parent_space {
            Some(parent_id) => {
                let parent_depth = ctx
                    .read::<ParentChainDepth>(parent_id.get())?
                    .ok_or(ActionError::InvalidInput("parent space not found"))?;
                let next = parent_depth.depth.saturating_add(1);
                if next > MAX_SPACE_DEPTH {
                    return Err(ActionError::InvalidInput("space depth exceeded"));
                }
                next
            }
            None => 0,
        };

        // Stamp the injected creator into the stored config (authenticated
        // creator), then spawn + attach.
        let config = self.config.clone().into_config(creator);
        let space_entity = ctx.spawn_entity_for::<SpaceConfig>()?;
        ctx.set_component(space_entity, &config)?;
        ctx.set_component(
            space_entity,
            &ParentChainDepth {
                schema_version: 1,
                depth: child_depth,
            },
        )?;
        Ok(())
    }
}

/// Maximum parent-chain depth (invariant E-space-4). Deeper trees reject with
/// `DepthExceeded`.
pub const MAX_SPACE_DEPTH: u8 = 64;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::action::ArkheAction;
    use crate::component::ArkheComponent;

    fn ent(v: u64) -> EntityId {
        EntityId::new(v).unwrap()
    }

    #[test]
    fn space_config_serde_roundtrip_postcard() {
        let cfg = SpaceConfig {
            schema_version: 1,
            shell_id: ShellId([0x01; 16]),
            slug: BoundedString::<32>::new("general").unwrap(),
            kind: SpaceKind::Tree,
            visibility: Visibility::Public,
            creator: ActorId::new(ent(42)),
            parent_space: None,
            created_tick: Tick(0),
        };
        let bytes = postcard::to_stdvec(&cfg).unwrap();
        let back: SpaceConfig = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn space_membership_preserves_canonical_order() {
        let mut set = BTreeSet::new();
        set.insert(ActorId::new(ent(3)));
        set.insert(ActorId::new(ent(1)));
        set.insert(ActorId::new(ent(2)));
        let m = SpaceMembership {
            schema_version: 1,
            members: set,
        };
        let serialized_once = postcard::to_stdvec(&m).unwrap();

        let mut set2 = BTreeSet::new();
        set2.insert(ActorId::new(ent(2)));
        set2.insert(ActorId::new(ent(1)));
        set2.insert(ActorId::new(ent(3)));
        let m2 = SpaceMembership {
            schema_version: 1,
            members: set2,
        };
        assert_eq!(serialized_once, postcard::to_stdvec(&m2).unwrap());
    }

    #[test]
    fn space_config_action_type_codes() {
        assert_eq!(SpaceConfig::TYPE_CODE, 0x0003_0201);
        assert_eq!(ParentChainDepth::TYPE_CODE, 0x0003_0202);
        assert_eq!(SpaceMembership::TYPE_CODE, 0x0003_0203);
        assert_eq!(CreateSpace::TYPE_CODE, 0x0001_0201);
        assert_eq!(CreateSpace::BAND, 1);
    }

    #[test]
    fn max_space_depth_is_sixty_four() {
        assert_eq!(MAX_SPACE_DEPTH, 64);
    }

    fn draft() -> SpaceConfigDraft {
        SpaceConfigDraft {
            schema_version: 1,
            shell_id: ShellId([0x01; 16]),
            slug: BoundedString::<32>::new("general").unwrap(),
            kind: SpaceKind::Flat,
            visibility: Visibility::Public,
            parent_space: None,
            created_tick: Tick(0),
        }
    }

    #[test]
    fn create_space_records_injected_creator_not_a_wire_field() {
        use crate::action::ActionCompute;
        use arkhe_kernel::abi::{CapabilityMask, InstanceId, Principal};

        let injected = ActorId::new(ent(0xC1));
        let act = CreateSpace {
            schema_version: 1,
            config: draft(),
        };
        let mut c = ActionContext::new(
            [0u8; 32],
            InstanceId::new(1).unwrap(),
            Tick(7),
            Principal::System,
            CapabilityMask::SYSTEM,
        )
        .with_actor(Some(injected));
        act.compute(&mut c).expect("injected creator → compute ok");
        let recorded = c.ops().iter().find_map(|op| match op {
            arkhe_kernel::state::Op::SetComponent {
                type_code, bytes, ..
            } if *type_code == TypeCode(SpaceConfig::TYPE_CODE) => {
                postcard::from_bytes::<SpaceConfig>(bytes).ok()
            }
            _ => None,
        });
        assert_eq!(
            recorded.expect("config present").creator,
            injected,
            "recorded creator must equal the injected acting actor",
        );
    }

    #[test]
    fn create_space_without_injected_actor_rejects() {
        use crate::action::ActionCompute;
        use arkhe_kernel::abi::{CapabilityMask, InstanceId, Principal};

        let act = CreateSpace {
            schema_version: 1,
            config: draft(),
        };
        let mut c = ActionContext::new(
            [0u8; 32],
            InstanceId::new(1).unwrap(),
            Tick(7),
            Principal::System,
            CapabilityMask::SYSTEM,
        );
        let err = act
            .compute(&mut c)
            .expect_err("no injected actor must reject");
        assert!(matches!(err, ActionError::AuthorizationFailed(_)));
        assert!(c.ops().is_empty(), "no Ops on rejection");
    }
}
