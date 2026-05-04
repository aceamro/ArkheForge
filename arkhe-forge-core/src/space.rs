//! Space primitive — container / scope (spec §4.3).

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
// E14.L1-Deny enforcement on Action::compute (auditor cross-review Q2(i)).
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

/// Spawn a fresh Space under `config`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 0x0001_0201, schema_version = 1, band = 1)]
pub struct CreateSpace {
    /// Wire-level schema version tag.
    pub schema_version: u16,
    /// Initial configuration.
    pub config: SpaceConfig,
}

impl ActionCompute for CreateSpace {
    #[arkhe_pure]
    fn compute<'i>(&self, ctx: &mut ActionContext<'i>) -> Result<(), ActionError> {
        // E-user-3 C3 MC — refuse Action when the creator's backing user is
        // already in `GdprStatus::ErasurePending`. The cascade owns the only
        // legal write path until completion (spec §3.3 / §4.1).
        ctx.ensure_actor_eligible(self.config.creator, ctx.tick())?;

        // E-space-4 MC — parent chain depth check. A parent reference that
        // would push the child past `MAX_SPACE_DEPTH` is rejected; a None
        // parent roots at depth 0. The `ParentChainDepth` O(1) cache is
        // read from the attached `InstanceView` (spec §4.3 invariant E8).
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

        let space_entity = ctx.spawn_entity_for::<SpaceConfig>()?;
        ctx.set_component(space_entity, &self.config)?;
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
}
