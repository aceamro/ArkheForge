//! `ArkheComponent` sealed trait + `BoundedString<N>`.
//!
//! Components are ECS storage units. Each impl carries a stable `TYPE_CODE`
//! (runtime registry pin, A15) and `SCHEMA_VERSION` (monotone increment on
//! field addition; removal / reorder forbidden — Enum WAL compat).
//!
//! `BoundedString<N>` wraps `arrayvec::ArrayString<N>` so `N` is a compile-time
//! capacity bound. The wrapper is sealed — downstream code cannot see the
//! internal representation, letting us swap `ArrayString` for another backend
//! without breaking wire format.

use arkhe_kernel::abi::TypeCode;
use arrayvec::ArrayString;
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};

/// Sealed marker trait for ECS Component types. Implementations are produced
/// only by `#[derive(ArkheComponent)]` — manual downstream impls are rejected
/// by the `Sealed` supertrait and the Runtime dylint gate.
///
/// Canonical bytes = `postcard::to_stdvec(&value)` (A17 succession).
pub trait ArkheComponent:
    crate::__sealed::__Sealed + Serialize + for<'de> Deserialize<'de> + 'static
{
    /// Globally stable dispatch code within the runtime `TypeCode` registry.
    const TYPE_CODE: u32;

    /// Monotone schema version. Bump on field addition (`#[serde(default)]`
    /// paired); field removal / reorder forbidden.
    const SCHEMA_VERSION: u16;

    /// `TypeCode` wrapper convenience.
    fn type_code() -> TypeCode {
        TypeCode(Self::TYPE_CODE)
    }

    /// Approximate payload size for quota tracking. Default returns
    /// `size_of::<Self>()`; override for `bytes::Bytes`-carrying Components.
    fn approx_size(&self) -> usize {
        core::mem::size_of::<Self>()
    }
}

/// Fixed-capacity UTF-8 string — bounded at compile time by const generic `N`.
///
/// Canonical wire = `postcard::serialize_str` (varint length + `N`-bounded
/// UTF-8 bytes). `N` is not on the wire — decode checks against the const.
/// Expanding `N` requires a `SCHEMA_VERSION` bump on the enclosing Component;
/// shrinking is forbidden (existing records might exceed the new cap).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct BoundedString<const N: usize>(ArrayString<N>);

impl<const N: usize> BoundedString<N> {
    /// Construct from a borrowed `&str`. Rejects over-length input.
    pub fn new(s: &str) -> Result<Self, BoundedStringError> {
        ArrayString::from(s)
            .map(Self)
            .map_err(|_| BoundedStringError::Overflow {
                len: s.len(),
                cap: N,
            })
    }

    /// Borrow as `&str`.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Compile-time capacity.
    pub const CAP: usize = N;
}

impl<const N: usize> Serialize for BoundedString<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.as_str())
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedString<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: &str = <&str>::deserialize(d)?;
        Self::new(s).map_err(D::Error::custom)
    }
}

/// Failure variants for [`BoundedString`].
#[non_exhaustive]
#[derive(Debug, Clone, thiserror::Error, Eq, PartialEq)]
pub enum BoundedStringError {
    /// Input length exceeded the compile-time capacity.
    #[error("BoundedString overflow: len {len} > cap {cap}")]
    Overflow {
        /// Attempted length in bytes.
        len: usize,
        /// Compile-time capacity.
        cap: usize,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn bounded_string_accepts_within_cap() {
        let s = BoundedString::<8>::new("abcd").unwrap();
        assert_eq!(s.as_str(), "abcd");
        assert_eq!(BoundedString::<8>::CAP, 8);
    }

    #[test]
    fn bounded_string_rejects_over_cap() {
        let e = BoundedString::<4>::new("hello").unwrap_err();
        match e {
            BoundedStringError::Overflow { len, cap } => {
                assert_eq!(len, 5);
                assert_eq!(cap, 4);
            }
        }
    }

    #[test]
    fn bounded_string_serde_roundtrip_postcard() {
        let s = BoundedString::<16>::new("hello").unwrap();
        let bytes = postcard::to_stdvec(&s).unwrap();
        let back: BoundedString<16> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn bounded_string_deserialize_rejects_over_cap_at_runtime() {
        let big = BoundedString::<16>::new("0123456789abcdef").unwrap();
        let bytes = postcard::to_stdvec(&big).unwrap();
        let res: Result<BoundedString<8>, _> = postcard::from_bytes(&bytes);
        assert!(res.is_err());
    }
}
