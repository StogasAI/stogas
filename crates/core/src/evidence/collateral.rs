use super::Error;

/// Intersection of the required vendor-signed certificate and revocation validity intervals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before_unix_ms: i64,
    pub not_after_unix_ms: i64,
}

impl Validity {
    pub(super) const fn at(self, now_unix_ms: i64) -> Result<Self, Error> {
        if now_unix_ms < self.not_before_unix_ms || now_unix_ms >= self.not_after_unix_ms {
            return Err(Error::CollateralExpired);
        }
        Ok(self)
    }

    pub(super) fn intersect(self, other: Self) -> Self {
        Self {
            not_before_unix_ms: self.not_before_unix_ms.max(other.not_before_unix_ms),
            not_after_unix_ms: self.not_after_unix_ms.min(other.not_after_unix_ms),
        }
    }
}

#[path = "amd.rs"]
mod amd;
pub(super) use amd::{Revocations, Store};
