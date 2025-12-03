//! Soft-float wrapper using the `softfloat` crate
//!
//! Uses the battle-tested softfloat crate for IEEE 754 compliance
//! to ensure deterministic floating point operations in zkVM.

use softfloat::F64;

/// Rounding modes (IEEE 754)
/// Note: The softfloat crate uses round-to-nearest-even by default
/// We map RandomX rounding modes but the crate may not support all modes
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum RoundingMode {
    /// Round to nearest, ties to even (default)
    NearestEven = 0,
    /// Round toward zero (truncate)
    TowardZero = 1,
    /// Round toward positive infinity (ceiling)
    TowardPositive = 2,
    /// Round toward negative infinity (floor)
    TowardNegative = 3,
}

impl From<u8> for RoundingMode {
    fn from(val: u8) -> Self {
        match val & 3 {
            0 => RoundingMode::NearestEven,
            1 => RoundingMode::TowardZero,
            2 => RoundingMode::TowardPositive,
            3 => RoundingMode::TowardNegative,
            _ => unreachable!(),
        }
    }
}

/// Soft-float double precision number wrapper
#[derive(Clone, Copy, Debug)]
pub struct SoftFloat {
    inner: F64,
}

impl SoftFloat {
    /// Create from raw bits
    #[inline]
    pub fn from_bits(bits: u64) -> Self {
        Self {
            inner: F64::from_bits(bits),
        }
    }

    /// Get raw bits
    #[inline]
    pub fn to_bits(self) -> u64 {
        self.inner.to_bits()
    }

    /// Create zero
    #[inline]
    pub fn zero() -> Self {
        Self {
            inner: F64::from_bits(0),
        }
    }

    /// Absolute value (clear sign bit)
    #[inline]
    pub fn abs(self) -> Self {
        // IEEE 754: sign bit is bit 63, clear it for absolute value
        Self {
            inner: F64::from_bits(self.inner.to_bits() & 0x7FFF_FFFF_FFFF_FFFF),
        }
    }

    /// Addition with rounding mode
    /// Note: softfloat crate uses default rounding, we accept rm for API compatibility
    #[inline]
    pub fn add(self, other: Self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner + other.inner,
        }
    }

    /// Subtraction with rounding mode
    #[inline]
    pub fn sub(self, other: Self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner - other.inner,
        }
    }

    /// Multiplication with rounding mode
    #[inline]
    pub fn mul(self, other: Self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner * other.inner,
        }
    }

    /// Division with rounding mode
    #[inline]
    pub fn div(self, other: Self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner / other.inner,
        }
    }

    /// Square root with rounding mode
    #[inline]
    pub fn sqrt(self, _rm: RoundingMode) -> Self {
        Self {
            inner: self.inner.sqrt(),
        }
    }
}
