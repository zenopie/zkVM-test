//! Soft-float IEEE 754 double precision implementation
//!
//! This module provides deterministic floating point operations
//! that don't rely on hardware FPU, ensuring consistent results
//! across all platforms for zkVM execution.

/// IEEE 754 double precision constants
const SIGN_BIT: u64 = 0x8000_0000_0000_0000;
const EXP_MASK: u64 = 0x7FF0_0000_0000_0000;
const MANT_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;
const EXP_BIAS: i32 = 1023;
const EXP_BITS: u32 = 11;
const MANT_BITS: u32 = 52;
const IMPLICIT_BIT: u64 = 1u64 << MANT_BITS;

/// Rounding modes (IEEE 754)
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

/// Soft-float double precision number
#[derive(Clone, Copy, Debug)]
pub struct SoftFloat {
    /// Raw IEEE 754 bit representation
    bits: u64,
}

impl SoftFloat {
    /// Create from raw bits
    #[inline]
    pub const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Get raw bits
    #[inline]
    pub const fn to_bits(self) -> u64 {
        self.bits
    }

    /// Create zero
    #[inline]
    pub const fn zero() -> Self {
        Self { bits: 0 }
    }

    /// Check if zero (positive or negative)
    #[inline]
    pub fn is_zero(self) -> bool {
        (self.bits & !SIGN_BIT) == 0
    }

    /// Check if NaN
    #[inline]
    pub fn is_nan(self) -> bool {
        let exp = (self.bits & EXP_MASK) >> MANT_BITS;
        let mant = self.bits & MANT_MASK;
        exp == 0x7FF && mant != 0
    }

    /// Check if infinity
    #[inline]
    pub fn is_inf(self) -> bool {
        let exp = (self.bits & EXP_MASK) >> MANT_BITS;
        let mant = self.bits & MANT_MASK;
        exp == 0x7FF && mant == 0
    }

    /// Check if negative
    #[inline]
    pub fn is_negative(self) -> bool {
        (self.bits & SIGN_BIT) != 0
    }

    /// Get sign bit (0 or 1)
    #[inline]
    fn sign(self) -> u64 {
        (self.bits >> 63) & 1
    }

    /// Get biased exponent
    #[inline]
    fn biased_exp(self) -> u64 {
        (self.bits & EXP_MASK) >> MANT_BITS
    }

    /// Get mantissa (without implicit bit)
    #[inline]
    fn mantissa(self) -> u64 {
        self.bits & MANT_MASK
    }

    /// Create positive infinity
    #[inline]
    pub const fn pos_inf() -> Self {
        Self { bits: EXP_MASK }
    }

    /// Create negative infinity
    #[inline]
    pub const fn neg_inf() -> Self {
        Self { bits: SIGN_BIT | EXP_MASK }
    }

    /// Create quiet NaN
    #[inline]
    pub const fn nan() -> Self {
        Self { bits: EXP_MASK | (1u64 << (MANT_BITS - 1)) }
    }

    /// Absolute value (just clear sign bit)
    #[inline]
    pub fn abs(self) -> Self {
        Self { bits: self.bits & !SIGN_BIT }
    }

    /// Negate (flip sign bit)
    #[inline]
    pub fn neg(self) -> Self {
        Self { bits: self.bits ^ SIGN_BIT }
    }

    /// Pack sign, exponent, and mantissa into f64 bits
    fn pack(sign: u64, exp: i32, mant: u64, rm: RoundingMode) -> Self {
        // Handle overflow to infinity
        if exp >= 0x7FF {
            return if sign != 0 { Self::neg_inf() } else { Self::pos_inf() };
        }

        // Handle underflow to zero or subnormal
        if exp <= 0 {
            // Subnormal or zero
            let shift = 1 - exp;
            if shift >= 64 {
                // Complete underflow
                return Self::from_bits(sign << 63);
            }

            let shifted_mant = mant >> shift;
            let round_bits = mant & ((1u64 << shift) - 1);
            let halfway = 1u64 << (shift - 1);

            let rounded = Self::round_mantissa(shifted_mant, round_bits, halfway, sign != 0, rm);
            return Self::from_bits((sign << 63) | rounded);
        }

        Self::from_bits((sign << 63) | ((exp as u64) << MANT_BITS) | (mant & MANT_MASK))
    }

    /// Round mantissa based on rounding mode
    fn round_mantissa(mant: u64, round_bits: u64, halfway: u64, negative: bool, rm: RoundingMode) -> u64 {
        if round_bits == 0 {
            return mant;
        }

        let round_up = match rm {
            RoundingMode::NearestEven => {
                if round_bits > halfway {
                    true
                } else if round_bits < halfway {
                    false
                } else {
                    // Exactly halfway - round to even
                    (mant & 1) != 0
                }
            }
            RoundingMode::TowardZero => false,
            RoundingMode::TowardPositive => !negative && round_bits != 0,
            RoundingMode::TowardNegative => negative && round_bits != 0,
        };

        if round_up {
            mant.wrapping_add(1)
        } else {
            mant
        }
    }

    /// Addition with rounding mode
    pub fn add(self, other: Self, rm: RoundingMode) -> Self {
        // Handle special cases
        if self.is_nan() || other.is_nan() {
            return Self::nan();
        }

        if self.is_inf() {
            if other.is_inf() && self.is_negative() != other.is_negative() {
                return Self::nan(); // inf - inf = NaN
            }
            return self;
        }
        if other.is_inf() {
            return other;
        }

        if self.is_zero() {
            return if other.is_zero() && self.is_negative() && other.is_negative() {
                Self::from_bits(SIGN_BIT) // -0 + -0 = -0
            } else {
                other
            };
        }
        if other.is_zero() {
            return self;
        }

        // Extract components
        let sign_a = self.sign();
        let sign_b = other.sign();
        let exp_a = self.biased_exp() as i32;
        let exp_b = other.biased_exp() as i32;

        // Get mantissas with implicit bit (handle subnormals)
        let mant_a = if exp_a == 0 {
            self.mantissa()
        } else {
            self.mantissa() | IMPLICIT_BIT
        };
        let mant_b = if exp_b == 0 {
            other.mantissa()
        } else {
            other.mantissa() | IMPLICIT_BIT
        };

        // Adjust exponents for subnormals
        let exp_a = if exp_a == 0 { 1 } else { exp_a };
        let exp_b = if exp_b == 0 { 1 } else { exp_b };

        // Align mantissas - use extra precision bits for rounding
        let (mut mant_a, mut mant_b, result_exp) = if exp_a >= exp_b {
            let shift = (exp_a - exp_b) as u32;
            let shifted_b = if shift >= 64 { 0 } else { mant_b >> shift };
            (mant_a << 3, shifted_b << 3, exp_a)
        } else {
            let shift = (exp_b - exp_a) as u32;
            let shifted_a = if shift >= 64 { 0 } else { mant_a >> shift };
            (shifted_a << 3, mant_b << 3, exp_b)
        };

        // Perform addition or subtraction
        let (result_mant, result_sign) = if sign_a == sign_b {
            // Same sign: add magnitudes
            (mant_a.wrapping_add(mant_b), sign_a)
        } else {
            // Different signs: subtract magnitudes
            if mant_a >= mant_b {
                (mant_a - mant_b, sign_a)
            } else {
                (mant_b - mant_a, sign_b)
            }
        };

        if result_mant == 0 {
            return Self::zero();
        }

        // Normalize
        let leading_zeros = result_mant.leading_zeros();
        let target_pos = 55; // Position of implicit bit in our shifted representation

        let (normalized_mant, final_exp) = if leading_zeros < (64 - target_pos - 1) as u32 {
            // Need to shift right (overflow)
            let shift = (64 - target_pos - 1) as u32 - leading_zeros;
            let round_bits = result_mant & ((1u64 << (shift + 3)) - 1);
            let halfway = 1u64 << (shift + 2);
            let shifted = result_mant >> (shift + 3);
            let rounded = Self::round_mantissa(shifted, round_bits, halfway, result_sign != 0, rm);
            (rounded, result_exp + shift as i32)
        } else if leading_zeros > (64 - target_pos - 1) as u32 {
            // Need to shift left (underflow)
            let shift = leading_zeros - (64 - target_pos - 1) as u32;
            let shifted = result_mant << shift >> 3;
            (shifted, result_exp - shift as i32)
        } else {
            (result_mant >> 3, result_exp)
        };

        Self::pack(result_sign, final_exp, normalized_mant & MANT_MASK, rm)
    }

    /// Subtraction with rounding mode
    pub fn sub(self, other: Self, rm: RoundingMode) -> Self {
        self.add(other.neg(), rm)
    }

    /// Multiplication with rounding mode
    pub fn mul(self, other: Self, rm: RoundingMode) -> Self {
        let result_sign = self.sign() ^ other.sign();

        // Handle special cases
        if self.is_nan() || other.is_nan() {
            return Self::nan();
        }

        if self.is_inf() || other.is_inf() {
            if self.is_zero() || other.is_zero() {
                return Self::nan(); // 0 * inf = NaN
            }
            return if result_sign != 0 { Self::neg_inf() } else { Self::pos_inf() };
        }

        if self.is_zero() || other.is_zero() {
            return Self::from_bits(result_sign << 63);
        }

        // Extract components
        let exp_a = self.biased_exp() as i32;
        let exp_b = other.biased_exp() as i32;

        let mant_a = if exp_a == 0 {
            self.mantissa()
        } else {
            self.mantissa() | IMPLICIT_BIT
        };
        let mant_b = if exp_b == 0 {
            other.mantissa()
        } else {
            other.mantissa() | IMPLICIT_BIT
        };

        let exp_a = if exp_a == 0 { 1 } else { exp_a };
        let exp_b = if exp_b == 0 { 1 } else { exp_b };

        // Multiply mantissas (128-bit result)
        let product = (mant_a as u128) * (mant_b as u128);

        // Result exponent
        let mut result_exp = exp_a + exp_b - EXP_BIAS;

        // Normalize - product is in bits [104:0] for normalized inputs
        // We need bits [52:0] for mantissa
        let leading = (product.leading_zeros()) as i32;
        let shift = 104 - 52 - leading; // Adjust to get mantissa in right position

        let (normalized, round_bits) = if shift >= 0 {
            let s = shift as u32;
            let mant = (product >> s) as u64;
            let round = if s >= 64 { 0 } else { (product & ((1u128 << s) - 1)) as u64 };
            let halfway = if s >= 64 { 0 } else { 1u64 << (s.saturating_sub(1)) };
            result_exp += shift - (104 - 52 - 23); // Adjust exponent
            (mant, (round, halfway))
        } else {
            let s = (-shift) as u32;
            result_exp -= s as i32;
            ((product << s) as u64, (0u64, 0u64))
        };

        let rounded_mant = Self::round_mantissa(
            normalized & MANT_MASK,
            round_bits.0,
            round_bits.1,
            result_sign != 0,
            rm,
        );

        Self::pack(result_sign, result_exp, rounded_mant, rm)
    }

    /// Division with rounding mode
    pub fn div(self, other: Self, rm: RoundingMode) -> Self {
        let result_sign = self.sign() ^ other.sign();

        // Handle special cases
        if self.is_nan() || other.is_nan() {
            return Self::nan();
        }

        if self.is_inf() {
            if other.is_inf() {
                return Self::nan(); // inf / inf = NaN
            }
            return if result_sign != 0 { Self::neg_inf() } else { Self::pos_inf() };
        }

        if other.is_inf() {
            return Self::from_bits(result_sign << 63); // x / inf = 0
        }

        if other.is_zero() {
            if self.is_zero() {
                return Self::nan(); // 0 / 0 = NaN
            }
            return if result_sign != 0 { Self::neg_inf() } else { Self::pos_inf() };
        }

        if self.is_zero() {
            return Self::from_bits(result_sign << 63);
        }

        // Extract components
        let exp_a = self.biased_exp() as i32;
        let exp_b = other.biased_exp() as i32;

        let mant_a = if exp_a == 0 {
            self.mantissa()
        } else {
            self.mantissa() | IMPLICIT_BIT
        };
        let mant_b = if exp_b == 0 {
            other.mantissa()
        } else {
            other.mantissa() | IMPLICIT_BIT
        };

        let exp_a = if exp_a == 0 { 1 } else { exp_a };
        let exp_b = if exp_b == 0 { 1 } else { exp_b };

        // Divide mantissas with extra precision
        // Shift dividend left to get more precision bits
        let dividend = (mant_a as u128) << 64;
        let divisor = mant_b as u128;
        let quotient = dividend / divisor;
        let remainder = dividend % divisor;

        // Result exponent
        let mut result_exp = exp_a - exp_b + EXP_BIAS;

        // Normalize quotient (it's in bits around position 64)
        let leading = quotient.leading_zeros();
        let target = 64 - MANT_BITS - 1; // Where we want the implicit bit

        let (normalized, adj) = if leading < target as u32 {
            let shift = target as u32 - leading;
            result_exp += shift as i32;
            ((quotient >> shift) as u64, shift)
        } else {
            let shift = leading - target as u32;
            result_exp -= shift as i32;
            ((quotient << shift) as u64, 0)
        };

        // Round based on remainder
        let has_remainder = remainder != 0 || (adj > 0 && (quotient & ((1u128 << adj) - 1)) != 0);
        let round_bit = if has_remainder { 1u64 } else { 0u64 };

        let rounded_mant = Self::round_mantissa(
            normalized & MANT_MASK,
            round_bit,
            1,
            result_sign != 0,
            rm,
        );

        Self::pack(result_sign, result_exp, rounded_mant, rm)
    }

    /// Square root with rounding mode
    pub fn sqrt(self, rm: RoundingMode) -> Self {
        // Handle special cases
        if self.is_nan() {
            return Self::nan();
        }

        if self.is_zero() {
            return self; // sqrt(+0) = +0, sqrt(-0) = -0
        }

        if self.is_negative() {
            return Self::nan(); // sqrt(negative) = NaN
        }

        if self.is_inf() {
            return Self::pos_inf();
        }

        // Extract components
        let exp = self.biased_exp() as i32;
        let mant = if exp == 0 {
            self.mantissa()
        } else {
            self.mantissa() | IMPLICIT_BIT
        };
        let exp = if exp == 0 { 1 } else { exp };

        // Adjust exponent to be even (for easier sqrt)
        let (adj_exp, adj_mant) = if (exp - EXP_BIAS) & 1 != 0 {
            (exp - 1, mant << 1)
        } else {
            (exp, mant)
        };

        // Result exponent is half of input exponent
        let result_exp = ((adj_exp - EXP_BIAS) >> 1) + EXP_BIAS;

        // Integer square root with extra precision
        // Shift mantissa to get more precision bits
        let radicand = (adj_mant as u128) << 60;

        // Newton-Raphson for integer sqrt
        let mut x = radicand;
        let mut y = (x + 1) >> 1;
        while y < x {
            x = y;
            y = (x + radicand / x) >> 1;
        }

        // x is now floor(sqrt(radicand))
        let sqrt_result = x as u64;

        // Normalize (result should be around bit 30)
        let leading = sqrt_result.leading_zeros();
        let target = 64 - MANT_BITS - 1;

        let normalized = if leading < target as u32 {
            sqrt_result >> (target as u32 - leading)
        } else {
            sqrt_result << (leading - target as u32)
        };

        // Check for rounding (did we truncate?)
        let exact = x * x == radicand;
        let round_bit = if exact { 0u64 } else { 1u64 };

        let rounded_mant = Self::round_mantissa(
            normalized & MANT_MASK,
            round_bit,
            1,
            false, // sqrt result is always positive
            rm,
        );

        Self::pack(0, result_exp, rounded_mant, rm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ops() {
        let a = SoftFloat::from_bits(0x4000_0000_0000_0000); // 2.0
        let b = SoftFloat::from_bits(0x4008_0000_0000_0000); // 3.0

        // Test add
        let sum = a.add(b, RoundingMode::NearestEven);
        assert_eq!(sum.to_bits(), 0x4014_0000_0000_0000); // 5.0

        // Test sub
        let diff = b.sub(a, RoundingMode::NearestEven);
        assert_eq!(diff.to_bits(), 0x3FF0_0000_0000_0000); // 1.0
    }
}