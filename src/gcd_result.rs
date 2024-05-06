/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

#[cfg(any(feature = "gmp", feature = "openssl", feature = "rust"))]
/// GcdResult encapsulates the gcd result and the Bézout coefficients
#[derive(Debug, Clone)]
pub struct GcdResult {
    /// Quotient
    pub gcd: crate::BigNumber,
    /// Bézout coefficient
    pub x: crate::BigNumber,
    /// Bézout coefficient
    pub y: crate::BigNumber,
}

#[cfg(feature = "crypto")]
/// GcdResult encapsulates the gcd result and the Bézout coefficients
#[derive(Debug, Clone)]
pub struct GcdResult<const LIMBS: usize>
where
    crypto_bigint::Uint<LIMBS>: crypto_bigint::Encoding,
{
    /// Quotient
    pub gcd: crate::SizedBigNumber<LIMBS>,
    /// Bézout coefficient
    pub x: crate::SizedBigNumber<LIMBS>,
    /// Bézout coefficient
    pub y: crate::SizedBigNumber<LIMBS>,
}
