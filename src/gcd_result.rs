/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::BigNumber;

/// GcdResult encapsulates the gcd result and the Bézout coefficients
#[derive(Debug, Clone)]
pub struct GcdResult {
    /// Quotient
    pub gcd: BigNumber,
    /// Bézout coefficient
    pub x: BigNumber,
    /// Bézout coefficient
    pub y: BigNumber,
}
