/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::BigNumber;

use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

/// Represents a cyclic group where all operations are reduced by a modulus.
/// Purely a convenience struct to avoid having to call mod{ops}
pub struct Group {
    /// The upper limit that all values in the group are to be reduced
    pub modulus: BigNumber,
}

macro_rules! binops_group {
    ($ops:ident, $func:ident, $opr:ident) => {
        impl<'a, 'b, 'c> $ops<(&'a BigNumber, &'b BigNumber)> for &'c Group {
            type Output = BigNumber;

            fn $func(self, pair: (&'a BigNumber, &'b BigNumber)) -> Self::Output {
                pair.0.$opr(pair.1, &self.modulus)
            }
        }

        impl<'a, 'c> $ops<(&'a BigNumber, BigNumber)> for &'c Group {
            type Output = BigNumber;

            fn $func(self, pair: (&'a BigNumber, BigNumber)) -> Self::Output {
                self + (pair.0, &pair.1)
            }
        }

        impl<'b, 'c> $ops<(BigNumber, &'b BigNumber)> for &'c Group {
            type Output = BigNumber;

            fn $func(self, pair: (BigNumber, &'b BigNumber)) -> Self::Output {
                self + (&pair.0, pair.1)
            }
        }

        impl<'c> $ops<(BigNumber, BigNumber)> for &'c Group {
            type Output = BigNumber;

            fn $func(self, pair: (BigNumber, BigNumber)) -> Self::Output {
                self + (&pair.0, &pair.1)
            }
        }

        impl<'a, 'b> $ops<(&'a BigNumber, &'b BigNumber)> for Group {
            type Output = BigNumber;

            fn $func(self, pair: (&'a BigNumber, &'b BigNumber)) -> Self::Output {
                &self + pair
            }
        }

        impl<'a> $ops<(&'a BigNumber, BigNumber)> for Group {
            type Output = BigNumber;

            fn $func(self, pair: (&'a BigNumber, BigNumber)) -> Self::Output {
                &self + (pair.0, &pair.1)
            }
        }

        impl<'b> $ops<(BigNumber, &'b BigNumber)> for Group {
            type Output = BigNumber;

            fn $func(self, pair: (BigNumber, &'b BigNumber)) -> Self::Output {
                &self + (&pair.0, pair.1)
            }
        }

        impl $ops<(BigNumber, BigNumber)> for Group {
            type Output = BigNumber;

            fn $func(self, pair: (BigNumber, BigNumber)) -> Self::Output {
                &self + (&pair.0, &pair.1)
            }
        }
    };
}
macro_rules! binops_group_assign {
    ($ops:ident, $func:ident, $opr:ident) => {
        impl<'a, 'b, 'c> $ops<(&'a mut BigNumber, &'b BigNumber)> for &'c Group {
            fn $func(&mut self, pair: (&'a mut BigNumber, &'b BigNumber)) {
                *pair.0 = pair.0.$opr(pair.1, &self.modulus);
            }
        }

        impl<'a, 'c> $ops<(&'a mut BigNumber, BigNumber)> for &'c Group {
            fn $func(&mut self, pair: (&'a mut BigNumber, BigNumber)) {
                *self += (pair.0, &pair.1)
            }
        }

        impl<'a, 'b> $ops<(&'a mut BigNumber, &'b BigNumber)> for Group {
            fn $func(&mut self, pair: (&'a mut BigNumber, &'b BigNumber)) {
                *pair.0 = pair.0.$opr(pair.1, &self.modulus);
            }
        }

        impl<'a> $ops<(&'a mut BigNumber, BigNumber)> for Group {
            fn $func(&mut self, pair: (&'a mut BigNumber, BigNumber)) {
                *self += (pair.0, &pair.1)
            }
        }
    };
}

binops_group!(Add, add, modadd);
binops_group!(Sub, sub, modsub);
binops_group!(Mul, mul, modmul);
binops_group!(Div, div, moddiv);
binops_group_assign!(AddAssign, add_assign, modadd);
binops_group_assign!(SubAssign, sub_assign, modsub);
binops_group_assign!(MulAssign, mul_assign, modmul);
binops_group_assign!(DivAssign, div_assign, moddiv);

impl Group {
    /// Compute -rhs mod self
    pub fn neg(&self, rhs: &BigNumber) -> BigNumber {
        rhs.modneg(&self.modulus)
    }

    /// Compute the sum of the the bignumbers in the group
    pub fn sum<I>(&self, nums: I) -> BigNumber
    where
        I: AsRef<[BigNumber]>,
    {
        let mut r = BigNumber::zero();
        for a in nums.as_ref() {
            r = r.modadd(a, &self.modulus);
        }
        r
    }

    /// Compute the product of the the bignumbers in the group
    pub fn product<I>(&self, nums: I) -> BigNumber
    where
        I: AsRef<[BigNumber]>,
    {
        let mut r = BigNumber::zero();
        for a in nums.as_ref() {
            r = r.modmul(a, &self.modulus);
        }
        r
    }
}
