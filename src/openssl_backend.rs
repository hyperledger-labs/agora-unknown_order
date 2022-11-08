/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::GcdResult;
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use rand::RngCore;
use std::{
    cmp::{Eq, Ordering, PartialEq, PartialOrd},
    fmt::{self, Debug, Display},
    iter::{Product, Sum},
    mem::swap,
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, Shr, Sub,
        SubAssign,
    },
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Big number
#[derive(Ord, PartialOrd)]
pub struct Bn(pub(crate) BigNum);

fn from_isize(d: isize) -> BigNum {
    if d < 0 {
        let mut b = BigNum::from_slice(&(-d).to_be_bytes()).unwrap();
        b.set_negative(true);
        b
    } else {
        BigNum::from_slice(&d.to_be_bytes()).unwrap()
    }
}

clone_impl!(|b: &Bn| {
    let mut t = BigNum::from_slice(&b.0.to_vec()).unwrap();
    t.set_negative(b.0.is_negative());
    t
});
default_impl!(|| BigNum::new().unwrap());
display_impl!();
eq_impl!();
from_impl!(
    |d: usize| BigNum::from_slice(&d.to_be_bytes()).unwrap(),
    usize
);
#[cfg(target_pointer_width = "64")]
from_impl!(
    |d: i128| {
        if d < 0 {
            let mut b = BigNum::from_slice(&(-d).to_be_bytes()).unwrap();
            b.set_negative(true);
            b
        } else {
            BigNum::from_slice(&d.to_be_bytes()).unwrap()
        }
    },
    i128
);
#[cfg(target_pointer_width = "64")]
from_impl!(
    |d: u128| BigNum::from_slice(&d.to_be_bytes()).unwrap(),
    u128
);
from_impl!(|d: u64| BigNum::from_slice(&d.to_be_bytes()).unwrap(), u64);
from_impl!(|d: u32| BigNum::from_u32(d).unwrap(), u32);
from_impl!(|d: u16| BigNum::from_u32(d as u32).unwrap(), u16);
from_impl!(|d: u8| BigNum::from_u32(d as u32).unwrap(), u8);
from_impl!(from_isize, isize);
from_impl!(|d: i64| from_isize(d as isize), i64);
from_impl!(|d: i32| from_isize(d as isize), i32);
from_impl!(|d: i16| from_isize(d as isize), i16);
from_impl!(|d: i8| from_isize(d as isize), i8);
iter_impl!();
serdes_impl!(
    |b: &Bn| b.0.to_hex_str().unwrap(),
    |s: &str| { BigNum::from_hex_str(s).ok() },
    |b: &Bn| {
        let mut digits = b.0.to_vec();
        digits.insert(0, if b.0.is_negative() { 1 } else { 0 });
        digits
    },
    |s: &[u8]| -> Option<BigNum> {
        if s.is_empty() {
            return None;
        }
        let result = BigNum::from_slice(&s[1..]).ok()?;
        Some(if s[0] == 1 { -result } else { result })
    }
);
zeroize_impl!(|b: &mut Bn| b.0.clear());

impl<'a, 'b> Add<&'b Bn> for &'a Bn {
    type Output = Bn;

    fn add(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().unwrap();
        BigNumRef::checked_add(&mut bn, &self.0, &rhs.0).unwrap();
        Bn(bn)
    }
}

impl<'a, 'b> Sub<&'b Bn> for &'a Bn {
    type Output = Bn;

    fn sub(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().unwrap();
        BigNumRef::checked_sub(&mut bn, &self.0, &rhs.0).unwrap();
        Bn(bn)
    }
}

impl<'a, 'b> Mul<&'b Bn> for &'a Bn {
    type Output = Bn;

    fn mul(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::checked_mul(&mut bn, &self.0, &rhs.0, &mut ctx).unwrap();
        Bn(bn)
    }
}

impl<'a, 'b> Div<&'b Bn> for &'a Bn {
    type Output = Bn;

    fn div(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::checked_div(&mut bn, &self.0, &rhs.0, &mut ctx).unwrap();
        Bn(bn)
    }
}

impl<'a, 'b> Rem<&'b Bn> for &'a Bn {
    type Output = Bn;

    fn rem(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::checked_rem(&mut bn, &self.0, &rhs.0, &mut ctx).unwrap();
        Bn(bn)
    }
}

impl<'b> AddAssign<&'b Bn> for Bn {
    fn add_assign(&mut self, rhs: &'b Bn) {
        let b = self.clone();
        BigNumRef::checked_add(&mut self.0, &b.0, &rhs.0).unwrap();
    }
}

impl<'b> SubAssign<&'b Bn> for Bn {
    fn sub_assign(&mut self, rhs: &'b Bn) {
        let b = self.clone();
        BigNumRef::checked_sub(&mut self.0, &b.0, &rhs.0).unwrap();
    }
}

impl<'b> MulAssign<&'b Bn> for Bn {
    fn mul_assign(&mut self, rhs: &'b Bn) {
        let mut ctx = BigNumContext::new().unwrap();
        let b = self.clone();
        BigNumRef::checked_mul(&mut self.0, &b.0, &rhs.0, &mut ctx).unwrap();
    }
}

impl<'b> DivAssign<&'b Bn> for Bn {
    fn div_assign(&mut self, rhs: &'b Bn) {
        let mut ctx = BigNumContext::new().unwrap();
        let b = self.clone();
        BigNumRef::checked_div(&mut self.0, &b.0, &rhs.0, &mut ctx).unwrap();
    }
}

impl<'b> RemAssign<&'b Bn> for Bn {
    fn rem_assign(&mut self, rhs: &'b Bn) {
        let mut ctx = BigNumContext::new().unwrap();
        let b = self.clone();
        BigNumRef::checked_rem(&mut self.0, &b.0, &rhs.0, &mut ctx).unwrap();
    }
}

ops_impl!(Add, add, AddAssign, add_assign, +, +=);
ops_impl!(Sub, sub, SubAssign, sub_assign, -, -=);
ops_impl!(Mul, mul, MulAssign, mul_assign, *, *=);
ops_impl!(Div, div, DivAssign, div_assign, /, /=);
ops_impl!(Rem, rem, RemAssign, rem_assign, %, %=);
neg_impl!(|b: &BigNum| {
    let mut n = BigNum::from_slice(b.to_vec().as_slice()).unwrap();
    n.set_negative(!b.is_negative());
    Bn(n)
});
shift_impl!(Shl, shl, |lhs: &BigNum, rhs| {
    let mut n = BigNum::new().unwrap();
    if rhs == 1 {
        BigNumRef::lshift1(&mut n, lhs).unwrap();
    } else {
        BigNumRef::lshift(&mut n, lhs, rhs as i32).unwrap();
    }
    Bn(n)
});
shift_impl!(Shr, shr, |lhs: &BigNum, rhs| {
    let mut n = BigNum::new().unwrap();
    if rhs == 1 {
        BigNumRef::rshift1(&mut n, lhs).unwrap();
    } else {
        BigNumRef::rshift(&mut n, lhs, rhs as i32).unwrap();
    }
    Bn(n)
});

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from(if self.0.ucmp(&other.0) == Ordering::Equal {
            1u8
        } else {
            0u8
        })
    }
}

impl Bn {
    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut bn = BigNum::new().unwrap();
        if exponent.0.is_negative() {
            match self.invert(n) {
                None => {}
                Some(a) => {
                    let e = -exponent.clone();
                    BigNumRef::mod_exp(&mut bn, &a.0, &e.0, &n.0, &mut ctx).unwrap();
                }
            }
        } else {
            BigNumRef::mod_exp(&mut bn, &self.0, &exponent.0, &n.0, &mut ctx).unwrap();
        }
        Self(bn)
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut t = BigNum::new().unwrap();
        BigNumRef::mod_add(&mut t, &self.0, &rhs.0, &n.0, &mut ctx).unwrap();
        Bn(t)
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut t = BigNum::new().unwrap();
        BigNumRef::mod_sub(&mut t, &self.0, &rhs.0, &n.0, &mut ctx).unwrap();
        Bn(t)
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut t = BigNum::new().unwrap();
        BigNumRef::mod_mul(&mut t, &self.0, &rhs.0, &n.0, &mut ctx).unwrap();
        Bn(t)
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut s = BigNum::new().unwrap();
        let mut t = BigNum::new().unwrap();
        BigNumRef::mod_inverse(&mut s, &rhs.0, &n.0, &mut ctx).unwrap();
        BigNumRef::mod_mul(&mut t, &self.0, &s, &n.0, &mut ctx).unwrap();
        Bn(t)
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        let mut t = self.clone() % n.clone();
        t = n.clone() - t.clone();
        t %= n.clone();
        t
    }

    /// Compute self mod n
    pub fn nmod(&self, n: &Self) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut t = BigNum::new().unwrap();
        BigNumRef::nnmod(&mut t, &self.0, &n.0, &mut ctx).unwrap();
        Bn(t)
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, modulus: &Bn) -> Option<Bn> {
        if self.is_zero() || modulus.is_zero() || modulus.is_one() {
            return None;
        }
        let mut ctx = BigNumContext::new().unwrap();
        let mut bn = BigNum::new().unwrap();
        BigNumRef::mod_inverse(&mut bn, &self.0, &modulus.0, &mut ctx).unwrap();

        Some(Self(bn))
    }

    /// Return zero
    pub fn zero() -> Self {
        Self(BigNum::new().unwrap())
    }

    /// Return one
    pub fn one() -> Self {
        Self(BigNum::from_u32(1).unwrap())
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.0.num_bits() == 0
    }

    /// self == 1
    pub fn is_one(&self) -> bool {
        self.0.num_bits() == 1 && self.0.is_bit_set(0)
    }

    /// Return the bit length
    pub fn bit_length(&self) -> usize {
        self.0.num_bits() as usize
    }

    /// Compute the greatest common divisor
    pub fn gcd(&self, other: &Bn) -> Self {
        let mut bn = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::gcd(&mut bn, &self.0, &other.0, &mut ctx).unwrap();
        Self(bn)
    }

    /// Compute the least common multiple
    pub fn lcm(&self, other: &Bn) -> Self {
        if self.is_zero() && other.is_zero() {
            Self::zero()
        } else {
            self / self.gcd(other) * other
        }
    }

    /// Generate a random value less than `n`
    pub fn random(n: &Self) -> Self {
        let mut b = BigNum::new().unwrap();
        BigNumRef::rand_range(&n.0, &mut b).unwrap();
        Self(b)
    }

    /// Generate a random value less than `n` using the specific random number generator
    pub fn from_rng(n: &Self, _rng: &mut impl RngCore) -> Self {
        // OpenSSL doesn't support supplying random number generators
        Self::random(n)
    }

    /// Hash a byte sequence to a big number
    pub fn from_digest<D>(hasher: D) -> Self
    where
        D: digest::Digest,
    {
        Self(BigNum::from_slice(hasher.finalize().as_slice()).unwrap())
    }

    /// Convert a byte sequence to a big number
    pub fn from_slice<B>(b: B) -> Self
    where
        B: AsRef<[u8]>,
    {
        Self(BigNum::from_slice(b.as_ref()).unwrap())
    }

    /// Convert this big number to a big-endian byte sequence
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    pub fn extended_gcd(&self, other: &Bn) -> GcdResult {
        let mut s = (Self::zero(), Self::one());
        let mut t = (Self::one(), Self::zero());
        let mut r = (other.clone(), self.clone());

        while !r.0.is_zero() {
            let q = r.1.clone() / r.0.clone();
            let f = |mut r: (Self, Self)| {
                swap(&mut r.0, &mut r.1);
                r.0 -= q.clone() * r.1.clone();
                r
            };
            r = f(r);
            s = f(s);
            t = f(t);
        }

        if r.1 >= Self::zero() {
            GcdResult {
                gcd: r.1,
                x: s.1,
                y: t.1,
            }
        } else {
            GcdResult {
                gcd: Self::zero() - r.1,
                x: Self::zero() - s.1,
                y: Self::zero() - t.1,
            }
        }
    }

    /// Generate a safe prime with `size` bits
    pub fn safe_prime(size: usize) -> Self {
        let mut p = BigNum::new().unwrap();
        BigNumRef::generate_prime(&mut p, size as i32, true, None, None).unwrap();
        Self(p)
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> Self {
        let mut p = BigNum::new().unwrap();
        BigNumRef::generate_prime(&mut p, size as i32, false, None, None).unwrap();
        Self(p)
    }

    /// True if a prime number
    pub fn is_prime(&self) -> bool {
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::is_prime(&self.0, 15, &mut ctx).unwrap()
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let mut ctx = BigNumContext::new().unwrap();
        let mut div = BigNum::new().unwrap();
        let mut rem = BigNum::new().unwrap();
        BigNumRef::div_rem(&mut div, &mut rem, &self.0, &other.0, &mut ctx).unwrap();
        (Self(div), Self(rem))
    }
}

#[test]
fn safe_prime() {
    let n = Bn::safe_prime(1024);
    assert_eq!(n.0.num_bits(), 1024);
    assert!(n.is_prime());
    let sg: Bn = n >> 1;
    assert!(sg.is_prime())
}

#[test]
fn ct_eq() {
    let a = Bn::from(8);
    let b = Bn::from(8);

    assert_eq!(a.ct_eq(&b).unwrap_u8(), 1u8);
}
