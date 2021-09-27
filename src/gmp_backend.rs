/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{get_mod, GcdResult};
use gmp::mpz::{mpz_ptr, mpz_srcptr, Mpz, ProbabPrimeResult};
use rand::RngCore;
use serde::{
    de::{Error as DError, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    cmp::{Eq, PartialEq, PartialOrd},
    fmt::{self, Debug, Display},
    iter::{Product, Sum},
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, Shr, Sub,
        SubAssign,
    },
};
use zeroize::Zeroize;

/// Big number
#[derive(Ord, PartialOrd)]
pub struct Bn(pub(crate) Mpz);

fn from_isize(d: isize) -> Mpz {
    if d < 0 {
        -Mpz::from(-d as u64)
    } else {
        Mpz::from(d as u64)
    }
}

clone_impl!(|b: &Bn| b.0.clone());
default_impl!(|| Mpz::new());
display_impl!();
eq_impl!();
#[cfg(target_pointer_width = "64")]
from_impl!(
    |d: i128| {
        if d < 0 {
            -Mpz::from(&(-d).to_be_bytes()[..])
        } else {
            Mpz::from(&d.to_be_bytes()[..])
        }
    },
    i128
);
#[cfg(target_pointer_width = "64")]
from_impl!(|d: u128| { Mpz::from(&d.to_be_bytes()[..]) }, u128);
from_impl!(|d: usize| Mpz::from(d as u64), usize);
from_impl!(|d: u64| Mpz::from(d), u64);
from_impl!(|d: u32| Mpz::from(d as u64), u32);
from_impl!(|d: u16| Mpz::from(d as u64), u16);
from_impl!(|d: u8| Mpz::from(d as u64), u8);
from_impl!(from_isize, isize);
from_impl!(|d: i64| from_isize(d as isize), i64);
from_impl!(|d: i32| from_isize(d as isize), i32);
from_impl!(|d: i16| from_isize(d as isize), i16);
from_impl!(|d: i8| from_isize(d as isize), i8);
iter_impl!();
serdes_impl!(
    |b: &Bn| b.0.to_str_radix(16),
    |s: &str| Mpz::from_str_radix(s, 16)
);
zeroize_impl!(|b: &mut Bn| b.0 -= b.0.clone());

binops_impl!(Add, add, AddAssign, add_assign, +, +=);
binops_impl!(Sub, sub, SubAssign, sub_assign, -, -=);
binops_impl!(Mul, mul, MulAssign, mul_assign, *, *=);
binops_impl!(Div, div, DivAssign, div_assign, /, /=);
binops_impl!(Rem, rem, RemAssign, rem_assign, %, %=);
neg_impl!(|b: &Mpz| Bn(-b));
shift_impl!(Shl, shl, |lhs, rhs| Bn(lhs << (rhs as usize)));
shift_impl!(Shr, shr, |lhs, rhs| Bn(lhs >> (rhs as usize)));

impl Bn {
    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        assert_ne!(n.0, Mpz::zero());
        if exponent.0 < Mpz::new() {
            match self.invert(n) {
                None => Self::zero(),
                Some(a) => {
                    let e = -exponent.0.clone();
                    Self(a.0.powm_sec(&e, &n.0))
                }
            }
        } else {
            Self(self.0.powm_sec(&exponent.0, &n.0))
        }
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (self + rhs) % &nn;
        if t < Bn::zero() {
            t += &nn;
        }
        t
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (self - rhs) % &nn;
        if t < Bn::zero() {
            t += &nn;
        }
        t
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (self * rhs) % &nn;
        if t < Bn::zero() {
            t += &nn;
        }
        t
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        match rhs.invert(&nn) {
            None => Self::zero(),
            Some(r) => {
                let mut t = (self * r) % &nn;
                if t < Bn::zero() {
                    t += &nn;
                }
                t
            }
        }
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        let mut t = self.clone() % n.clone();
        t = n.clone() - t.clone();
        t %= n.clone();
        t
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, modulus: &Bn) -> Option<Bn> {
        if self.is_zero() || modulus.is_zero() || modulus.is_one() {
            return None;
        }
        self.0.invert(&modulus.0).map(Self)
    }

    /// Return zero
    pub fn zero() -> Self {
        Self(Mpz::new())
    }

    /// Return one
    pub fn one() -> Self {
        Self(Mpz::from(1))
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// self == 1
    pub fn is_one(&self) -> bool {
        self.0 == Mpz::one()
    }

    /// Compute the greatest common divisor
    pub fn gcd(&self, other: &Bn) -> Self {
        Self(self.0.gcd(&other.0))
    }

    /// Compute the least common multiple
    pub fn lcm(&self, other: &Bn) -> Self {
        Self(self.0.lcm(&other.0))
    }

    /// Generate a random value less than `n`
    pub fn random(n: &Self) -> Self {
        let size = n.0.bit_length();

        loop {
            let b = _random_nbit(size);

            if b < n.0 {
                return Self(b);
            }
        }
    }

    /// Hash a byte sequence to a big number
    pub fn from_digest<D>(hasher: D) -> Self
    where
        D: digest::Digest,
    {
        Self(Mpz::from(hasher.finalize().as_slice()))
    }

    /// Convert a byte sequence to a big number
    pub fn from_slice<B>(b: B) -> Self
    where
        B: AsRef<[u8]>,
    {
        Self(Mpz::from(b.as_ref()))
    }

    /// Convert this big number to a big-endian byte sequence
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut s = self.0.to_str_radix(16);
        if s.len() & 1 == 1 {
            s = format!("0{}", s);
        }
        hex::decode(&s).unwrap()
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    pub fn extended_gcd(&self, other: &Bn) -> GcdResult {
        let (gcd, x, y) = self.0.gcdext(&other.0);
        GcdResult {
            gcd: Self(gcd),
            x: Self(x),
            y: Self(y),
        }
    }

    /// Generate a safe prime with `size` bits
    pub fn safe_prime(size: usize) -> Self {
        let mut p = _random_nbit(size - 1);

        // Set the MSB bit so that we're sampling from [2^(size - 2), 2^(size - 1))
        p.setbit(size - 2);

        loop {
            p = p.nextprime();
            p <<= 1;
            p += 1;

            // Using 25 to mimic GMP's use of 25 rounds in nextprime
            if let ProbabPrimeResult::Prime | ProbabPrimeResult::ProbablyPrime = p.probab_prime(25)
            {
                return Self(p);
            };

            p >>= 1;
        }
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> Self {
        let mut p = _random_nbit(size);

        // Set the MSB bit so that we're sampling from [2^(size - 1), 2^size)
        p.setbit(size - 1);

        p = p.nextprime();

        Self(p)
    }

    /// True if a prime number
    pub fn is_prime(&self) -> bool {
        matches!(
            self.0.probab_prime(25),
            ProbabPrimeResult::Prime | ProbabPrimeResult::ProbablyPrime
        )
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (q, r) = _div_rem(&self.0, &other.0);
        (Self(q), Self(r))
    }
}

#[link(name = "gmp")]
extern "C" {
    fn __gmpz_tdiv_qr(q: mpz_ptr, r: mpz_ptr, n: mpz_srcptr, d: mpz_srcptr);
}

fn _div_rem(lhs: &Mpz, rhs: &Mpz) -> (Mpz, Mpz) {
    // SAFETY: q, r, lhs, and rhs are all initialized
    // Note: There probably is UB in the implementation of Mpz::new() since it uses the deprecated
    // [uninitialized](https://doc.rust-lang.org/std/mem/fn.uninitialized.html) function instead
    // of [MaybeUninit](https://doc.rust-lang.org/std/mem/fn.uninitialized.html)
    unsafe {
        if rhs.is_zero() {
            panic!("divide by zero");
        }

        let mut q = Mpz::new();
        let mut r = Mpz::new();
        __gmpz_tdiv_qr(q.inner_mut(), r.inner_mut(), lhs.inner(), rhs.inner());

        (q, r)
    }
}

/// Sample a bignum from [0, 2^size)
fn _random_nbit(size: usize) -> Mpz {
    let len = (size + 7) / 8;
    let mut buf = vec![0u8; len];

    let mut rng = rand::thread_rng();

    rng.fill_bytes(&mut buf);

    let mut x = Mpz::from(buf.as_ref());
    x >>= len * 8 - size;

    x
}

#[test]
fn safe_prime() {
    let n = Bn::safe_prime(1024);
    assert_eq!(n.0.bit_length(), 1024);
    assert!(n.is_prime());
    let sg: Bn = &n >> 1;
    assert!(sg.is_prime());
    // Make sure it doesn't produce the same prime when called twice
    let m = Bn::safe_prime(1024);
    assert_eq!(m.0.bit_length(), 1024);
    assert!(m.is_prime());
    let sg: Bn = &m >> 1;
    assert!(sg.is_prime());
    assert_ne!(n, m);
}

#[test]
fn div_rem_test() {
    let a = Bn::from(11);
    let b = Bn::from(3);
    let (q, r) = a.div_rem(&b);
    assert_eq!(q, Bn::from(3));
    assert_eq!(r, Bn::from(2));

    let a = Bn::from(23);
    let b = Bn::from(10);
    let (q, r) = a.div_rem(&b);
    assert_eq!(q, Bn::from(2));
    assert_eq!(r, Bn::from(3));
}
