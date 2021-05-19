use crate::GcdResult;
use gmp::{
    mpz::{Mpz, ProbabPrimeResult},
    rand::RandState,
};
use rand::RngCore;
use serde::{
    de::{Error as DError, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    fmt::{self, Debug, Display},
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, Shr, Sub,
        SubAssign,
    },
};
use zeroize::Zeroize;

/// Big number
pub struct Bn(pub(crate) Mpz);

clone_impl!(|b: &Bn| b.0.clone());
default_impl!(|| Mpz::new());
display_impl!();
eq_impl!();
from_impl!(|d: usize| Mpz::from(d as u64));
ord_impl!();
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
    /// The result will be in the interval `[0, n)` for `modulus > 0`,
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        assert_ne!(n.0, Mpz::zero());
        if exponent.0 < Mpz::new() {
            match self.invert(&n) {
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
        let mut t = (self + rhs) % n;
        if t < Bn::zero() {
            t += n;
        }
        t
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        let mut t = (self - rhs) % n;
        if t < Bn::zero() {
            t += n;
        }
        t
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let mut t = (self * rhs) % n;
        if t < Bn::zero() {
            t += n;
        }
        t
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let mut t = (self * rhs.invert(n).unwrap()) % n;
        if t < Bn::zero() {
            t += n;
        }
        t
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, modulus: &Bn) -> Option<Bn> {
        if self.is_zero() || modulus.is_zero() || modulus.is_one() {
            return None;
        }
        self.0.invert(&modulus.0).map(|b| Self(b))
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
        let mut rng = rand::rngs::OsRng::default();
        let len = (n.0.bit_length() - 1) / 8;
        let mut t = vec![0u8; len as usize];
        loop {
            rng.fill_bytes(t.as_mut_slice());
            let b = Mpz::from(t.as_slice());
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
        let s = self.0.to_str_radix(16);
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

    /// Generate a safe prime
    pub fn safe_prime(size: usize) -> Self {
        let mut rand_state = RandState::new();
        let mut p = rand_state.urandom_2exp(size as u64).nextprime();
        loop {
            while p.bit_length() != size {
                p = rand_state.urandom_2exp(size as u64).nextprime();
            }
            let p_tick = &p >> 1;
            match p_tick.probab_prime(15) {
                ProbabPrimeResult::Prime | ProbabPrimeResult::ProbablyPrime => return Self(p),
                _ => p = rand_state.urandom_2exp(size as u64).nextprime(),
            };
        }
    }

    /// Generate a prime
    pub fn prime(size: usize) -> Self {
        let mut rand_state = RandState::new();
        Self(rand_state.urandom_2exp(size as u64).nextprime())
    }

    /// True if self is a prime number
    pub fn is_prime(&self) -> bool {
        match self.0.probab_prime(15) {
            ProbabPrimeResult::Prime | ProbabPrimeResult::ProbablyPrime => true,
            _ => false,
        }
    }
}
