/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::*;
use core::hash::Hasher;
use core::{
    cmp::{self, Ordering},
    fmt::{self, Binary, Debug, Display, Formatter, LowerHex, Octal, UpperHex},
    hash::Hash,
    mem,
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
        ShrAssign, Sub, SubAssign,
    },
    str::FromStr,
};
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{
    modular::runtime_mod, rand_core, CheckedAdd, CheckedMul, CheckedSub, Encoding, Integer,
    NonZero, RandomMod, Zero, U4096,
};
use num_traits::PrimInt;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use subtle::{Choice, ConstantTimeEq};

type InnerRep = U4096;
const INNER_LIMBS: usize = 512;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Sign {
    Minus,
    NoSign,
    Plus,
}

impl Neg for Sign {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        match self {
            Self::Minus => Self::Plus,
            Self::NoSign => Self::NoSign,
            Self::Plus => Self::Minus,
        }
    }
}

impl Mul for Sign {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Sign::NoSign, _) | (_, Sign::NoSign) => Sign::NoSign,
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => Sign::Plus,
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => Sign::Minus,
        }
    }
}

impl Display for Sign {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Minus => "-",
                _ => "",
            }
        )
    }
}

impl FromStr for Sign {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "-" => Ok(Self::Minus),
            _ => Ok(Self::Plus),
        }
    }
}

impl Serialize for Sign {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            match self {
                Self::Minus => "-".serialize(s),
                Self::NoSign => "00".serialize(s),
                Self::Plus => None::<&str>.serialize(s),
            }
        } else {
            match self {
                Self::Minus => (-1i8).serialize(s),
                Self::NoSign => (0i8).serialize(s),
                Self::Plus => (1i8).serialize(s),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Sign {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            struct SignStrVisitor;

            impl<'de> Visitor<'de> for SignStrVisitor {
                type Value = Sign;

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "00, -, or empty")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if v.is_empty() {
                        Ok(Sign::Plus)
                    } else if v == "00" {
                        Ok(Sign::NoSign)
                    } else if v == "-" {
                        Ok(Sign::Minus)
                    } else {
                        Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
                    }
                }
            }
            d.deserialize_str(SignStrVisitor)
        } else {
            let sign = i8::deserialize(d)?;
            match sign {
                -1i8 => Ok(Sign::Minus),
                0i8 => Ok(Sign::NoSign),
                1i8 => Ok(Sign::Plus),
                _ => Err(de::Error::invalid_value(
                    de::Unexpected::Signed(sign.into()),
                    &"-1, 0, or 1",
                )),
            }
        }
    }
}

impl Sign {
    /// [`true`] if == Minus
    pub fn is_negative(&self) -> bool {
        self == &Self::Minus
    }

    /// [`true`] if == NoSign
    pub fn is_zero(&self) -> bool {
        self == &Self::NoSign
    }

    /// [`true`] if == Plus
    pub fn is_positive(&self) -> bool {
        self == &Self::Plus
    }
}

/// Big number that handle up to 4096-bits
pub struct Bn {
    pub(crate) sign: Sign,
    pub(crate) value: InnerRep,
}

impl Clone for Bn {
    fn clone(&self) -> Self {
        Self {
            sign: self.sign,
            value: self.value,
        }
    }
}

impl Default for Bn {
    fn default() -> Self {
        Self {
            sign: Sign::NoSign,
            value: InnerRep::default(),
        }
    }
}

impl Display for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // The default formatter leaves lots of zeros, so we trim them to help with readability
        let lz = self.value.leading_zeros() / 8;
        let repr = multibase::encode(multibase::Base::Base10, &self.value.to_be_bytes()[lz..]);
        // The leading digit will be a '9' to indicate the encoding so drop it
        write!(f, "{}{}", self.sign, &repr[1..])
    }
}

impl Debug for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:?}", self.sign, self.value)
    }
}

impl Binary for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in &bytes {
            write!(f, "{:b}", b)?;
        }
        Ok(())
    }
}

impl Octal for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in &bytes {
            write!(f, "{:o}", b)?;
        }
        Ok(())
    }
}

impl LowerHex for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in &bytes {
            write!(f, "{:x}", b)?;
        }
        Ok(())
    }
}

impl UpperHex for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in &bytes {
            write!(f, "{:X}", b)?;
        }
        Ok(())
    }
}

impl Eq for Bn {}

impl PartialEq for Bn {
    fn eq(&self, other: &Self) -> bool {
        self.sign == other.sign && self.value == other.value
    }
}

impl PartialOrd for Bn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bn {
    fn cmp(&self, other: &Self) -> Ordering {
        let scmp = self.sign.cmp(&other.sign);
        if scmp != Ordering::Equal {
            return scmp;
        }

        match self.sign {
            Sign::NoSign => Ordering::Equal,
            Sign::Plus => self.value.cmp(&other.value),
            Sign::Minus => other.value.cmp(&self.value),
        }
    }
}

impl Hash for Bn {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sign.hash(state);
        self.value.hash(state);
    }
}

macro_rules! from_uint_impl {
    ($($type:tt),+$(,)*) => {
        $(
            impl From<$type> for Bn {
                fn from(value: $type) -> Self {
                    Self {
                        sign: if value != 0 { Sign::Plus } else { Sign::NoSign },
                        value: InnerRep::from(value)
                    }
                }
            }
        )+
    };
}

macro_rules! from_sint_impl {
    ($($stype:tt => $utype:tt),+$(,)*) => {
        $(
            impl From<$stype> for Bn {
                fn from(value: $stype) -> Self {
                    let (sign, value) = match 0.cmp(&value) {
                            Ordering::Greater => (Sign::Minus, (-value) as $utype),
                            Ordering::Equal => (Sign::NoSign, 0 as $utype),
                            Ordering::Less => (Sign::Plus, value as $utype),
                    };
                    Self {
                        sign,
                        value: InnerRep::from(value)
                    }
                }
            }
        )+
    };
}

impl From<usize> for Bn {
    fn from(value: usize) -> Self {
        Self {
            sign: if value == 0 { Sign::NoSign } else { Sign::Plus },
            value: InnerRep::from(value as u64),
        }
    }
}

#[cfg(target_pointer_width = "64")]
from_uint_impl!(u128);
from_uint_impl!(u64, u32, u16, u8);
#[cfg(target_pointer_width = "64")]
from_sint_impl!(i128 => u128);
from_sint_impl!(isize => u64, i64 => u64, i32 => u32, i16 => u16, i8 => u8);

impl Neg for Bn {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            sign: -self.sign,
            value: self.value,
        }
    }
}

impl Neg for &Bn {
    type Output = Bn;

    fn neg(self) -> Self::Output {
        Bn {
            sign: -self.sign,
            value: self.value,
        }
    }
}

impl<'a, 'b> Add<&'a Bn> for &'b Bn {
    type Output = Bn;

    fn add(self, rhs: &'a Bn) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::NoSign) => self.clone(),
            (Sign::NoSign, _) => rhs.clone(),
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => Bn {
                sign: self.sign,
                value: self.value.checked_add(&rhs.value).unwrap(),
            },
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => {
                match self.value.cmp(&rhs.value) {
                    Ordering::Less => Bn {
                        sign: rhs.sign,
                        value: rhs.value.checked_sub(&self.value).unwrap(),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: self.value.checked_sub(&rhs.value).unwrap(),
                    },
                    Ordering::Equal => Bn::default(),
                }
            }
        }
    }
}

impl Add<Bn> for &Bn {
    type Output = Bn;

    fn add(self, rhs: Bn) -> Self::Output {
        self + &rhs
    }
}

impl Add<&Bn> for Bn {
    type Output = Self;

    fn add(self, rhs: &Bn) -> Self::Output {
        &self + rhs
    }
}

impl Add for Bn {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl AddAssign for Bn {
    fn add_assign(&mut self, rhs: Self) {
        let n = mem::replace(self, Bn::zero());
        *self = n + rhs;
    }
}

impl AddAssign<&Bn> for Bn {
    fn add_assign(&mut self, rhs: &Bn) {
        let n = mem::replace(self, Bn::zero());
        *self = n + rhs;
    }
}

impl<'a, 'b> Sub<&'a Bn> for &'b Bn {
    type Output = Bn;

    fn sub(self, rhs: &'a Bn) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::NoSign) => self.clone(),
            (Sign::NoSign, _) => rhs.clone(),
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => Bn {
                sign: self.sign,
                value: self.value.checked_add(&rhs.value).unwrap(),
            },
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => {
                match self.value.cmp(&rhs.value) {
                    Ordering::Less => Bn {
                        sign: -self.sign,
                        value: rhs.value.checked_sub(&self.value).unwrap(),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: self.value.checked_sub(&rhs.value).unwrap(),
                    },
                    Ordering::Equal => Bn::zero(),
                }
            }
        }
    }
}

impl Sub<Bn> for &Bn {
    type Output = Bn;

    fn sub(self, rhs: Bn) -> Self::Output {
        self - &rhs
    }
}

impl Sub<&Bn> for Bn {
    type Output = Self;

    fn sub(self, rhs: &Bn) -> Self::Output {
        &self - rhs
    }
}

impl Sub for Bn {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl SubAssign for Bn {
    fn sub_assign(&mut self, rhs: Self) {
        let n = mem::replace(self, Bn::zero());
        *self = n - rhs;
    }
}

impl SubAssign<&Bn> for Bn {
    fn sub_assign(&mut self, rhs: &Bn) {
        let n = mem::replace(self, Bn::zero());
        *self = n - rhs;
    }
}

impl<'a, 'b> Mul<&'a Bn> for &'b Bn {
    type Output = Bn;

    fn mul(self, rhs: &'a Bn) -> Self::Output {
        Bn {
            sign: self.sign * rhs.sign,
            value: self.value.checked_mul(&rhs.value).unwrap(),
        }
    }
}

impl Mul<Bn> for &Bn {
    type Output = Bn;

    fn mul(self, rhs: Bn) -> Self::Output {
        self * &rhs
    }
}

impl Mul<&Bn> for Bn {
    type Output = Self;

    fn mul(self, rhs: &Bn) -> Self::Output {
        &self * rhs
    }
}

impl Mul for Bn {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl MulAssign<&Bn> for Bn {
    fn mul_assign(&mut self, rhs: &Bn) {
        self.value = self.value.saturating_mul(&rhs.value);
        if rhs.is_zero() || self.value.is_zero().into() {
            self.sign = Sign::NoSign;
        } else {
            self.sign = self.sign * rhs.sign;
        }
    }
}

impl MulAssign for Bn {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl<'a, 'b> Div<&'a Bn> for &'b Bn {
    type Output = Bn;

    fn div(self, rhs: &'a Bn) -> Self::Output {
        let (q, _) = self.div_rem(rhs);
        q
    }
}

impl Div<Bn> for &Bn {
    type Output = Bn;

    fn div(self, rhs: Bn) -> Self::Output {
        self / &rhs
    }
}

impl Div<&Bn> for Bn {
    type Output = Self;

    fn div(self, rhs: &Bn) -> Self::Output {
        &self / rhs
    }
}

impl Div for Bn {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        &self / &rhs
    }
}

impl DivAssign<&Bn> for Bn {
    fn div_assign(&mut self, rhs: &Bn) {
        *self = &*self / rhs;
    }
}

impl DivAssign for Bn {
    fn div_assign(&mut self, rhs: Self) {
        *self = &*self / rhs;
    }
}

impl<'a, 'b> Rem<&'a Bn> for &'b Bn {
    type Output = Bn;

    fn rem(self, rhs: &'a Bn) -> Self::Output {
        let (_, r) = self.div_rem(rhs);
        r
    }
}

impl Rem<Bn> for &Bn {
    type Output = Bn;

    fn rem(self, rhs: Bn) -> Self::Output {
        self % &rhs
    }
}

impl Rem<&Bn> for Bn {
    type Output = Self;

    fn rem(self, rhs: &Bn) -> Self::Output {
        &self % rhs
    }
}

impl Rem for Bn {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        &self % &rhs
    }
}

impl RemAssign<&Bn> for Bn {
    fn rem_assign(&mut self, rhs: &Bn) {
        *self = &*self % rhs;
    }
}

impl RemAssign for Bn {
    fn rem_assign(&mut self, rhs: Self) {
        *self = &*self % &rhs;
    }
}

macro_rules! shift_impl {
    (@ref $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:expr, $($rhs:ty),+) => {$(
        impl<'a> $ops<$rhs> for &'a Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                $opr(&self, rhs)
            }
        }

        impl $ops<$rhs> for Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                $opr(&self, rhs)
            }
        }

        impl $ops_assign<$rhs> for Bn {
            fn $func_assign(&mut self, rhs: $rhs) {
                *self = $opr(self, rhs);
            }
        }
    )*};
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:expr) => {
        shift_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, u8, u16, u32, u64, usize);
        shift_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, i8, i16, i32, i64, isize);
    };
}

shift_impl!(Shl, shl, ShlAssign, shl_assign, inner_shl);
shift_impl!(Shr, shr, ShrAssign, shr_assign, inner_shr);

fn inner_shl<T: PrimInt>(lhs: &Bn, rhs: T) -> Bn {
    let v = lhs.value << rhs.to_usize().unwrap();
    if v.is_zero().into() {
        Bn::zero()
    } else {
        Bn {
            sign: lhs.sign,
            value: v,
        }
    }
}

/// Idea borrowed from [num-bigint](https://github.com/rust-num/num-bigint/blob/master/src/bigint/shift.rs#L100)
/// Negative values need a rounding adjustment if there are any ones in the
/// bits that get shifted out.
fn shr_round_down<T: PrimInt>(n: &Bn, shift: T) -> bool {
    if n.sign.is_negative() {
        let zeros = n.value.trailing_zeros();
        shift > T::zero() && shift.to_usize().map(|shift| zeros < shift).unwrap_or(true)
    } else {
        false
    }
}

fn inner_shr<T: PrimInt>(lhs: &Bn, rhs: T) -> Bn {
    let round_down = shr_round_down(lhs, rhs);
    let value = lhs.value >> rhs.to_usize().unwrap();
    let value = if round_down {
        value.saturating_add(&InnerRep::ONE)
    } else {
        value
    };
    Bn {
        sign: lhs.sign,
        value,
    }
}

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl Serialize for Bn {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            alloc::format!("{}{:x}", self.sign, self.value).serialize(s)
        } else {
            (self.sign, &self.value).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for Bn {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let s = alloc::string::String::deserialize(d)?;
            if s.starts_with('-') {
                let zero_padding = "0".repeat(1024 - (s.len() - 1));
                let value = InnerRep::from_be_hex(&alloc::format!("{}{}", zero_padding, &s[1..]));
                Ok(Bn {
                    sign: Sign::Minus,
                    value,
                })
            } else {
                let zero_padding = if s.len() < 1024 {
                    "0".repeat(1024 - s.len())
                } else {
                    alloc::string::String::new()
                };
                let value = InnerRep::from_be_hex(&alloc::format!("{}{}", zero_padding, &s[..]));
                if value.is_zero().into() {
                    Ok(Bn::zero())
                } else {
                    Ok(Bn {
                        sign: Sign::Plus,
                        value,
                    })
                }
            }
        } else {
            let (sign, value) = Deserialize::deserialize(d)?;
            Ok(Bn { sign, value })
        }
    }
}

impl Bn {
    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        assert_ne!(n.value.is_zero().unwrap_u8(), 1u8);
        let params = runtime_mod::DynResidueParams::new(&n.value);
        let mm = match exponent.sign {
            Sign::NoSign => return Self::one(),
            Sign::Minus => match self.invert(n) {
                None => return Self::zero(),
                Some(a) => runtime_mod::DynResidue::new(&a.value, params),
            },
            Sign::Plus => runtime_mod::DynResidue::new(&self.value, params),
        };

        let value = mm.pow(&exponent.value).retrieve();

        let odd = exponent.value.is_odd().into();

        let (sign, value) = match (self.sign.is_negative() && odd, n.sign.is_negative()) {
            (true, false) => (Sign::Plus, n.value.saturating_sub(&value)),
            (_, _) => (Sign::Plus, value),
        };
        Self {
            sign: if value.is_zero().into() {
                Sign::NoSign
            } else {
                sign
            },
            value,
        }
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        match (self.sign, rhs.sign) {
            (_, Sign::NoSign) => {
                let mut bn = Self {
                    sign: self.sign,
                    value: self.value.add_mod(&InnerRep::ZERO, &n.value),
                };
                if bn.sign.is_negative() {
                    bn.value = bn.value.saturating_add(&n.value);
                    -bn
                } else {
                    bn
                }
            }
            (Sign::NoSign, _) => {
                let mut bn = Self {
                    sign: rhs.sign,
                    value: rhs.value.add_mod(&InnerRep::ZERO, &n.value),
                };
                if bn.sign.is_negative() {
                    bn.value = bn.value.saturating_add(&n.value);
                    -bn
                } else {
                    bn
                }
            }
            (Sign::Plus, Sign::Plus) => Self {
                sign: self.sign,
                value: self.value.add_mod(&rhs.value, &n.value),
            },
            (Sign::Minus, Sign::Minus) => {
                let value = self.value.add_mod(&rhs.value, &n.value);
                Self {
                    sign: Sign::Plus,
                    value: value.saturating_add(&n.value),
                }
            }
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => {
                let mut bn = match self.value.cmp(&rhs.value) {
                    Ordering::Less => Self {
                        sign: rhs.sign,
                        value: rhs.value.sub_mod(&self.value, &n.value),
                    },
                    Ordering::Greater => Self {
                        sign: self.sign,
                        value: self.value.sub_mod(&rhs.value, &n.value),
                    },
                    Ordering::Equal => Self::zero(),
                };
                if bn.sign.is_negative() {
                    bn.value = bn.value.saturating_add(&n.value);
                    -bn
                } else {
                    bn
                }
            }
        }
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        self.modadd(&-rhs, n)
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let params = runtime_mod::DynResidueParams::new(&n.value);
        let l = runtime_mod::DynResidue::new(&self.value, params);
        let r = runtime_mod::DynResidue::new(&rhs.value, params);

        let result = l.mul(&r).retrieve();
        let sign = if result.is_zero().into() {
            Sign::NoSign
        } else {
            self.sign * rhs.sign
        };

        match sign {
            Sign::NoSign => Self::zero(),
            Sign::Plus => Self {
                sign,
                value: result,
            },
            Sign::Minus => Self {
                sign: Sign::Plus,
                value: result.saturating_add(&n.value),
            },
        }
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let params = runtime_mod::DynResidueParams::new(&n.value);
        let r = runtime_mod::DynResidue::new(&rhs.value, params);

        let (r, valid) = r.invert();

        if bool::from(valid) {
            return Self::zero();
        }
        let rhs = Self {
            sign: rhs.sign,
            value: r.retrieve(),
        };
        self.modmul(&rhs, n)
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        let params = runtime_mod::DynResidueParams::new(&n.value);
        let r = runtime_mod::DynResidue::new(&self.value, params);
        let value = (-r).retrieve();

        if self.sign.is_zero() || value.is_zero().into() {
            Self::zero()
        } else {
            Self {
                sign: -self.sign,
                value,
            }
        }
    }

    /// Compute self mod n
    pub fn nmod(&self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut out = self.clone() % nn;
        if out < Self::zero() {
            out += n;
        }
        out
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, n: &Self) -> Option<Self> {
        if self.is_zero() || n.is_zero() || n.is_one() {
            return None;
        }
        if n.value.is_odd().into() {
            let (i, exists) = self.value.inv_odd_mod(&n.value);
            if exists.into() {
                Some(Self {
                    sign: self.sign,
                    value: i,
                })
            } else {
                None
            }
        } else {
            let params = runtime_mod::DynResidueParams::new(&n.value);
            let r = runtime_mod::DynResidue::new(&self.value, params);
            let (r, valid) = r.invert();
            if valid.into() {
                Some(Self {
                    sign: self.sign,
                    value: r.retrieve(),
                })
            } else {
                None
            }
        }
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.sign.is_zero() || self.value.is_zero().into()
    }

    /// self == 1
    pub fn is_one(&self) -> bool {
        self.sign.is_positive() && self.value.ct_eq(&InnerRep::ONE).into()
    }

    /// Return the bit length
    pub fn bit_length(&self) -> usize {
        self.value.bits()
    }

    /// Compute the greatest common divisor
    pub fn gcd(&self, other: &Self) -> Self {
        // borrowed from num-bigint/src/biguint.rs

        // Stein's algorithm
        if self.is_zero() {
            return other.clone();
        }
        if other.is_zero() {
            return self.clone();
        }
        let mut m = self.clone();
        let mut n = other.clone();

        // find common factors of 2
        let shift = cmp::min(n.value.trailing_zeros(), m.value.trailing_zeros());

        // divide m and n by 2 until odd
        // m inside loop
        n >>= n.value.trailing_zeros();

        while !m.is_zero() {
            m >>= m.value.trailing_zeros();
            if n > m {
                mem::swap(&mut n, &mut m)
            }
            m -= &n;
        }

        n << shift
    }

    /// Compute the least common multiple
    pub fn lcm(&self, other: &Self) -> Self {
        if self.is_zero() && other.is_zero() {
            Self::zero()
        } else {
            self / self.gcd(other) * other
        }
    }

    /// Generate a random value less than `n`
    pub fn random(n: &Self) -> Self {
        Self::from_rng(n, &mut rand_core::OsRng)
    }

    /// Generate a random value less than `n` using the specific random number generator
    pub fn from_rng(n: &Self, rng: &mut impl CryptoRngCore) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        Self {
            sign: Sign::Plus,
            value: InnerRep::random_mod(rng, &NonZero::new(n.value).unwrap()),
        }
    }

    /// Hash a byte sequence to a big number
    pub fn from_digest<D>(hasher: D) -> Self
    where
        D: digest::Digest,
    {
        Self::from_slice(hasher.finalize().as_slice())
    }

    /// Convert a byte sequence to a big number
    pub fn from_slice<B>(b: B) -> Self
    where
        B: AsRef<[u8]>,
    {
        let b = b.as_ref();
        if b.len() <= INNER_LIMBS {
            let mut tmp = [0u8; INNER_LIMBS];
            tmp[INNER_LIMBS - b.len()..].copy_from_slice(b);
            Self {
                sign: Sign::Plus,
                value: InnerRep::from_be_slice(&tmp),
            }
        } else {
            panic!("bytes are not the expected size");
        }
    }

    /// Convert this big number to a big-endian byte sequence, the sign is not included
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        self.value.to_be_bytes().as_ref().to_vec()
    }

    /// Convert this big number to a big-endian byte sequence and store it in `buffer`.
    /// The sign is not included
    pub fn copy_bytes_into_buffer(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.value.to_be_bytes())
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    #[allow(clippy::many_single_char_names)]
    pub fn extended_gcd(&self, other: &Self) -> GcdResult {
        let mut s = (Self::zero(), Self::one());
        let mut t = (Self::one(), Self::zero());
        let mut r = (other.clone(), self.clone());

        while !r.0.is_zero() {
            let q = r.1.clone() / r.0.clone();
            let f = |mut r: (Self, Self)| {
                mem::swap(&mut r.0, &mut r.1);
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
        Self::safe_prime_from_rng(size, &mut rand_core::OsRng)
    }

    /// Generate a safe prime with `size` bits with a user-provided rng
    pub fn safe_prime_from_rng(size: usize, rng: &mut impl CryptoRngCore) -> Self {
        Self {
            sign: Sign::Plus,
            value: crypto_primes::generate_safe_prime_with_rng(rng, Some(size)),
        }
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> Self {
        Self::prime_from_rng(size, &mut rand_core::OsRng)
    }

    /// Generate a prime with `size` bits with a user-provided rng
    pub fn prime_from_rng(size: usize, rng: &mut impl CryptoRngCore) -> Self {
        Self {
            sign: Sign::Plus,
            value: crypto_primes::generate_prime_with_rng(rng, Some(size)),
        }
    }

    /// True if a prime number
    pub fn is_prime(&self) -> bool {
        crypto_primes::is_prime_with_rng(&mut rand_core::OsRng, &self.value)
    }

    /// Return zero
    pub fn zero() -> Self {
        Self::default()
    }

    /// Return one
    pub fn one() -> Self {
        Self {
            sign: Sign::Plus,
            value: InnerRep::ONE,
        }
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (d, r) = self.value.div_rem(&NonZero::new(other.value).unwrap());
        let rem_sign = if r.is_zero().into() {
            Sign::NoSign
        } else {
            Sign::Plus
        };
        if other.sign == Sign::Minus {
            (
                Self {
                    sign: -self.sign,
                    value: d,
                },
                Self {
                    sign: rem_sign,
                    value: r,
                },
            )
        } else {
            (
                Self {
                    sign: self.sign,
                    value: d,
                },
                Self {
                    sign: rem_sign,
                    value: r,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() {
        let (_, v1) =
            multibase::decode("9595374401003766034096130243798882341754528442149").unwrap();
        let (_, v2) =
            multibase::decode("9365375409332725729550921208179070754913983243889").unwrap();
        let (_, v3) =
            multibase::decode("9960749810336491763647051451977953096668511686038").unwrap();
        let (_, v4) =
            multibase::decode("9229998991671040304545209035619811586840545198260").unwrap();
        let (_, v5) = multibase::decode("9217535165472977407178102302905245480306183692659917226463581384024497196271511427656856694277461").unwrap();
        let bn1 = Bn::from_slice(v1.as_slice());
        let bn2 = Bn::from_slice(v2.as_slice());
        let bn3 = Bn::from_slice(v3.as_slice());
        let bn4 = Bn::from_slice(v4.as_slice());
        let bn5 = Bn::from_slice(v5.as_slice());
        assert_eq!(&bn1 + &bn2, bn3);
        assert_eq!(&bn1 - &bn2, bn4);
        assert_eq!(&bn2 - &bn1, -bn4);
        assert_eq!(&bn1 * &bn2, bn5);
        assert_eq!(&bn1 * -&bn2, -bn5.clone());
        assert_eq!(&-bn1 * -&bn2, bn5);
    }

    #[test]
    fn primes() {
        let p1 = Bn::prime_from_rng(256, &mut rand_core::OsRng);
        assert!(p1.is_prime());
    }
}
