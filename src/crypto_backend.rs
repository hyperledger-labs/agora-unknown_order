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
    NonZero, RandomMod, Uint, Zero,
};
use num_traits::PrimInt;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// The default big number type
pub type DefaultBn = Bn<64>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Sign {
    Minus,
    None,
    Plus,
}

impl Neg for Sign {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        match self {
            Self::Minus => Self::Plus,
            Self::None => Self::None,
            Self::Plus => Self::Minus,
        }
    }
}

impl Mul for Sign {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Sign::None, _) | (_, Sign::None) => Sign::None,
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
                Self::None => "00".serialize(s),
                Self::Plus => None::<&str>.serialize(s),
            }
        } else {
            i8::from(self).serialize(s)
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
                        Ok(Sign::None)
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
            Self::try_from(sign).map_err(|_| {
                de::Error::invalid_value(de::Unexpected::Signed(sign.into()), &"-1, 0, or 1")
            })
        }
    }
}

impl From<Sign> for i8 {
    fn from(sign: Sign) -> i8 {
        match sign {
            Sign::Minus => -1,
            Sign::None => 0,
            Sign::Plus => 1,
        }
    }
}

impl From<&Sign> for i8 {
    fn from(sign: &Sign) -> i8 {
        i8::from(*sign)
    }
}

impl TryFrom<i8> for Sign {
    type Error = &'static str;

    fn try_from(sign: i8) -> Result<Self, Self::Error> {
        match sign {
            -1 => Ok(Sign::Minus),
            0 => Ok(Sign::None),
            1 => Ok(Sign::Plus),
            _ => Err("expected -1, 0, or 1"),
        }
    }
}

impl ConstantTimeEq for Sign {
    fn ct_eq(&self, other: &Self) -> Choice {
        i8::from(self).ct_eq(&i8::from(other))
    }
}

impl Sign {
    /// [`true`] if == Minus
    pub fn is_negative(&self) -> bool {
        self == &Self::Minus
    }

    /// [`true`] if == NoSign
    pub fn is_zero(&self) -> bool {
        self == &Self::None
    }

    /// [`true`] if == Plus
    pub fn is_positive(&self) -> bool {
        self == &Self::Plus
    }
}

/// Big number that handle up to 4096-bits
pub struct Bn<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    pub(crate) sign: Sign,
    pub(crate) value: Uint<LIMBS>,
}

impl<const LIMBS: usize> Clone for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn clone(&self) -> Self {
        Self {
            sign: self.sign,
            value: self.value,
        }
    }
}

impl<const LIMBS: usize> Default for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self {
            sign: Sign::None,
            value: Uint::<LIMBS>::ZERO,
        }
    }
}

impl<const LIMBS: usize> Display for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // The default formatter leaves lots of zeros, so we trim them to help with readability
        let lz = self.value.leading_zeros() / 8;
        let repr = multibase::encode(
            multibase::Base::Base10,
            &self.value.to_be_bytes().as_ref()[lz..],
        );
        // The leading digit will be a '9' to indicate the encoding so drop it
        write!(f, "{}{}", self.sign, &repr[1..])
    }
}

impl<const LIMBS: usize> Debug for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:?}", self.sign, self.value)
    }
}

impl<const LIMBS: usize> Binary for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in bytes.as_ref() {
            write!(f, "{:b}", b)?;
        }
        Ok(())
    }
}

impl<const LIMBS: usize> Octal for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in bytes.as_ref() {
            write!(f, "{:o}", b)?;
        }
        Ok(())
    }
}

impl<const LIMBS: usize> LowerHex for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in bytes.as_ref() {
            write!(f, "{:x}", b)?;
        }
        Ok(())
    }
}

impl<const LIMBS: usize> UpperHex for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in bytes.as_ref() {
            write!(f, "{:X}", b)?;
        }
        Ok(())
    }
}

impl<const LIMBS: usize> Eq for Bn<LIMBS> where Uint<LIMBS>: Encoding {}

impl<const LIMBS: usize> PartialEq for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn eq(&self, other: &Self) -> bool {
        self.sign == other.sign && self.value == other.value
    }
}

impl<const LIMBS: usize> PartialOrd for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const LIMBS: usize> Ord for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn cmp(&self, other: &Self) -> Ordering {
        let scmp = self.sign.cmp(&other.sign);
        if scmp != Ordering::Equal {
            return scmp;
        }

        match self.sign {
            Sign::None => Ordering::Equal,
            Sign::Plus => self.value.cmp(&other.value),
            Sign::Minus => other.value.cmp(&self.value),
        }
    }
}

impl<const LIMBS: usize> Hash for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sign.hash(state);
        self.value.hash(state);
    }
}

macro_rules! from_uint_impl {
    ($($type:tt),+$(,)*) => {
        $(
            impl<const LIMBS: usize> From<$type> for Bn<LIMBS>
                where Uint<LIMBS>: Encoding
            {
                fn from(value: $type) -> Self {
                    Self {
                        sign: if value != 0 { Sign::Plus } else { Sign::None },
                        value: Uint::<LIMBS>::from(value)
                    }
                }
            }
        )+
    };
}

macro_rules! from_sint_impl {
    ($($stype:tt => $utype:tt),+$(,)*) => {
        $(
            impl<const LIMBS: usize> From<$stype> for Bn<LIMBS>
                where Uint<LIMBS>: Encoding
            {
                fn from(value: $stype) -> Self {
                    let (sign, value) = match 0.cmp(&value) {
                            Ordering::Greater => (Sign::Minus, (-value) as $utype),
                            Ordering::Equal => (Sign::None, 0 as $utype),
                            Ordering::Less => (Sign::Plus, value as $utype),
                    };
                    Self {
                        sign,
                        value: Uint::<LIMBS>::from(value)
                    }
                }
            }
        )+
    };
}

macro_rules! ops_impl {
    (@ref $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:tt, $opr_assign:tt, $($rhs:ty),+) => {$(
        impl<'a, const LIMBS: usize> $ops<$rhs> for &'a Bn<LIMBS>
            where Uint<LIMBS>: Encoding
        {
            type Output = Bn<LIMBS>;

            fn $func(self, rhs: $rhs) -> Self::Output {
                self $opr Bn::<LIMBS>::from(rhs)
            }
        }

        impl<const LIMBS: usize> $ops<$rhs> for Bn<LIMBS>
            where Uint<LIMBS>: Encoding
        {
            type Output = Self;

            fn $func(self, rhs: $rhs) -> Self::Output {
                self $opr Self::from(rhs)
            }
        }

        impl<const LIMBS: usize> $ops_assign<$rhs> for Bn<LIMBS>
            where Uint<LIMBS>: Encoding,
        {
            fn $func_assign(&mut self, rhs: $rhs) {
                *self = &*self $opr &Self::from(rhs);
            }
        }
    )*};
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:tt, $opr_assign:tt) => {
        ops_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, $opr_assign, u8, u16, u32, u64, usize);
        ops_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, $opr_assign, i8, i16, i32, i64, isize);
    };
}

impl<const LIMBS: usize> From<usize> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: usize) -> Self {
        Self {
            sign: if value == 0 { Sign::None } else { Sign::Plus },
            value: Uint::<LIMBS>::from(value as u64),
        }
    }
}

#[cfg(target_pointer_width = "64")]
from_uint_impl!(u128);
from_uint_impl!(u64, u32, u16, u8);
#[cfg(target_pointer_width = "64")]
from_sint_impl!(i128 => u128);
from_sint_impl!(isize => u64, i64 => u64, i32 => u32, i16 => u16, i8 => u8);

impl<const LIMBS: usize> Neg for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            sign: -self.sign,
            value: self.value,
        }
    }
}

impl<const LIMBS: usize> Neg for &Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn neg(self) -> Self::Output {
        Bn {
            sign: -self.sign,
            value: self.value,
        }
    }
}

impl<'a, 'b, const LIMBS: usize> Add<&'a Bn<LIMBS>> for &'b Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn add(self, rhs: &'a Bn<LIMBS>) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => self.clone(),
            (Sign::None, _) => rhs.clone(),
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

impl<const LIMBS: usize> Add<Bn<LIMBS>> for &Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn add(self, rhs: Bn<LIMBS>) -> Self::Output {
        self + &rhs
    }
}

impl<const LIMBS: usize> Add<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn add(self, rhs: &Bn<LIMBS>) -> Self::Output {
        &self + rhs
    }
}

impl<const LIMBS: usize> Add for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl<const LIMBS: usize> AddAssign for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn add_assign(&mut self, rhs: Self) {
        let n = mem::replace(self, Bn::<LIMBS>::zero());
        *self = n + rhs;
    }
}

impl<const LIMBS: usize> AddAssign<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn add_assign(&mut self, rhs: &Bn<LIMBS>) {
        let n = mem::replace(self, Bn::<LIMBS>::zero());
        *self = n + rhs;
    }
}

impl<'a, 'b, const LIMBS: usize> Sub<&'a Bn<LIMBS>> for &'b Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn sub(self, rhs: &'a Bn<LIMBS>) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => self.clone(),
            (Sign::None, _) => rhs.clone(),
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

impl<const LIMBS: usize> Sub<Bn<LIMBS>> for &Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn sub(self, rhs: Bn<LIMBS>) -> Self::Output {
        self - &rhs
    }
}

impl<const LIMBS: usize> Sub<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn sub(self, rhs: &Bn<LIMBS>) -> Self::Output {
        &self - rhs
    }
}

impl<const LIMBS: usize> Sub for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl<const LIMBS: usize> SubAssign for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sub_assign(&mut self, rhs: Self) {
        let n = mem::replace(self, Bn::<LIMBS>::zero());
        *self = n - rhs;
    }
}

impl<const LIMBS: usize> SubAssign<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sub_assign(&mut self, rhs: &Bn<LIMBS>) {
        let n = mem::replace(self, Bn::<LIMBS>::zero());
        *self = n - rhs;
    }
}

impl<'a, 'b, const LIMBS: usize> Mul<&'a Bn<LIMBS>> for &'b Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn mul(self, rhs: &'a Bn<LIMBS>) -> Self::Output {
        Bn {
            sign: self.sign * rhs.sign,
            value: self.value.checked_mul(&rhs.value).expect("overflow"),
        }
    }
}

impl<const LIMBS: usize> Mul<Bn<LIMBS>> for &Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn mul(self, rhs: Bn<LIMBS>) -> Self::Output {
        self * &rhs
    }
}

impl<const LIMBS: usize> Mul<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: &Bn<LIMBS>) -> Self::Output {
        &self * rhs
    }
}

impl<const LIMBS: usize> Mul for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl<const LIMBS: usize> MulAssign<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_assign(&mut self, rhs: &Bn<LIMBS>) {
        self.value = self.value.saturating_mul(&rhs.value);
        if rhs.is_zero() || self.value.is_zero().into() {
            self.sign = Sign::None;
        } else {
            self.sign = self.sign * rhs.sign;
        }
    }
}

impl<const LIMBS: usize> MulAssign for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl<'a, 'b, const LIMBS: usize> Div<&'a Bn<LIMBS>> for &'b Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn div(self, rhs: &'a Bn<LIMBS>) -> Self::Output {
        let (q, _) = self.div_rem(rhs);
        q
    }
}

impl<const LIMBS: usize> Div<Bn<LIMBS>> for &Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn div(self, rhs: Bn<LIMBS>) -> Self::Output {
        self / &rhs
    }
}

impl<const LIMBS: usize> Div<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn div(self, rhs: &Bn<LIMBS>) -> Self::Output {
        &self / rhs
    }
}

impl<const LIMBS: usize> Div for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        &self / &rhs
    }
}

impl<const LIMBS: usize> DivAssign<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn div_assign(&mut self, rhs: &Bn<LIMBS>) {
        *self = &*self / rhs;
    }
}

impl<const LIMBS: usize> DivAssign for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn div_assign(&mut self, rhs: Self) {
        *self = &*self / rhs;
    }
}

impl<'a, 'b, const LIMBS: usize> Rem<&'a Bn<LIMBS>> for &'b Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn rem(self, rhs: &'a Bn<LIMBS>) -> Self::Output {
        let (_, r) = self.div_rem(rhs);
        r
    }
}

impl<const LIMBS: usize> Rem<Bn<LIMBS>> for &Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Bn<LIMBS>;

    fn rem(self, rhs: Bn<LIMBS>) -> Self::Output {
        self % &rhs
    }
}

impl<const LIMBS: usize> Rem<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn rem(self, rhs: &Bn<LIMBS>) -> Self::Output {
        &self % rhs
    }
}

impl<const LIMBS: usize> Rem for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        &self % &rhs
    }
}

impl<const LIMBS: usize> RemAssign<&Bn<LIMBS>> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn rem_assign(&mut self, rhs: &Bn<LIMBS>) {
        *self = &*self % rhs;
    }
}

impl<const LIMBS: usize> RemAssign for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn rem_assign(&mut self, rhs: Self) {
        *self = &*self % &rhs;
    }
}

macro_rules! shift_impl {
(@ref $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:expr, $($rhs:ty),+) => {$(
    impl<'a, const LIMBS: usize> $ops<$rhs> for &'a Bn<LIMBS>
        where Uint<LIMBS>: Encoding
    {
        type Output = Bn<LIMBS>;

        fn $func(self, rhs: $rhs) -> Self::Output {
            $opr(&self, rhs)
        }
    }

    impl<const LIMBS: usize> $ops<$rhs> for Bn<LIMBS>
        where Uint<LIMBS>: Encoding
    {
        type Output = Self;

        fn $func(self, rhs: $rhs) -> Self::Output {
            $opr(&self, rhs)
        }
    }

    impl<const LIMBS: usize> $ops_assign<$rhs> for Bn<LIMBS>
        where Uint<LIMBS>: Encoding
    {
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
ops_impl!(Add, add, AddAssign, add_assign, +, +=);
ops_impl!(Sub, sub, SubAssign, sub_assign, -, -=);
ops_impl!(Mul, mul, MulAssign, mul_assign, *, *=);
ops_impl!(Div, div, DivAssign, div_assign, /, /=);
ops_impl!(Rem, rem, RemAssign, rem_assign, %, %=);

fn inner_shl<T: PrimInt, const LIMBS: usize>(lhs: &Bn<LIMBS>, rhs: T) -> Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
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
fn shr_round_down<T: PrimInt, const LIMBS: usize>(n: &Bn<LIMBS>, shift: T) -> bool
where
    Uint<LIMBS>: Encoding,
{
    if n.sign.is_negative() {
        let zeros = n.value.trailing_zeros();
        shift > T::zero() && shift.to_usize().map(|shift| zeros < shift).unwrap_or(true)
    } else {
        false
    }
}

fn inner_shr<T: PrimInt, const LIMBS: usize>(lhs: &Bn<LIMBS>, rhs: T) -> Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    let round_down = shr_round_down(lhs, rhs);
    let value = lhs.value >> rhs.to_usize().unwrap();
    let value = if round_down {
        value.saturating_add(&Uint::<LIMBS>::ONE)
    } else {
        value
    };
    Bn {
        sign: lhs.sign,
        value,
    }
}

impl<const LIMBS: usize> ConstantTimeEq for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.sign.ct_eq(&other.sign) & self.value.ct_eq(&other.value)
    }
}

impl<const LIMBS: usize> Serialize for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        if s.is_human_readable() {
            alloc::format!("{}{}", self.sign, hex::encode(bytes)).serialize(s)
        } else {
            (self.sign, bytes).serialize(s)
        }
    }
}

impl<'de, const LIMBS: usize> Deserialize<'de> for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let s = alloc::string::String::deserialize(d)?;
            if let Some(stripped) = s.strip_prefix('-') {
                let zero_padding = "0".repeat(Uint::<LIMBS>::BYTES * 2 - (s.len() - 1));
                let value =
                    Uint::<LIMBS>::from_be_hex(&alloc::format!("{}{}", zero_padding, stripped));
                Ok(Self {
                    sign: Sign::Minus,
                    value,
                })
            } else {
                let zero_padding = if s.len() < Uint::<LIMBS>::BYTES * 2 {
                    "0".repeat(Uint::<LIMBS>::BYTES * 2 - s.len())
                } else {
                    alloc::string::String::new()
                };
                let value =
                    Uint::<LIMBS>::from_be_hex(&alloc::format!("{}{}", zero_padding, &s[..]));
                if value.is_zero().into() {
                    Ok(Self::zero())
                } else {
                    Ok(Self {
                        sign: Sign::Plus,
                        value,
                    })
                }
            }
        } else {
            let (sign, value): (Sign, alloc::vec::Vec<u8>) = Deserialize::deserialize(d)?;
            let mut bn = Self::from_slice(value);
            bn.sign = sign;
            Ok(bn)
        }
    }
}

impl<const LIMBS: usize> Zeroize for Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn zeroize(&mut self) {
        self.sign = Sign::None;
        self.value.zeroize();
    }
}

impl<const LIMBS: usize> Bn<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        assert_ne!(n.value.is_zero().unwrap_u8(), 1u8);
        let params = runtime_mod::DynResidueParams::new(&n.value);
        let mm = match exponent.sign {
            Sign::None => return Self::one(),
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
                Sign::None
            } else {
                sign
            },
            value,
        }
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => {
                let mut bn = Self {
                    sign: self.sign,
                    value: self.value.add_mod(&Uint::<LIMBS>::ZERO, &n.value),
                };
                if bn.sign.is_negative() {
                    bn.value = bn.value.saturating_add(&n.value);
                    -bn
                } else {
                    bn
                }
            }
            (Sign::None, _) => {
                let mut bn = Self {
                    sign: rhs.sign,
                    value: rhs.value.add_mod(&Uint::<LIMBS>::ZERO, &n.value),
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
            Sign::None
        } else {
            self.sign * rhs.sign
        };

        match sign {
            Sign::None => Self::zero(),
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
        let (i, exists) = if n.value.is_odd().into() {
            self.value.inv_odd_mod(&n.value)
        } else {
            self.value.inv_mod(&n.value)
        };
        if exists.into() {
            Some(Self {
                sign: self.sign,
                value: i,
            })
        } else {
            None
        }
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.sign.is_zero() || self.value.is_zero().into()
    }

    /// self == 1
    pub fn is_one(&self) -> bool {
        self.sign.is_positive() && self.value.ct_eq(&Uint::<LIMBS>::ONE).into()
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
            value: Uint::<LIMBS>::random_mod(rng, &NonZero::new(n.value).expect("divisor is zero")),
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
        if b.len() <= Uint::<LIMBS>::BYTES {
            let mut tmp = alloc::vec![0u8; Uint::<LIMBS>::BYTES];
            tmp[Uint::<LIMBS>::BYTES - b.len()..].copy_from_slice(b);
            Self {
                sign: Sign::Plus,
                value: Uint::<LIMBS>::from_be_slice(&tmp),
            }
        } else {
            panic!("bytes are not the expected size");
        }
    }

    /// Convert this big number to a big-endian byte sequence, the sign is not included
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let a = Uint::<LIMBS>::BITS;
        let b = self.value.leading_zeros();
        let remainder = (a - b + 7) / 8;
        let mut output = alloc::vec::Vec::with_capacity(remainder);
        let bytes = self.value.to_be_bytes();
        output.extend_from_slice(&bytes.as_ref()[Uint::<LIMBS>::BYTES - remainder..]);
        output
    }

    /// Convert this big number to a big-endian byte sequence and store it in `buffer`.
    /// The sign is not included
    pub fn copy_bytes_into_buffer(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self.value.to_be_bytes().as_ref())
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    #[allow(clippy::many_single_char_names)]
    pub fn extended_gcd(&self, other: &Self) -> GcdResult<LIMBS> {
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
            value: Uint::<LIMBS>::ONE,
        }
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (d, r) = self
            .value
            .div_rem(&NonZero::new(other.value).expect("divisor is zero"));
        let rem_sign = if r.is_zero().into() {
            Sign::None
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
        let bn1 = DefaultBn::from_slice(v1.as_slice());
        let bn2 = DefaultBn::from_slice(v2.as_slice());
        let bn3 = DefaultBn::from_slice(v3.as_slice());
        let bn4 = DefaultBn::from_slice(v4.as_slice());
        let bn5 = DefaultBn::from_slice(v5.as_slice());
        assert_eq!(&bn1 + &bn2, bn3);
        assert_eq!(&bn1 - &bn2, bn4);
        assert_eq!(&bn2 - &bn1, -bn4);
        assert_eq!(&bn1 * &bn2, bn5);
        assert_eq!(&bn1 * -&bn2, -bn5.clone());
        assert_eq!(&-bn1 * -&bn2, bn5);
    }

    #[test]
    fn primes() {
        let p1 = DefaultBn::prime_from_rng(256, &mut rand_core::OsRng);
        assert!(p1.is_prime());
    }

    #[test]
    fn bytes() {
        let p1 = DefaultBn::prime_from_rng(256, &mut rand_core::OsRng);
        let bytes = p1.to_bytes();
        assert_eq!(bytes.len(), 32);
        let p2 = DefaultBn::from_slice(&bytes);
        assert_eq!(p1, p2);
    }
}
