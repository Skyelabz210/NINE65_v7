//! Checked fixed-width arithmetic for public modulus and capacity certificates.
//!
//! All values use sixteen little-endian 64-bit limbs. Operations reject
//! overflow, underflow, and zero divisors instead of wrapping. The add,
//! subtract, multiply, divide-by-word, and comparison loops have fixed public
//! bounds. This is not a constant-time security claim.

use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U1024 {
    /// Least-significant limb first.
    pub limbs: [u64; 16],
}

impl U1024 {
    pub const ZERO: Self = Self { limbs: [0; 16] };
    pub const ONE: Self = Self::from_u64(1);
    pub const MAX: Self = Self {
        limbs: [u64::MAX; 16],
    };

    pub const fn from_limbs(limbs: [u64; 16]) -> Self {
        Self { limbs }
    }

    pub const fn from_u64(value: u64) -> Self {
        let mut limbs = [0; 16];
        limbs[0] = value;
        Self { limbs }
    }

    pub const fn from_u128(value: u128) -> Self {
        let mut limbs = [0; 16];
        limbs[0] = value as u64;
        limbs[1] = (value >> 64) as u64;
        Self { limbs }
    }

    pub fn bit_length(self) -> u32 {
        let mut bits = 0;
        for (i, limb) in self.limbs.iter().enumerate() {
            if *limb != 0 {
                bits = 64 * i as u32 + (64 - limb.leading_zeros());
            }
        }
        bits
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut limbs = [0; 16];
        let mut carry = false;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let (sum, first) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            *limb = sum;
            carry = first | second;
        }
        (!carry).then_some(Self { limbs })
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        let mut limbs = [0; 16];
        let mut borrow = false;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let (difference, first) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            *limb = difference;
            borrow = first | second;
        }
        (!borrow).then_some(Self { limbs })
    }

    pub fn checked_mul_u64(self, other: u64) -> Option<Self> {
        let mut limbs = [0; 16];
        let mut carry = 0u128;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let product = self.limbs[i] as u128 * other as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        (carry == 0).then_some(Self { limbs })
    }

    pub fn checked_mul_u128(self, other: u128) -> Option<Self> {
        let factors = [other as u64, (other >> 64) as u64];
        let mut wide = [0u64; 18];
        for (i, factor) in factors.iter().enumerate() {
            let mut carry = 0u128;
            for (j, limb) in self.limbs.iter().enumerate() {
                // The maximum is (2^64-1)^2 + 2*(2^64-1) = 2^128-1.
                let product = *factor as u128 * *limb as u128 + wide[i + j] as u128 + carry;
                wide[i + j] = product as u64;
                carry = product >> 64;
            }
            wide[i + 16] = carry as u64;
        }
        let mut limbs = [0; 16];
        limbs.copy_from_slice(&wide[..16]);
        ((wide[16] | wide[17]) == 0).then_some(Self { limbs })
    }

    pub fn checked_mul(self, other: Self) -> Option<Self> {
        let mut wide = [0u64; 32];
        for (i, left) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, right) in other.limbs.iter().enumerate() {
                let product = *left as u128 * *right as u128 + wide[i + j] as u128 + carry;
                wide[i + j] = product as u64;
                carry = product >> 64;
            }
            // Earlier rows reach at most i+15, so this slot is still zero.
            wide[i + 16] = carry as u64;
        }
        let overflow = wide[16..].iter().fold(0, |bits, limb| bits | limb);
        let mut limbs = [0; 16];
        limbs.copy_from_slice(&wide[..16]);
        (overflow == 0).then_some(Self { limbs })
    }

    /// Empty products equal one. The iteration count depends on the public
    /// factor-list length, including when an intermediate product overflows.
    pub fn checked_product_u64s(factors: &[u64]) -> Option<Self> {
        // A zero factor makes the exact full product zero even if a prefix
        // exceeds the accumulator. Handle it independently of prefix capacity.
        let has_zero = factors
            .iter()
            .fold(false, |zero, factor| zero | (*factor == 0));
        let mut product = Self::ONE;
        let mut overflow = false;
        for factor in factors {
            match product.checked_mul_u64(*factor) {
                Some(value) => product = value,
                None => {
                    overflow = true;
                    product = Self::ZERO;
                }
            }
        }
        if has_zero {
            Some(Self::ZERO)
        } else {
            (!overflow).then_some(product)
        }
    }

    pub fn div_mod_u64(self, divisor: u64) -> Option<(Self, u64)> {
        if divisor == 0 {
            return None;
        }
        let mut quotient = [0; 16];
        let mut remainder = 0u128;
        for i in (0..16).rev() {
            let numerator = (remainder << 64) | self.limbs[i] as u128;
            quotient[i] = (numerator / divisor as u128) as u64;
            remainder = numerator % divisor as u128;
        }
        Some((Self { limbs: quotient }, remainder as u64))
    }

    pub fn mod_u64(self, divisor: u64) -> Option<u64> {
        self.div_mod_u64(divisor).map(|(_, remainder)| remainder)
    }

    pub fn shr1(self) -> Self {
        self.shift_right(1)
    }

    /// Logical right shift; shifting by 1024 or more produces zero.
    pub fn shift_right(self, shift: u32) -> Self {
        if shift >= 1024 {
            return Self::ZERO;
        }
        let words = shift as usize / 64;
        let bits = shift % 64;
        let mut limbs = [0; 16];
        for (i, limb) in limbs.iter_mut().enumerate() {
            if i + words < 16 {
                *limb = self.limbs[i + words] >> bits;
                if bits != 0 && i + words + 1 < 16 {
                    *limb |= self.limbs[i + words + 1] << (64 - bits);
                }
            }
        }
        Self { limbs }
    }
}

impl Ord for U1024 {
    fn cmp(&self, other: &Self) -> Ordering {
        let (mut less, mut greater) = (false, false);
        for i in (0..16).rev() {
            let undecided = !(less | greater);
            less |= undecided & (self.limbs[i] < other.limbs[i]);
            greater |= undecided & (self.limbs[i] > other.limbs[i]);
        }
        if less {
            Ordering::Less
        } else if greater {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

impl PartialOrd for U1024 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl core::ops::Shr<u32> for U1024 {
    type Output = Self;

    fn shr(self, shift: u32) -> Self::Output {
        U1024::shift_right(self, shift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(value: &str) -> U1024 {
        assert!(value.len() <= 256);
        let mut limbs = [0; 16];
        for (i, chunk) in value.as_bytes().rchunks(16).enumerate() {
            limbs[i] = u64::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        U1024::from_limbs(limbs)
    }

    fn optional_hex(value: &str) -> Option<U1024> {
        (value != "overflow").then(|| from_hex(value))
    }

    #[test]
    fn checked_boundaries_refuse_overflow_underflow_and_zero_divisors() {
        assert_eq!(U1024::from_u128(u128::MAX).limbs[..2], [u64::MAX; 2]);
        assert_eq!(U1024::MAX.bit_length(), 1024);
        assert_eq!(U1024::ZERO.bit_length(), 0);
        assert_eq!(U1024::MAX.checked_add(U1024::ONE), None);
        assert_eq!(U1024::ZERO.checked_sub(U1024::ONE), None);
        assert_eq!(U1024::MAX.checked_mul_u64(2), None);
        assert_eq!(U1024::MAX.checked_mul_u128(2), None);
        assert_eq!(U1024::MAX.checked_mul_u128(0), Some(U1024::ZERO));
        assert_eq!(U1024::MAX.checked_mul(U1024::from_u64(2)), None);
        assert_eq!(U1024::MAX.checked_mul(U1024::ZERO), Some(U1024::ZERO));
        assert_eq!(U1024::MAX.checked_mul(U1024::ONE), Some(U1024::MAX));
        assert_eq!(U1024::MAX.div_mod_u64(0), None);
        assert_eq!(U1024::MAX.mod_u64(0), None);
        assert_eq!(U1024::checked_product_u64s(&[]), Some(U1024::ONE));
        assert_eq!(U1024::checked_product_u64s(&[u64::MAX; 17]), None);
        assert!(U1024::checked_product_u64s(&[u64::MAX; 16]).is_some());
        assert_eq!(U1024::checked_product_u64s(&[2; 1024]), None);
        let power = U1024::checked_product_u64s(&[2; 1023]).unwrap();
        assert_eq!(power.limbs[15], 1 << 63);
        assert!(power.limbs[..15].iter().all(|limb| *limb == 0));
        let mut zero_product = vec![u64::MAX; 17];
        zero_product.push(0);
        assert_eq!(
            U1024::checked_product_u64s(&zero_product),
            Some(U1024::ZERO)
        );
    }

    #[test]
    fn shifts_and_order_cross_every_limb_boundary() {
        for bit in 0..1024 {
            let mut limbs = [0; 16];
            limbs[bit / 64] = 1 << (bit % 64);
            let value = U1024::from_limbs(limbs);
            assert_eq!(value.bit_length(), bit as u32 + 1);
            assert_eq!(value.shift_right(bit as u32), U1024::ONE);
            assert_eq!(value.shift_right(bit as u32 + 1), U1024::ZERO);
            let below = value.checked_sub(U1024::ONE).unwrap();
            assert!(below < value);
            assert!(value > below);
            assert_eq!(value.cmp(&value), Ordering::Equal);
            assert_eq!(below.checked_add(U1024::ONE), Some(value));
        }
        assert_eq!(U1024::MAX.shift_right(1024), U1024::ZERO);
        assert_eq!(U1024::MAX.shift_right(u32::MAX), U1024::ZERO);
        assert_eq!(U1024::MAX.shr1().limbs[15], u64::MAX >> 1);
    }

    #[test]
    fn agrees_with_existing_u512_when_all_results_fit() {
        use crate::arithmetic::rns::U512;

        let widen = |value: U512| {
            let mut limbs = [0; 16];
            for (i, word) in [value.d0, value.d1, value.d2, value.d3].iter().enumerate() {
                limbs[2 * i] = *word as u64;
                limbs[2 * i + 1] = (*word >> 64) as u64;
            }
            U1024::from_limbs(limbs)
        };
        for index in 0..64u128 {
            let value = U512 {
                d0: u128::MAX - index,
                d1: 0x1234_5678_9abc_def0_ffff_0000_1111_2222 ^ index,
                d2: (1 << 126) + index,
                d3: 0,
            };
            let scalar = u128::MAX - 7 * index;
            let wide = widen(value);
            assert_eq!(
                wide.checked_mul_u128(scalar),
                Some(widen(value.mul_u128(scalar)))
            );
            assert_eq!(wide.checked_add(wide), Some(widen(value.add(value))));
            for divisor in [1, 3, 65537, u64::MAX] {
                assert_eq!(
                    wide.div_mod_u64(divisor).unwrap().0,
                    widen(value.div_u64(divisor))
                );
                assert_eq!(wide.mod_u64(divisor), Some(value.mod_u64(divisor)));
            }
        }
    }

    // BEGIN PYTHON INTEGER ORACLE
    // Generated by scripts/generate_wide_arithmetic_vectors.py; seed 0x1024.
    #[test]
    fn python_integer_vectors_cover_full_width_arithmetic() {
        type Vector = (
            &'static str,
            &'static str,
            [&'static str; 5],
            u64,
            &'static str,
            u64,
        );
        let vectors: &[Vector] = &[
            // Operand widths: 0, 0.
            (
                "0",
                "0",
                [
                    "0",
                    "0",
                    "0",
                    "0",
                    "0",
                ],
                1,
                "0",
                0,
            ),
            // Operand widths: 0, 1024.
            (
                "0",
                "ee4d387bc709691b54b3d68b33a89266de6d5db9580a7c5da62191b0155ed1e979a07a8715049764cd1742b03b25ac2d8b8d72a5ad0bbdba6b22be6c30043adc30d9f3cbcf10a5735f66c5f352de65a423ca10ee7eee1b56ed7887fe0fc7aa10f864fd881c07a2e3229d89758eac30e1fa11655c356fdfd587ef2dd44d3a4334",
                [
                    "ee4d387bc709691b54b3d68b33a89266de6d5db9580a7c5da62191b0155ed1e979a07a8715049764cd1742b03b25ac2d8b8d72a5ad0bbdba6b22be6c30043adc30d9f3cbcf10a5735f66c5f352de65a423ca10ee7eee1b56ed7887fe0fc7aa10f864fd881c07a2e3229d89758eac30e1fa11655c356fdfd587ef2dd44d3a4334",
                    "overflow",
                    "0",
                    "0",
                    "0",
                ],
                2,
                "0",
                0,
            ),
            // Operand widths: 1, 1024.
            (
                "1",
                "e74ac21aba5d962ec256001059f25d2bb0b883c56f2bfda551ccf952b5a313f68a9004ae6471cee2f4b850fb1f7269eec9d78d996efe1e8d989f4e11c53725de0afa0c680cd3b16a7996e15fe76b858fac8614bfe904cb28dfd48cefeb1a37260ab0513ec475823393985cc0e4944daf89691a2b10e13c89b8c6982a6a381183",
                [
                    "e74ac21aba5d962ec256001059f25d2bb0b883c56f2bfda551ccf952b5a313f68a9004ae6471cee2f4b850fb1f7269eec9d78d996efe1e8d989f4e11c53725de0afa0c680cd3b16a7996e15fe76b858fac8614bfe904cb28dfd48cefeb1a37260ab0513ec475823393985cc0e4944daf89691a2b10e13c89b8c6982a6a381184",
                    "overflow",
                    "e74ac21aba5d962ec256001059f25d2bb0b883c56f2bfda551ccf952b5a313f68a9004ae6471cee2f4b850fb1f7269eec9d78d996efe1e8d989f4e11c53725de0afa0c680cd3b16a7996e15fe76b858fac8614bfe904cb28dfd48cefeb1a37260ab0513ec475823393985cc0e4944daf89691a2b10e13c89b8c6982a6a381183",
                    "b8c6982a6a381183",
                    "89691a2b10e13c89b8c6982a6a381183",
                ],
                3,
                "0",
                1,
            ),
            // Operand widths: 63, 65.
            (
                "7f9de3149cb792a1",
                "103c5206d022ff22e",
                [
                    "1836303819ee784cf",
                    "overflow",
                    "817f0167ad1db8776e6d0d3fdf278aee",
                    "1e11e53106625d66e6d0d3fdf278aee",
                    "817f0167ad1db8776e6d0d3fdf278aee",
                ],
                17,
                "781c210457435cd",
                4,
            ),
            // Operand widths: 64, 64.
            (
                "a91e4c88687bc588",
                "a718ceb0204b849c",
                [
                    "150371b3888c74a24",
                    "2057dd8483040ec",
                    "6e63274ee4b2985dd1be4b735c1e7ee0",
                    "6e63274ee4b2985dd1be4b735c1e7ee0",
                    "6e63274ee4b2985dd1be4b735c1e7ee0",
                ],
                4294967297,
                "a91e4c87",
                3210574081,
            ),
            // Operand widths: 65, 127.
            (
                "105478a6a4be282ce",
                "4c325773fe6e612bff4056f489e331fe",
                [
                    "4c325773fe6e612d0487e15ed5c5b4cc",
                    "overflow",
                    "4dc49e524a2501dcb96291c444b46cdcdead102fe0713664",
                    "10483ed8219946642dead102fe0713664",
                    "4dc49e524a2501dcb96291c444b46cdcdead102fe0713664",
                ],
                9223372036854775807,
                "2",
                380424882680398544,
            ),
            // Operand widths: 127, 128.
            (
                "7fcf98824a9b3536eef3528be85166c0",
                "9fc3f02e171f29bf2e730a12e268f38f",
                [
                    "11f9388b061ba5ef61d665c9ecaba5a4f",
                    "overflow",
                    "4fc3c2c3b967fd50700391ec2ef0b1d3e6e80c24b3d76b6aa930e0f34800a540",
                    "1730bcb07586e1ee832024f6a467022aa930e0f34800a540",
                    "4fc3c2c3b967fd50700391ec2ef0b1d3e6e80c24b3d76b6aa930e0f34800a540",
                ],
                18446744073709551615,
                "7fcf98824a9b3537",
                7981199935870376951,
            ),
            // Operand widths: 128, 128.
            (
                "d71cc046a37f33b87ecae8b860d6059b",
                "d1b6db3aa10c26c9cd15cce1d80afb03",
                [
                    "1a8d39b81448b5a824be0b59a38e1009e",
                    "565e50c02730ceeb1b51bd688cb0a98",
                    "b0381fa13a065e648752cd3a03e19e64f621afbfbbfbdbb954bf4f6cfa0f09d1",
                    "ac54577d05bf0a7fde3f96ef30d8730654bf4f6cfa0f09d1",
                    "b0381fa13a065e648752cd3a03e19e64f621afbfbbfbdbb954bf4f6cfa0f09d1",
                ],
                1,
                "d71cc046a37f33b87ecae8b860d6059b",
                0,
            ),
            // Operand widths: 129, 129.
            (
                "1834e6efc6fe03d5d1b4e3a841ed774d0",
                "17ab315c8743f518df085c28184c6c77c",
                [
                    "2fe0184c4e41f8eeb0bd3fd05a39e3c4c",
                    "89b5933fba0ebcf2ac878029a10ad54",
                    "23cf0c0ad0bf414c570aa389351966e46ae19b8686e8b53f5ec9f7ba8050a44c0",
                    "16be3e611b58ac0b50caa256d46ba2d65ec9f7ba8050a44c0",
                    "b9a251b09c13d768555bfe0f32bef976ae19b8686e8b53f5ec9f7ba8050a44c0",
                ],
                2,
                "c1a7377e37f01eae8da71d420f6bba68",
                0,
            ),
            // Operand widths: 255, 256.
            (
                "4b0767447cb45ed013e3f666a31138bb096c55210092b7ca1ecd35c0fa8ed596",
                "c90d9563187a2feb0b782ce18ff11697830d787809922ad2f8e8bededcb36e73",
                [
                    "11414fca7952e8ebb1f5c234833024f528c79cd990a24e29d17b5f49fd7424409",
                    "overflow",
                    "3aeccb3d5e8840ec469104c17bba72f17b4697fc6a24e8f4057971399b0ac283b822d55a83720554ba54c42f3fa98ebdcd2c1d7a3ce6656c9adc8eda2dd26662",
                    "48f362b0be9f148c75608971cde620c32cda1bcdbf9482076b7602c92f2494609adc8eda2dd26662",
                    "2668bc86f0f93da3a525700e3c850ea0690e495cbbfd03c0317a4f3752d8af43cd2c1d7a3ce6656c9adc8eda2dd26662",
                ],
                3,
                "190277c17ee6ca455bf6a7778bb0683e587971b5aadb9298b4ef11eafe2f9c87",
                1,
            ),
            // Operand widths: 256, 256.
            (
                "8e816dd93e561bea38f021c5096a77aa047653fff54f66126aedf72c5fed91d7",
                "b0e28aae2ce493ea379f6f7a62dd4c84b98e55a0e5067e8900867a94b5307653",
                [
                    "13f63f8876b3aafd4708f913f6c47c42ebe04a9a0da55e49b6b7471c1151e082a",
                    "overflow",
                    "627716fb0ed17cf655099f001ca22b2332ea762bfa1cc82309a34fac53dbe89884bef5e21a2b59fb6bcd5a672612cefabbb885a4e766016b169d528ef68f62b5",
                    "4adbfbf5c0272cbe16e249c503d2369b985a25b6209c32cbb41b47e571235c169d528ef68f62b5",
                    "674ac3d77667fc252ba163cf5063342fed109efcbdf66d89c6b43fa9f3acc81ebbb885a4e766016b169d528ef68f62b5",
                ],
                17,
                "861f76721c8d477308698931eabe8ebe22513ffff5f060115594ac65ffeea76",
                1,
            ),
            // Operand widths: 511, 512.
            (
                "56fb75eb4c4a21d59775e2e6497e927b0e93ee5bc614bdcebad1568b3b1c5b28be8e7aa51d3fe0c64d1fcf38a2f0023f26730c728d167fac77801ac2c7a33ee8",
                "84f784a341327718a5a1fdcd9548d217596d9e839308af679cc51032406942ba6dede6b1e978f491362024e833ded05904f6c3545a67b4e636e34f10cc8471f2",
                [
                    "dbf2fa8e8d7c98ee3d17e0b3dec7649268018cdf591d6d36579666bd7b859de32c7c615706b8d557833ff420d6ced2982b69cfc6e77e3492ae6369d39427b0da",
                    "overflow",
                    "2d2dc27d3a6d3ba59dd1ddce85c5303a40922c76c512f4df6d8cb538103fbbb4f715cb9a39b9fcca965fd6d29b0fb749b4ea500c73c193996676523000c4b0f491b264a0cc41ab440a42d3ccd3abd186cbfe9b25fefbd9aca7011bc6ae90cef90abbb5accfe5b967572b7deb7f977ae6ca924416671c666718c3d30d16b5df50",
                    "12a646b68054a6763a4bf0c61bee6a91373528c436566c45cecef7966592981b7336a388533bfb3a85bb252918d5aa257d6226758e717b7d2eb031cc62dec1f718c3d30d16b5df50",
                    "1afc5d93159082d8baf9ac1ffdd1484a7d3e72147aa3395e93b5e37e69cc465d768a80beed3057e931b8fc937d207a1e4d4a9b9597c4541056ba6a6af8a1c3eca924416671c666718c3d30d16b5df50",
                ],
                4294967297,
                "56fb75eaf54eabeaa22736fba7575b7f673c92dc5ed82af25bf92b98df232f8fdf6b4b153dd495b10f4b398793a4c8b792ce43bafa483bf17d37ded1",
                1248550935,
            ),
            // Operand widths: 512, 512.
            (
                "b5778a4ccfe05f862520f601e8110dec0c8986bd2dd87321298550903693a50e8b50e340239f3c3887dd662a53388469adaedea3fb7625a15b12c0b0cad93530",
                "88baa93d8071ed2dcf9e735dd11c15255593003063ef6ae458c3540fe4e08ee59d9572bced269efb1cca8feb9923d50936ed080df25047191ef3a1184b949db5",
                [
                    "13e32338a50524cb3f4bf695fb92d2311621c86ed91c7de058248a4a01b7433f428e655fd10c5db33a4a7f615ec5c5972e49be6b1edc66cba7a0661c9166dd2e5",
                    "2cbce10f4f6e7258558282a416f4f8c6b6f6868cc9e9083cd0c1fc8051b31628edbb708336789d3d6b12d63eba14af6076c1d6960925de883c1f1f987f44977b",
                    "60ebd24acd136c57eac7264086db5eed7f77eabe3ad0545d2e233360baa22efcb9e8b4525c2c828072477bfeb75fc88d8e4e170a45651c1c9b338be4f62f18375667fd32ce6acc7bbf082f2089dd639abb930863901d15c20300a95b9e21fdea7920bc3aa97de8d6ad30dc7b250ef3f931a2646347117779d171be0e70f10af0",
                    "15f0b4deae08418710703a8a0d7678b09b2709f4794fa3151eb5e2f18a6e27eb4ace8d89fa65f9af8c755cc521f078b0b94817a5d2ae9ca24e3a9f453b1af5c9d171be0e70f10af0",
                    "26ef3c8cdc1e1bc216e1f2d1ef888ada82551fb2839c134695750c03964d582fe93d403ea9f86b917069800134ecc2a806ca3777341571cb1bd3cdf1549b254931a2646347117779d171be0e70f10af0",
                ],
                9223372036854775807,
                "16aef14999fc0bf0f202015370fa399f6595337e87af81a2f05b110f163177e7b2203e8630d6d756753c29d1ac14bf3a202e2f77d79843286",
                6770520123676387254,
            ),
            // Operand widths: 513, 512.
            (
                "11f03b12b5eec5a56438353e0f64d2308418197caadb48c8af4e28e8ba7cdeb2edd7a2e300e5bf5d97949e3683073efa2bc6d9dede29b49614e8413803c252a01",
                "c73672299db1e8852906a4afe63082bb1de320bf345f679717fd7454074d36854dd9fc6216b40315e01c7b1aa9d9999d8c49785b949bed4e02babf409a16075c",
                [
                    "1e63a2354fc9e42db6c89f890dc7da5c35f64b889e213f4220ce002dfaf1b21b42b542a92250ff8ef59665e82da4d894048b71649773736af513ed2c0d63b315d",
                    "57cd3f01c13a71d11a7caf31101ca04d239e770b795524f3dce51a37a080b4a98fa031cdf7a7f2c3992d684d869a5605302425924dff5c134bc9543fa20f22a5",
                    "df58e97e63392a314c6f2e426853895bbc512ce0d83f4b4c1114a583896cd6e86645d0230e3e42eb9e78c059c476f4b4ed4966999857e2cc17c4e5aceb96b9200adf788d7b45d0dfae568325af0893cf3c0392e358d09392b34936ee8af6167a877cc5c6db1f3d120d691263ee3ebd89704022169b6e7ec3ef8e4970d7971f5c",
                    "30f667d3f1d623df1b137d8cb38feea08eb6390890f2fc1628122d0f1c1006a49fdf90accb9e2a5564fe2c81da3ddecd25b9108916586fff95b2c31dd9dc575ef8e4970d7971f5c",
                    "9d4863e1a540956db139448b0cde419c26faa2f96409211b7eaca6714ed57f05a6fe0befa6471be5e0a6b86177362c42847122eae0092fd158493577918061ec704022169b6e7ec3ef8e4970d7971f5c",
                ],
                18446744073709551615,
                "11f03b12b5eec5a576287050c55397d5fa4089cd702ee09ea98eb2b62aabbf51976655992b917eaf2efaf3cfae98bda95ac1cdae8cc2723f6",
                18059696640633884151,
            ),
            // Operand widths: 749, 274.
            (
                "1e4ec1f263ef1f4ebc6077d672bf144bf5dff8ce591443e3dec75648102f843958a4e60c04f781514609788e1ef5dbafb8a97549798877c107bb3671929f2629370a631b3f4a29515422941d909685a49d442477a45fed4985bb3b28aaa9",
                "38e8793b8130da1f98b64881636e1987cc4298bba884d33a9f1bdcabab4cd08588906",
                [
                    "1e4ec1f263ef1f4ebc6077d672bf144bf5dff8ce591443e3dec75648102f843958a4e60c04f781514609788e1ef5dbafb8a97549798877c107bb36752126b9e14a180514caaeb1678b042c9a54c0115f25915821961db8043a88438133af",
                    "1e4ec1f263ef1f4ebc6077d672bf144bf5dff8ce591443e3dec75648102f843958a4e60c04f781514609788e1ef5dbafb8a97549798877c107bb366e0417927123fcc121b3e5a13b1d40fba0cc6cf9ea14f6f0cdb2a2228ed0ee32d021a3",
                    "6bcc0270ea49bf8f70cb89e1249f564b89874a082c6a2a69b6cc592e5766873a827ef2250d5718677d3b790dfaf1f991c5fb7688a272d7c873f443e8fa5feba09807e3a3734917a20aa362989e62fd0079e6068513f5aba9e98f89fd09a90dda5d847fedb3847b170b86071b8bb134ca00252e934907f4310ad96db1186070f6",
                    "18003fa9d363f92a226d817d7e2c87d0dc2e058343a4af4b4f6d409f7f855cb97fc15c659bcefca3deb353650a2bdaf68649908085f386cb39a01268134a2d8031cc277ae5c737e4c98aa9928bd6b699ecf47eabc662dce5ebf9fec7dc6c0ad96db1186070f6",
                    "108ad8aa81365bfb86b2b9b47cb3e080dfd76450605124c3346a62300b44e6a012f31ed4d3d5e97f82363417b1d8d7f457c5264c0ff0d89c52a393db3cc5b66c7f40aff26cd2177b1364111242f3c11c0f1831e0f9d3c947d143eda87bb900252e934907f4310ad96db1186070f6",
                ],
                1,
                "1e4ec1f263ef1f4ebc6077d672bf144bf5dff8ce591443e3dec75648102f843958a4e60c04f781514609788e1ef5dbafb8a97549798877c107bb3671929f2629370a631b3f4a29515422941d909685a49d442477a45fed4985bb3b28aaa9",
                0,
            ),
            // Operand widths: 750, 273.
            (
                "306b224510971e13b9fc5c2c84970f07f744e9e7c90eba8facbe11b25fa673bd8cff563551592ec8dc0bed87323e636e93b052bdf587ffdfa509812dd213f34d3705df5e5cd76bca9f35f90a5ef755d5165efbc8518805d72ed99a332ef8",
                "14735b56b17ef727f805cb00bcbfc6b171f33d93c0a78c6f2f8d8191dda4ec565a4b8",
                [
                    "306b224510971e13b9fc5c2c84970f07f744e9e7c90eba8facbe11b25fa673bd8cff563551592ec8dc0bed87323e636e93b052bdf587ffdfa509812f1949a8b84ef551dddd341bd66b3264217e2b2f1120d7c2bb4a601ef509285f98d3b0",
                    "306b224510971e13b9fc5c2c84970f07f744e9e7c90eba8facbe11b25fa673bd8cff563551592ec8dc0bed87323e636e93b052bdf587ffdfa509812c8ade3de21f166cdedc7abbbed3398df33fc37c990be634d558afecb9548ad4cd8a40",
                    "3de301445106880e39bc4b18389396ed2338cd867fbc38df3ffa8e74376b7d3d6be7abf55d1fe900e43cc6b04953d686f0ca460d6ae0d44128f2a131935be7a6b7e87ee00db6a2eaede24b4c88e21279c4a23149d22249b6aa73369b95d6fdefc57e6fc6fe101d1f3ebb4b4601ec395d6c0627a79ea98eb417dfcc15feb8a240",
                    "4c01bc5c19a8f052d066303232998df7be76dbe49b35b0a7d0b95e9063eed7ead726762474354d59aa43bc0f0c694950c5f9300797f53af6168b8c22382bb8108b6207977c488b1c7eb17fce1503fff5547dc3f550bf028c3b5b789ad7417dfcc15feb8a240",
                    "29162b239a6f8fc7ebbfde0637761ce177be2f429d265949988d71f26cf4077132a59e38768f23cc92f4218dc60be8b5f3b55f71d2079e088fd51d9c187fbac21ef61007cbe220fd3cb2e4fe009713d3c32aa760924ef7e778e536c1d5f56c0627a79ea98eb417dfcc15feb8a240",
                ],
                2,
                "18359122884b8f09dcfe2e16424b8783fba274f3e4875d47d65f08d92fd339dec67fab1aa8ac97646e05f6c3991f31b749d8295efac3ffefd284c096e909f9a69b82efaf2e6bb5e54f9afc852f7baaea8b2f7de428c402eb976ccd19977c",
                0,
            ),
            // Operand widths: 750, 274.
            (
                "2b5cac8048f146774b69f1376f7166a109340d067d95849b0b550a0defe4f7ceed285601f129157ff17e35f7d0326137fc487f61310d403990a143f84064cbe14c26659752f9b4d1d50d83c31b43f65b5d35a540902ff675c31e4f371622",
                "33b80b827d9aa0d6aaeb0c8f8d246aec3a0d2f88aa0e960518b36a5f3e495bd255690",
                [
                    "2b5cac8048f146774b69f1376f7166a109340d067d95849b0b550a0defe4f7ceed285601f129157ff17e35f7d0326137fc487f61310d403990a143fb7be5840925d0730201aa7dcaa7543286bc16eee5fe1f05921b669c69a7b40c5c6cb2",
                    "2b5cac8048f146774b69f1376f7166a109340d067d95849b0b550a0defe4f7ceed285601f129157ff17e35f7d0326137fc487f61310d403990a143f504e413b9727c582ca448ebd902c6d4ff7a70fdd0bc4c44ef04f95081de889211bf92",
                    "8c2a2eca07c0bf48356a425e07ce3c5003bc6270d062acd9fcaecf753064af449e06ab70b9fbef9d5edda16dfafea7771743f8106b2cf2593d3abf4d1121d86e7ac5a9839afd0e6df14b525c1bc8514448c78e26456b99868f8a820b8cdef31f28f494ed9b1bac5f18ecc35ef2de551e3c363783572f2ac3dcb337c05d55df20",
                    "1c1c0ade5365257b4880ed3149407824df1c9381c45585d565e8e0e25cb9a68fd494b0da4b652529a410420cef0e5f52684d899560dc47fdd89b0cae27ac2d619f26b43d5deb5468b4bb653678d01cf899f6963bbaa0ced57c6ef7ca0997dcb337c05d55df20",
                    "2a194252b74acd4400449ecc559a7f3a753c22c271f970ec0fd4bce0ecc6257adc3f2013991ebc76679593f717a7ed74bcaaaae0b54c3f4c0d3f4a8f6370b337489bf91f20dfaddcc232da18bf4c48f37175c77a535e3e4a09b291f2ed3a3c363783572f2ac3dcb337c05d55df20",
                ],
                3,
                "e74398018506cd26e78a5bd2525cce05866af0229dc818903c70359faa1a7efa462c755fb0db1d5507f67529abb75bd54182a75bb046abddae06bfd6acc43f5c40ccc87c6533c45f1af2bebb3c1521e7467371585655227410a1a67b20b",
                1,
            ),
            // Operand widths: 750, 275.
            (
                "3c1c016a6a4788b142a21291aa2af5530468bd10c80e97109cddc15ccb66e808e86033a59897fea84c7086e8e45d9972a29a491b92c6e7bc9830ce7c584181f5ceed9dad2018c2083ccf992b4880fcceb3a043d603d864172b5d0034d80d",
                "5bbffaf9ad6ab7b34512ecbda9fb0ac8bf9c679796a535f533fe5ba32bac200bed46e",
                [
                    "3c1c016a6a4788b142a21291aa2af5530468bd10c80e97109cddc15ccb66e808e86033a59897fea84c7086e8e45d9972a29a491b92c6e7bc9830ce8214413190a59918e171478de2dc8045b7424776481df3a32943be1e49e61f00f3ac7b",
                    "3c1c016a6a4788b142a21291aa2af5530468bd10c80e97109cddc15ccb66e808e86033a59897fea84c7086e8e45d9972a29a491b92c6e7bc9830ce769c41d25af8422278cee9f62d9d1eec9f4eba8355494ce482c3f2a9e4709aff76039f",
                    "overflow",
                    "2bb842597e6dedd012bec2b811e5564b07581755549a93bcbc0fec1358258a6b416e7c973a9f3cbbefa08767afcf95507bdfc0eb28702b2dedd102133ec45cdd84ad56baa9f883aae8b2ad9a952cba53f27ac21ce985fe7ac49df52000fc9272f93433459996",
                    "1c85bedf239481894021880e9ac5a528ca7fd5794cfb37556e856fe9f463d7793211159902649d0250e9e2395f8c5879ada94b327b828a4975cd900471d37108846545b480290e0eba14c4e4f68faea93921ec01ab782822966627534ba902d78d6204c7779d9272f93433459996",
                ],
                17,
                "3892d427eb8e9ec4f36b5cc554dd2320f517488843d17f1eb1c1a6edec9d169ef8d3036eadbc3af8c069e862b8d0906be454f9835cf770b1802def8416d43e148685491b6980b69e5759f992261f0c0dd63c7c14b8533106bf6696c852d",
                16,
            ),
            // Operand widths: 960, 64.
            (
                "b3009f53ea1ea86e37213b3a7c1fa768477d5d862d3ad452208ef7cadc49fab61da56a7fec3ba7170c0d870606254833ea97febf682e314cb45de812ccacacb084efb2f2d1ab574d1d634840a1ad3c15a46238dc35ac07686c1e18ec55ed40f48dd67ab41fe72560a38201c946347102234b0ff027e8ca88",
                "a28101fe46616b8d",
                [
                    "b3009f53ea1ea86e37213b3a7c1fa768477d5d862d3ad452208ef7cadc49fab61da56a7fec3ba7170c0d870606254833ea97febf682e314cb45de812ccacacb084efb2f2d1ab574d1d634840a1ad3c15a46238dc35ac07686c1e18ec55ed40f48dd67ab41fe72560a38201c946347102c5cc11ee6e4a3615",
                    "b3009f53ea1ea86e37213b3a7c1fa768477d5d862d3ad452208ef7cadc49fab61da56a7fec3ba7170c0d870606254833ea97febf682e314cb45de812ccacacb084efb2f2d1ab574d1d634840a1ad3c15a46238dc35ac07686c1e18ec55ed40f48dd67ab41fe72560a38201c94634710180ca0df1e1875efb",
                    "71a099882fe413363240468a675761ef50019df5ff737eb2f788ad9d819c2ad67c530bf2b923a02333c474a985989c4194bca5fb5eb626b08804f1f08180f96b23e2263c451562de18f3e78c1dc8a234cba020d5a048777716bb04e554670267ddae8aaa5b822dc50f0b4982c71b9a3b44b278244e6335a22535697a356664e8",
                    "71a099882fe413363240468a675761ef50019df5ff737eb2f788ad9d819c2ad67c530bf2b923a02333c474a985989c4194bca5fb5eb626b08804f1f08180f96b23e2263c451562de18f3e78c1dc8a234cba020d5a048777716bb04e554670267ddae8aaa5b822dc50f0b4982c71b9a3b44b278244e6335a22535697a356664e8",
                    "71a099882fe413363240468a675761ef50019df5ff737eb2f788ad9d819c2ad67c530bf2b923a02333c474a985989c4194bca5fb5eb626b08804f1f08180f96b23e2263c451562de18f3e78c1dc8a234cba020d5a048777716bb04e554670267ddae8aaa5b822dc50f0b4982c71b9a3b44b278244e6335a22535697a356664e8",
                ],
                4294967297,
                "b3009f53371e091b0003321f7c1c7548cb60e83d61d9ec14beb50bb61d94ef0000107b7fec2b2b971fe25b6ee642ecc5045511fa63d91f525084c8c07c27e3f008c7cf02c8e3884a547fbff64d2d7c1f5734bcbcde774aab8da6ce40c84672b3c59008005a571d60492ae468fd098c9926418357",
                27739953,
            ),
            // Operand widths: 961, 64.
            (
                "1db20b0a68d0041acc1922e2050d3d3808ffa157b6bfd3734334313bbd4164fd90701a8a3eaf3182d2d6f886a38cc79b9e17255ba263f2bfd98078ae3cf84f2fa410d1c60c60c08b68e9a821cf94b709dce4d27b4fcaa707c28bdef16bb269237a8995c948c66949cb8e95871e6842762ec557c2106b5484c",
                "f8941c3194b5e018",
                [
                    "1db20b0a68d0041acc1922e2050d3d3808ffa157b6bfd3734334313bbd4164fd90701a8a3eaf3182d2d6f886a38cc79b9e17255ba263f2bfd98078ae3cf84f2fa410d1c60c60c08b68e9a821cf94b709dce4d27b4fcaa707c28bdef16bb269237a8995c948c66949cb8e95871e6842763e4e998529b6b2864",
                    "1db20b0a68d0041acc1922e2050d3d3808ffa157b6bfd3734334313bbd4164fd90701a8a3eaf3182d2d6f886a38cc79b9e17255ba263f2bfd98078ae3cf84f2fa410d1c60c60c08b68e9a821cf94b709dce4d27b4fcaa707c28bdef16bb269237a8995c948c66949cb8e95871e6842761f3c15fef71ff6834",
                    "overflow",
                    "overflow",
                    "overflow",
                ],
                9223372036854775807,
                "3b641614d1a008360efa71edad5a8adc2ff4268ac834bc9ee650af8d0aec4338ed81942e9336e97780b1196a6d8762263d907d8c1fd6a9cc2e21ec74b99df1f7a4657c758bfd65061a9e492eb724381fef0637540dddbe4f63242c8af3204ee5bb5b84a877cd705f0dd4345f2c6b65aa7",
                5303201951535309555,
            ),
            // Operand widths: 1000, 25.
            (
                "db97241e247bf0fac200b2067cf2330cb14d799f314ed0a0f02aa9df8951ddbc4466752b64eca3545ab71217d861c9eb483f63befa79cfec7fa6538bd74c573ae59f27927fa02b2b8c5391eaa6b0f37e9358d2d6e476455b30931282b419f33b4d7c7ad3f2683ae668f05bf58b316639ad33f32c0ede0829b06708e44e",
                "1c45d76",
                [
                    "db97241e247bf0fac200b2067cf2330cb14d799f314ed0a0f02aa9df8951ddbc4466752b64eca3545ab71217d861c9eb483f63befa79cfec7fa6538bd74c573ae59f27927fa02b2b8c5391eaa6b0f37e9358d2d6e476455b30931282b419f33b4d7c7ad3f2683ae668f05bf58b316639ad33f32c0ede0829b068cd41c4",
                    "db97241e247bf0fac200b2067cf2330cb14d799f314ed0a0f02aa9df8951ddbc4466752b64eca3545ab71217d861c9eb483f63befa79cfec7fa6538bd74c573ae59f27927fa02b2b8c5391eaa6b0f37e9358d2d6e476455b30931282b419f33b4d7c7ad3f2683ae668f05bf58b316639ad33f32c0ede0829b0654486d8",
                    "overflow",
                    "overflow",
                    "overflow",
                ],
                18446744073709551615,
                "db97241e247bf0fb9d97d624a16e24084ee54fc3d2bcf4a93f0ff9a35c0ed26583766ecec0fb75b9de2d80e6995d3fa5266ce4a593d70f91a61338316b2366cc8bb25fc3eac391f81805f1ae91748576ab5ec48575eacad1dbf1d7082a04be0d296e51dc1c6cf8f3925eadd1a79e5f2d3f92a0fdb6",
                8964229171990094340,
            ),
            // Operand widths: 1023, 2.
            (
                "5191417f367357df5c113b40b37a457e5a6428063332a64784b0c9377fcfed9ca9769976c6351001ed646d5d6e3385b0928a6bd77d56304971d00c35dd7ac11d4c24b9cf9e8a11fecc8dcb979c6985905e81ef5e6dfb86d3e0689824f120b6f0a90a7ef41806b82485ea741d1e4faf77eee847235b1725307d770eaa33094e6c",
                "2",
                [
                    "5191417f367357df5c113b40b37a457e5a6428063332a64784b0c9377fcfed9ca9769976c6351001ed646d5d6e3385b0928a6bd77d56304971d00c35dd7ac11d4c24b9cf9e8a11fecc8dcb979c6985905e81ef5e6dfb86d3e0689824f120b6f0a90a7ef41806b82485ea741d1e4faf77eee847235b1725307d770eaa33094e6e",
                    "5191417f367357df5c113b40b37a457e5a6428063332a64784b0c9377fcfed9ca9769976c6351001ed646d5d6e3385b0928a6bd77d56304971d00c35dd7ac11d4c24b9cf9e8a11fecc8dcb979c6985905e81ef5e6dfb86d3e0689824f120b6f0a90a7ef41806b82485ea741d1e4faf77eee847235b1725307d770eaa33094e6a",
                    "a32282fe6ce6afbeb822768166f48afcb4c8500c66654c8f0961926eff9fdb3952ed32ed8c6a2003dac8dabadc670b612514d7aefaac6092e3a0186bbaf5823a9849739f3d1423fd991b972f38d30b20bd03debcdbf70da7c0d13049e2416de15214fde8300d70490bd4e83a3c9f5eefddd08e46b62e4a60faee1d5466129cd8",
                    "a32282fe6ce6afbeb822768166f48afcb4c8500c66654c8f0961926eff9fdb3952ed32ed8c6a2003dac8dabadc670b612514d7aefaac6092e3a0186bbaf5823a9849739f3d1423fd991b972f38d30b20bd03debcdbf70da7c0d13049e2416de15214fde8300d70490bd4e83a3c9f5eefddd08e46b62e4a60faee1d5466129cd8",
                    "a32282fe6ce6afbeb822768166f48afcb4c8500c66654c8f0961926eff9fdb3952ed32ed8c6a2003dac8dabadc670b612514d7aefaac6092e3a0186bbaf5823a9849739f3d1423fd991b972f38d30b20bd03debcdbf70da7c0d13049e2416de15214fde8300d70490bd4e83a3c9f5eefddd08e46b62e4a60faee1d5466129cd8",
                ],
                1,
                "5191417f367357df5c113b40b37a457e5a6428063332a64784b0c9377fcfed9ca9769976c6351001ed646d5d6e3385b0928a6bd77d56304971d00c35dd7ac11d4c24b9cf9e8a11fecc8dcb979c6985905e81ef5e6dfb86d3e0689824f120b6f0a90a7ef41806b82485ea741d1e4faf77eee847235b1725307d770eaa33094e6c",
                0,
            ),
            // Operand widths: 1024, 1023.
            (
                "d880b22cedf78aafabd404c5c84caac91babf6b08f45e30094d0b5736ad623d012a756fcc536dbc98cc858247df64867a5937be967f2426852440618869c0656b9067fec778242ec40760e38a8ab99a63328e4a0fa8748f1e15e81d76c67f447c5df8534066c619ff224b3e294b1ef3d231ca588693c9cb1b6878d6807c9f709",
                "5a8a70c7d59d7198ca653678c3d60c544c3238eb4e34c3807063cb4eb955005aa6dfd448de20a0c31d872bb41ce334dad6440e35a9e9d063c12d301699b07e17d877d9642354771c91e83c38e2d2adaa4a4c0beefa0f883ffa21c0b518df0e5b994d2ad88c77223694dd39976c8709ef1d26659c96a25ab0e6dbbd5974355aa1",
                [
                    "overflow",
                    "7df64165185a1916e16ece4d04769e74cf79bdc541111f80246cea24b18123756bc782b3e7163b066f412c706113138ccf4f6db3be0872049116d601eceb883ee08ea688542dcbcfae8dd1ffc5d8ebfbe8dcd8b20077c0b1e73cc1225388e5ec2c925a5b79f53f695d477a4b282ae54e05f63febd29a4200cfabd00e93949c68",
                    "overflow",
                    "overflow",
                    "overflow",
                ],
                2,
                "6c40591676fbc557d5ea0262e42655648dd5fb5847a2f1804a685ab9b56b11e80953ab7e629b6de4c6642c123efb2433d2c9bdf4b3f921342922030c434e032b5c833ff63bc12176203b071c5455ccd3199472507d43a478f0af40ebb633fa23e2efc29a033630cff91259f14a58f79e918e52c4349e4e58db43c6b403e4fb84",
                1,
            ),
            // Operand widths: 1024, 1024.
            (
                "a9b1f768d29d5d982585be9286c3e93b747df99e67283789d3cba6b6f913bfd7c4da593dcb63848989626a1707e97d9a016e3a9c2efa4c01ec7c63f3615db043ae3d721d76faa32f94adc3e8be51e6569a0cc0844943327fa4a459a00688bce023d1f80d53d12e757f552d412c087a082658cd55aa5258dcfff502419765202f",
                "b7affd594c17a1d71fbbcee35157b201af4367e4c84e2a7f3f993485e9da4f4c6cbb7d2fb66ed3b332090e2f1fbf03748dfabf3d58b85113cb3e0d506c005377da5fc295102274819685faec226d95cabc850b01ce348c8599cd38e7fa7f6c4807ac969b2526f85d268e58e7f7d305b33f211fc3207ce0807d1da5f45ccea71e",
                [
                    "overflow",
                    "overflow",
                    "overflow",
                    "overflow",
                    "overflow",
                ],
                3,
                "3890a7cd9b89c9dd61d73f862cebf86926d4a88a2262bd2df143e23cfdb13ff296f3731499212c2dd876235d02a329de007a138964fe1955f97ecbfbcb1f3ac13a147b5f27a8e10fdc39ebf83f70a21cde04402c186bbb7fe18c1de0022d944ab69b52af1bf064d1d51c646b0ead7e02b772ef1c8e1b72f45551ab6b32770aba",
                1,
            ),
        ];
        for &(
            a,
            b,
            [sum, difference, product, product64, product128],
            divisor,
            quotient,
            remainder,
        ) in vectors
        {
            let (a, b) = (from_hex(a), from_hex(b));
            assert_eq!(a.checked_add(b), optional_hex(sum));
            assert_eq!(a.checked_sub(b), optional_hex(difference));
            assert_eq!(a.checked_mul(b), optional_hex(product));
            assert_eq!(b.checked_mul(a), optional_hex(product));
            assert_eq!(a.checked_mul_u64(b.limbs[0]), optional_hex(product64));
            let scalar = b.limbs[0] as u128 | ((b.limbs[1] as u128) << 64);
            assert_eq!(a.checked_mul_u128(scalar), optional_hex(product128));
            assert_eq!(
                a.div_mod_u64(divisor),
                Some((from_hex(quotient), remainder))
            );
            assert_eq!(a.mod_u64(divisor), Some(remainder));
        }
    }
    // END PYTHON INTEGER ORACLE
}
