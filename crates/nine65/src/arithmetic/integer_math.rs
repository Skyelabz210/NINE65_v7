//! Integer Math Utilities — Float-Free Helpers
//!
//! Shared utility functions for the float purge. All computations are
//! exact integer or fixed-point — zero floating point anywhere.

/// Integer log2: floor(log2(x)). Returns 0 for x=0.
#[inline]
pub fn integer_log2(x: u64) -> u32 {
    if x == 0 {
        0
    } else {
        63 - x.leading_zeros()
    }
}

/// Integer log2 for u128: floor(log2(x)). Returns 0 for x=0.
#[inline]
pub fn integer_log2_u128(x: u128) -> u32 {
    if x == 0 {
        0
    } else {
        127 - x.leading_zeros()
    }
}

/// Integer square root (floor). Babylonian method, exact.
pub fn integer_sqrt(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    // Start from a good initial estimate using bit length
    let shift = (63 - n.leading_zeros()) / 2;
    let mut x = 1u64 << (shift + 1);
    loop {
        let y = (x + n / x) / 2;
        if y >= x {
            break;
        }
        x = y;
    }
    x
}

/// Format millibits as "X.YYY" string (e.g., 31500 -> "31.500")
pub fn format_millibits(mb: u64) -> String {
    format!("{}.{:03}", mb / 1000, mb % 1000)
}

/// Format ops count with suffix: 1_234_567_890 -> "1G"
/// Uses integer-only arithmetic.
pub fn format_ops(ops: u128) -> String {
    if ops >= 1_000_000_000 {
        format!("{}G", ops / 1_000_000_000)
    } else if ops >= 1_000_000 {
        format!("{}M", ops / 1_000_000)
    } else {
        format!("{}", ops)
    }
}

/// Format large integer as "~2^N" (bit-length notation)
pub fn format_as_bits(val: u128) -> String {
    if val == 0 {
        "0".into()
    } else {
        format!("~2^{}", integer_log2_u128(val))
    }
}

/// Precomputed cos/sin table for golden-angle basin placement.
/// 256 entries, Q15 fixed-point (multiply, then >> 15).
/// Entry i = (cos(i * 2π/256) * 32768, sin(i * 2π/256) * 32768)
pub const COS_SIN_TABLE: [(i32, i32); 256] = [
    (32768, 0),
    (32758, 804),
    (32729, 1608),
    (32679, 2411),
    (32610, 3212),
    (32522, 4011),
    (32413, 4808),
    (32286, 5602),
    (32138, 6393),
    (31972, 7180),
    (31786, 7962),
    (31581, 8740),
    (31357, 9512),
    (31114, 10279),
    (30853, 11039),
    (30572, 11793),
    (30274, 12540),
    (29957, 13279),
    (29622, 14010),
    (29269, 14733),
    (28899, 15447),
    (28511, 16151),
    (28106, 16846),
    (27684, 17531),
    (27246, 18205),
    (26791, 18868),
    (26320, 19520),
    (25833, 20160),
    (25330, 20788),
    (24812, 21403),
    (24279, 22006),
    (23732, 22595),
    (23170, 23170),
    (22595, 23732),
    (22006, 24279),
    (21403, 24812),
    (20788, 25330),
    (20160, 25833),
    (19520, 26320),
    (18868, 26791),
    (18205, 27246),
    (17531, 27684),
    (16846, 28106),
    (16151, 28511),
    (15447, 28899),
    (14733, 29269),
    (14010, 29622),
    (13279, 29957),
    (12540, 30274),
    (11793, 30572),
    (11039, 30853),
    (10279, 31114),
    (9512, 31357),
    (8740, 31581),
    (7962, 31786),
    (7180, 31972),
    (6393, 32138),
    (5602, 32286),
    (4808, 32413),
    (4011, 32522),
    (3212, 32610),
    (2411, 32679),
    (1608, 32729),
    (804, 32758),
    (0, 32768),
    (-804, 32758),
    (-1608, 32729),
    (-2411, 32679),
    (-3212, 32610),
    (-4011, 32522),
    (-4808, 32413),
    (-5602, 32286),
    (-6393, 32138),
    (-7180, 31972),
    (-7962, 31786),
    (-8740, 31581),
    (-9512, 31357),
    (-10279, 31114),
    (-11039, 30853),
    (-11793, 30572),
    (-12540, 30274),
    (-13279, 29957),
    (-14010, 29622),
    (-14733, 29269),
    (-15447, 28899),
    (-16151, 28511),
    (-16846, 28106),
    (-17531, 27684),
    (-18205, 27246),
    (-18868, 26791),
    (-19520, 26320),
    (-20160, 25833),
    (-20788, 25330),
    (-21403, 24812),
    (-22006, 24279),
    (-22595, 23732),
    (-23170, 23170),
    (-23732, 22595),
    (-24279, 22006),
    (-24812, 21403),
    (-25330, 20788),
    (-25833, 20160),
    (-26320, 19520),
    (-26791, 18868),
    (-27246, 18205),
    (-27684, 17531),
    (-28106, 16846),
    (-28511, 16151),
    (-28899, 15447),
    (-29269, 14733),
    (-29622, 14010),
    (-29957, 13279),
    (-30274, 12540),
    (-30572, 11793),
    (-30853, 11039),
    (-31114, 10279),
    (-31357, 9512),
    (-31581, 8740),
    (-31786, 7962),
    (-31972, 7180),
    (-32138, 6393),
    (-32286, 5602),
    (-32413, 4808),
    (-32522, 4011),
    (-32610, 3212),
    (-32679, 2411),
    (-32729, 1608),
    (-32758, 804),
    (-32768, 0),
    (-32758, -804),
    (-32729, -1608),
    (-32679, -2411),
    (-32610, -3212),
    (-32522, -4011),
    (-32413, -4808),
    (-32286, -5602),
    (-32138, -6393),
    (-31972, -7180),
    (-31786, -7962),
    (-31581, -8740),
    (-31357, -9512),
    (-31114, -10279),
    (-30853, -11039),
    (-30572, -11793),
    (-30274, -12540),
    (-29957, -13279),
    (-29622, -14010),
    (-29269, -14733),
    (-28899, -15447),
    (-28511, -16151),
    (-28106, -16846),
    (-27684, -17531),
    (-27246, -18205),
    (-26791, -18868),
    (-26320, -19520),
    (-25833, -20160),
    (-25330, -20788),
    (-24812, -21403),
    (-24279, -22006),
    (-23732, -22595),
    (-23170, -23170),
    (-22595, -23732),
    (-22006, -24279),
    (-21403, -24812),
    (-20788, -25330),
    (-20160, -25833),
    (-19520, -26320),
    (-18868, -26791),
    (-18205, -27246),
    (-17531, -27684),
    (-16846, -28106),
    (-16151, -28511),
    (-15447, -28899),
    (-14733, -29269),
    (-14010, -29622),
    (-13279, -29957),
    (-12540, -30274),
    (-11793, -30572),
    (-11039, -30853),
    (-10279, -31114),
    (-9512, -31357),
    (-8740, -31581),
    (-7962, -31786),
    (-7180, -31972),
    (-6393, -32138),
    (-5602, -32286),
    (-4808, -32413),
    (-4011, -32522),
    (-3212, -32610),
    (-2411, -32679),
    (-1608, -32729),
    (-804, -32758),
    (0, -32768),
    (804, -32758),
    (1608, -32729),
    (2411, -32679),
    (3212, -32610),
    (4011, -32522),
    (4808, -32413),
    (5602, -32286),
    (6393, -32138),
    (7180, -31972),
    (7962, -31786),
    (8740, -31581),
    (9512, -31357),
    (10279, -31114),
    (11039, -30853),
    (11793, -30572),
    (12540, -30274),
    (13279, -29957),
    (14010, -29622),
    (14733, -29269),
    (15447, -28899),
    (16151, -28511),
    (16846, -28106),
    (17531, -27684),
    (18205, -27246),
    (18868, -26791),
    (19520, -26320),
    (20160, -25833),
    (20788, -25330),
    (21403, -24812),
    (22006, -24279),
    (22595, -23732),
    (23170, -23170),
    (23732, -22595),
    (24279, -22006),
    (24812, -21403),
    (25330, -20788),
    (25833, -20160),
    (26320, -19520),
    (26791, -18868),
    (27246, -18205),
    (27684, -17531),
    (28106, -16846),
    (28511, -16151),
    (28899, -15447),
    (29269, -14733),
    (29622, -14010),
    (29957, -13279),
    (30274, -12540),
    (30572, -11793),
    (30853, -11039),
    (31114, -10279),
    (31357, -9512),
    (31581, -8740),
    (31786, -7962),
    (31972, -7180),
    (32138, -6393),
    (32286, -5602),
    (32413, -4808),
    (32522, -4011),
    (32610, -3212),
    (32679, -2411),
    (32729, -1608),
    (32758, -804),
];

/// Golden angle in Q30 fixed-point: 2.399963229... * 2^30
pub const GOLDEN_ANGLE_Q30: u64 = 2_576_980_378;

/// Look up cos/sin for angle index using fixed-point table.
/// Returns (cos_q15, sin_q15) — multiply by value and >> 15 to get result.
#[inline]
pub fn fixed_cos_sin(angle_index: u64) -> (i32, i32) {
    let idx = (angle_index % 256) as usize;
    COS_SIN_TABLE[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_log2() {
        assert_eq!(integer_log2(0), 0);
        assert_eq!(integer_log2(1), 0);
        assert_eq!(integer_log2(2), 1);
        assert_eq!(integer_log2(3), 1);
        assert_eq!(integer_log2(4), 2);
        assert_eq!(integer_log2(7), 2);
        assert_eq!(integer_log2(8), 3);
        assert_eq!(integer_log2(255), 7);
        assert_eq!(integer_log2(256), 8);
        assert_eq!(integer_log2(1023), 9);
        assert_eq!(integer_log2(1024), 10);
        assert_eq!(integer_log2(u64::MAX), 63);
    }

    #[test]
    fn test_integer_log2_u128() {
        assert_eq!(integer_log2_u128(0), 0);
        assert_eq!(integer_log2_u128(1), 0);
        assert_eq!(integer_log2_u128(1 << 64), 64);
        assert_eq!(integer_log2_u128(u128::MAX), 127);
    }

    #[test]
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(16), 4);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(99), 9); // floor
        assert_eq!(integer_sqrt(101), 10); // floor
        assert_eq!(integer_sqrt(10000), 100);
        assert_eq!(integer_sqrt(u64::MAX), 4294967295); // floor(sqrt(2^64-1))
    }

    #[test]
    fn test_integer_sqrt_correctness() {
        // Verify s^2 <= n < (s+1)^2 for various values
        for n in [2u64, 3, 5, 7, 10, 15, 17, 50, 99, 1000, 9999, 65535] {
            let s = integer_sqrt(n);
            assert!(
                s * s <= n,
                "sqrt({}) = {} but {}^2 = {} > {}",
                n,
                s,
                s,
                s * s,
                n
            );
            assert!(
                (s + 1) * (s + 1) > n,
                "sqrt({}) = {} but {}^2 = {} <= {}",
                n,
                s,
                s + 1,
                (s + 1) * (s + 1),
                n
            );
        }
    }

    #[test]
    fn test_format_millibits() {
        assert_eq!(format_millibits(0), "0.000");
        assert_eq!(format_millibits(1000), "1.000");
        assert_eq!(format_millibits(31500), "31.500");
        assert_eq!(format_millibits(500), "0.500");
        assert_eq!(format_millibits(1), "0.001");
        assert_eq!(format_millibits(999), "0.999");
        assert_eq!(format_millibits(128000), "128.000");
    }

    #[test]
    fn test_format_ops() {
        assert_eq!(format_ops(0), "0");
        assert_eq!(format_ops(999), "999");
        assert_eq!(format_ops(1_000_000), "1M");
        assert_eq!(format_ops(5_500_000), "5M");
        assert_eq!(format_ops(1_000_000_000), "1G");
        assert_eq!(format_ops(42_000_000_000), "42G");
    }

    #[test]
    fn test_format_as_bits() {
        assert_eq!(format_as_bits(0), "0");
        assert_eq!(format_as_bits(1), "~2^0");
        assert_eq!(format_as_bits(256), "~2^8");
        assert_eq!(format_as_bits(1024), "~2^10");
    }

    #[test]
    fn test_cos_sin_table_properties() {
        // cos(0) = 32768, sin(0) = 0
        assert_eq!(COS_SIN_TABLE[0], (32768, 0));
        // cos(64) = cos(pi/2) = 0, sin(64) = sin(pi/2) = 32768
        assert_eq!(COS_SIN_TABLE[64], (0, 32768));
        // cos(128) = cos(pi) = -32768, sin(128) = sin(pi) = 0
        assert_eq!(COS_SIN_TABLE[128], (-32768, 0));
        // cos(192) = cos(3pi/2) = 0, sin(192) = sin(3pi/2) = -32768
        assert_eq!(COS_SIN_TABLE[192], (0, -32768));
    }

    #[test]
    fn test_cos_sin_table_unit_circle() {
        // Verify cos^2 + sin^2 ≈ 32768^2 for all entries (within Q15 rounding)
        // Max error from rounding: each term off by ±0.5, so squared sum off by ~2*32768
        for (i, &(c, s)) in COS_SIN_TABLE.iter().enumerate() {
            let mag_sq = (c as i64) * (c as i64) + (s as i64) * (s as i64);
            let expected = 32768i64 * 32768;
            let error = (mag_sq - expected).unsigned_abs();
            assert!(
                error < 65536,
                "Entry {} magnitude error {} too large",
                i,
                error
            );
        }
    }

    #[test]
    fn test_fixed_cos_sin() {
        assert_eq!(fixed_cos_sin(0), (32768, 0));
        assert_eq!(fixed_cos_sin(64), (0, 32768));
        // Wraps around
        assert_eq!(fixed_cos_sin(256), (32768, 0));
        assert_eq!(fixed_cos_sin(320), (0, 32768));
    }

    #[test]
    fn test_golden_angle_q30() {
        // 2.399963229... * 2^30 ≈ 2_576_980_378
        // Verify it's in the right ballpark
        assert!(
            (2_500_000_000..2_700_000_000).contains(&GOLDEN_ANGLE_Q30),
            "GOLDEN_ANGLE_Q30 out of expected range"
        );
    }
}
