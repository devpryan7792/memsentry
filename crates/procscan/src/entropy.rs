//! Shannon entropy over byte buffers.
//!
//! Entropy is used here as a *ranking* signal, not a verdict. Encrypted and
//! compressed data both approach 8.0 bits/byte, so a high reading narrows the
//! search but does not by itself establish that a region holds ciphertext.

/// Shannon entropy of `data` in bits per byte, in the range `0.0..=8.0`.
///
/// Returns `0.0` for an empty buffer, which is the limit of the formula rather
/// than a meaningful measurement.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Whether a buffer's entropy is at or above `threshold` bits per byte.
pub fn exceeds(data: &[u8], threshold: f64) -> bool {
    shannon_entropy(data) >= threshold
}

/// Entropy expressed as a fraction of the 8-bit maximum, in `0.0..=1.0`.
pub fn normalised(data: &[u8]) -> f64 {
    shannon_entropy(data) / 8.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uniform_byte_distribution_is_exactly_eight_bits() {
        // Every byte value appears the same number of times, so the
        // distribution is uniform and the entropy is exactly 8.0.
        let mut data = Vec::new();
        for _ in 0..4 {
            for byte in 0u8..=255 {
                data.push(byte);
            }
        }
        assert_eq!(shannon_entropy(&data), 8.0);
        assert!((normalised(&data) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_constant_buffer_has_zero_entropy() {
        let data = [0x41u8; 4096];
        assert_eq!(shannon_entropy(&data), 0.0);
        assert!(!exceeds(&data, 7.5));
    }

    #[test]
    fn a_two_value_buffer_has_one_bit() {
        let mut data = Vec::new();
        for _ in 0..512 {
            data.push(0x00);
            data.push(0xFF);
        }
        assert_eq!(shannon_entropy(&data), 1.0);
    }

    #[test]
    fn an_empty_buffer_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(normalised(&[]), 0.0);
    }

    #[test]
    fn a_single_byte_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[0x7F]), 0.0);
    }

    #[test]
    fn an_ascii_text_buffer_sits_well_below_the_threshold() {
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(64);
        let entropy = shannon_entropy(text.as_bytes());
        assert!(entropy < 5.0, "unexpected entropy for text: {entropy}");
        assert!(!exceeds(text.as_bytes(), 7.5));
    }

    #[test]
    fn a_pseudorandom_looking_buffer_exceeds_the_threshold() {
        // A deterministic high-entropy pattern: a counter hashed by a
        // different stride per byte, which spreads values across the range
        // without needing a random source.
        let mut data = Vec::with_capacity(8192);
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..8192 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.push((state & 0xFF) as u8);
        }
        let entropy = shannon_entropy(&data);
        assert!(entropy > 7.5, "unexpected entropy: {entropy}");
        assert!(exceeds(&data, 7.5));
    }

    #[test]
    fn exceeds_is_inclusive_at_the_threshold() {
        let mut data = Vec::new();
        for _ in 0..4 {
            for byte in 0u8..=255 {
                data.push(byte);
            }
        }
        assert!(exceeds(&data, 8.0));
        assert!(!exceeds(&data, 8.0001));
    }
}
