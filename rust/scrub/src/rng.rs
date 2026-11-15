//! Random numbers for the replacement noise: xoshiro256++ with Gaussian draws.
//!
//! The noise does not need to be secret: it fills bins whose original content is thrown away, so knowing it would not give
//! the original back. It is seeded from the operating system anyway (through std's randomly keyed hasher, no file or
//! syscall of our own), unless a test asks for a fixed seed.

use std::hash::{BuildHasher, Hasher};

/// xoshiro256++ (Blackman and Vigna), with a spare Gaussian kept from each Box-Muller pair.
pub struct Rng {
    s: [u64; 4],
    spare: Option<f32>,
}

fn splitmix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl Rng {
    /// A fixed seed, for tests and for `--seed`.
    pub fn seeded(seed: u64) -> Rng {
        let mut x = seed;
        Rng { s: [splitmix(&mut x), splitmix(&mut x), splitmix(&mut x), splitmix(&mut x)], spare: None }
    }

    /// A seed from the operating system's randomness (std keys every `RandomState` from it).
    pub fn from_os() -> Rng {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(0x6865_696d_6461_6c6c);
        let a = h.finish();
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(a);
        Rng::seeded(a ^ h.finish().rotate_left(17))
    }

    /// `Some(seed)` = fixed, `None` = from the operating system.
    pub fn new(seed: Option<u64>) -> Rng {
        seed.map(Rng::seeded).unwrap_or_else(Rng::from_os)
    }

    pub fn next_u64(&mut self) -> u64 {
        let s = &mut self.s;
        let r = s[0].wrapping_add(s[3]).rotate_left(23).wrapping_add(s[0]);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        r
    }

    /// Uniform in (0, 1], never 0 (so its logarithm is finite).
    pub fn uniform(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64 + 1.0) * (1.0 / (1u64 << 53) as f64)
    }

    /// A standard normal draw.
    pub fn normal(&mut self) -> f32 {
        if let Some(v) = self.spare.take() {
            return v;
        }
        let r = (-2.0 * self.uniform().ln()).sqrt();
        let a = 2.0 * std::f64::consts::PI * self.uniform();
        self.spare = Some((r * a.sin()) as f32);
        (r * a.cos()) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_draws_have_unit_variance() {
        let mut r = Rng::seeded(1);
        let n = 200_000;
        let (mut s, mut s2) = (0.0f64, 0.0f64);
        for _ in 0..n {
            let v = r.normal() as f64;
            s += v;
            s2 += v * v;
        }
        let mean = s / n as f64;
        assert!(mean.abs() < 0.01);
        assert!((s2 / n as f64 - 1.0).abs() < 0.02);
    }

    #[test]
    fn os_seeds_differ() {
        assert_ne!(Rng::from_os().next_u64(), Rng::from_os().next_u64());
    }
}
