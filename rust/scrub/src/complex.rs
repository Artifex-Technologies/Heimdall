//! A complex number of two f32s: just what the FFT and the spectral work need.

use std::ops::{Add, Mul, Sub};

/// A complex sample or STFT bin.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct C32 {
    pub re: f32,
    pub im: f32,
}

impl C32 {
    pub const ZERO: C32 = C32 { re: 0.0, im: 0.0 };

    pub const fn new(re: f32, im: f32) -> C32 {
        C32 { re, im }
    }

    /// |z|^2, the bin's power.
    pub fn norm_sqr(self) -> f32 {
        self.re * self.re + self.im * self.im
    }

    pub fn abs(self) -> f32 {
        self.norm_sqr().sqrt()
    }

    pub fn conj(self) -> C32 {
        C32 { re: self.re, im: -self.im }
    }

    pub fn scale(self, k: f32) -> C32 {
        C32 { re: self.re * k, im: self.im * k }
    }
}

impl Add for C32 {
    type Output = C32;
    fn add(self, o: C32) -> C32 {
        C32 { re: self.re + o.re, im: self.im + o.im }
    }
}

impl Sub for C32 {
    type Output = C32;
    fn sub(self, o: C32) -> C32 {
        C32 { re: self.re - o.re, im: self.im - o.im }
    }
}

impl Mul for C32 {
    type Output = C32;
    fn mul(self, o: C32) -> C32 {
        C32 { re: self.re * o.re - self.im * o.im, im: self.re * o.im + self.im * o.re }
    }
}
