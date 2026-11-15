//! Flight data as plain points, and the local flat frame the scorer works in.
//!
//! The input is deliberately a plain type: whatever a caller reads flight positions from, it hands over [`FlightPoint`]s,
//! so no data source's format reaches this crate.

use crate::physics::Track;

/// One position report of one aircraft.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FlightPoint {
    /// Seconds on the same clock as the recording's start (Unix time, for example).
    pub time_s: f64,
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// Geometric altitude in metres (above the same datum as the ground altitude given to the search).
    pub alt_m: f64,
    /// Ground speed in m/s, if known (NaN if not).
    pub speed_mps: f64,
    /// Track over the ground in degrees clockwise from true north, if known (NaN if not).
    pub heading_deg: f64,
}

/// One aircraft's reports, in any order.
#[derive(Clone, Debug, Default)]
pub struct Flight {
    pub id: String,
    pub points: Vec<FlightPoint>,
}

/// Mean Earth radius (m), as the reference uses.
pub const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// A local east/north/up frame around a point: equirectangular, good to a few metres over the ten-kilometre boxes
/// searched here.
#[derive(Clone, Copy, Debug)]
pub struct LocalFrame {
    pub lat0: f64,
    pub lon0: f64,
    pub alt0: f64,
}

impl LocalFrame {
    pub fn new(lat0: f64, lon0: f64, alt0: f64) -> LocalFrame {
        LocalFrame { lat0, lon0, alt0 }
    }

    pub fn to_enu(&self, lat: f64, lon: f64, alt: f64) -> [f64; 3] {
        let x = (lon - self.lon0).to_radians() * EARTH_RADIUS_M * self.lat0.to_radians().cos();
        let y = (lat - self.lat0).to_radians() * EARTH_RADIUS_M;
        [x, y, alt - self.alt0]
    }

    /// (lat, lon) of a local point.
    pub fn to_latlon(&self, x: f64, y: f64) -> (f64, f64) {
        let lat = self.lat0 + (y / EARTH_RADIUS_M).to_degrees();
        let lon = self.lon0 + (x / (EARTH_RADIUS_M * self.lat0.to_radians().cos())).to_degrees();
        (lat, lon)
    }
}

/// A flight as a dense, smooth track in `frame`: every `out_dt` seconds, each coordinate a local quadratic fit over the
/// reports within about `smoothing_s` (Gaussian weights). Speed and heading, where given, enter the fit as velocity
/// observations. Differentiating raw, noisy one-second positions would turn metres of noise into tens of m/s of false
/// radial velocity and wreck the modelled Doppler curve; this is the attacker-side cleanup the reference does with a
/// smoothing spline. Returns `None` with fewer than four reports.
pub fn track_from_flight(flight: &Flight, frame: &LocalFrame, out_dt: f64, smoothing_s: f64) -> Option<Track> {
    let mut pts: Vec<FlightPoint> = flight.points.iter().copied().filter(|p| p.time_s.is_finite()).collect();
    pts.sort_by(|a, b| a.time_s.total_cmp(&b.time_s));
    pts.dedup_by(|a, b| a.time_s == b.time_s);
    if pts.len() < 4 {
        return None;
    }
    let enu: Vec<[f64; 3]> = pts.iter().map(|p| frame.to_enu(p.lat_deg, p.lon_deg, p.alt_m)).collect();
    let vel: Vec<Option<[f64; 2]>> = pts
        .iter()
        .map(|p| {
            (p.speed_mps.is_finite() && p.heading_deg.is_finite()).then(|| {
                let h = p.heading_deg.to_radians();
                [p.speed_mps * h.sin(), p.speed_mps * h.cos()]
            })
        })
        .collect();
    let (t0, t1) = (pts[0].time_s, pts[pts.len() - 1].time_s);
    let sigma = (smoothing_s / 2.0).max(0.5);
    let n = ((t1 - t0) / out_dt).floor() as usize + 1;
    let mut t = Vec::with_capacity(n);
    let mut pos = Vec::with_capacity(n);
    let mut lo = 0;
    for i in 0..n {
        let tc = t0 + i as f64 * out_dt;
        while lo < pts.len() && pts[lo].time_s < tc - 3.0 * sigma {
            lo += 1;
        }
        let mut p = [0.0; 3];
        for (c, pc) in p.iter_mut().enumerate() {
            // weighted least squares for a + b u + c u^2, u = t - tc
            let mut m = [[0.0f64; 3]; 3];
            let mut rhs = [0.0f64; 3];
            for j in lo..pts.len() {
                let u = pts[j].time_s - tc;
                if u > 3.0 * sigma {
                    break;
                }
                let w = (-0.5 * (u / sigma).powi(2)).exp();
                let phi = [1.0, u, u * u];
                for a in 0..3 {
                    rhs[a] += w * phi[a] * enu[j][c];
                    for b in 0..3 {
                        m[a][b] += w * phi[a] * phi[b];
                    }
                }
                if c < 2 {
                    if let Some(v) = vel[j] {
                        // velocity b + 2 c u, weighted as a position report a second away would be
                        let dphi = [0.0, 1.0, 2.0 * u];
                        for a in 0..3 {
                            rhs[a] += w * dphi[a] * v[c];
                            for b in 0..3 {
                                m[a][b] += w * dphi[a] * dphi[b];
                            }
                        }
                    }
                }
            }
            *pc = solve3(m, rhs).map_or(f64::NAN, |s| s[0]);
        }
        if p.iter().all(|v| v.is_finite()) {
            t.push(tc);
            pos.push(p);
        }
    }
    (t.len() >= 4).then_some(Track { t, pos })
}

fn solve3(mut m: [[f64; 3]; 3], mut b: [f64; 3]) -> Option<[f64; 3]> {
    for i in 0..3 {
        let piv = (i..3).max_by(|&a, &c| m[a][i].abs().total_cmp(&m[c][i].abs()))?;
        if m[piv][i].abs() < 1e-12 {
            return None;
        }
        m.swap(i, piv);
        b.swap(i, piv);
        for r in i + 1..3 {
            let f = m[r][i] / m[i][i];
            for c in i..3 {
                m[r][c] -= f * m[i][c];
            }
            b[r] -= f * b[i];
        }
    }
    let mut x = [0.0; 3];
    for i in (0..3).rev() {
        x[i] = (b[i] - (i + 1..3).map(|c| m[i][c] * x[c]).sum::<f64>()) / m[i][i];
    }
    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips() {
        let f = LocalFrame::new(41.9, -87.7, 0.0);
        let p = f.to_enu(41.91, -87.69, 100.0);
        let (lat, lon) = f.to_latlon(p[0], p[1]);
        assert!((lat - 41.91).abs() < 1e-9 && (lon + 87.69).abs() < 1e-9);
        assert!((p[1] - 1112.0).abs() < 2.0);
    }

    #[test]
    fn noisy_reports_come_back_close_to_the_path() {
        let truth = Track::synthetic(1000.0, 200.0, (-6000.0, 300.0), 800.0, 70.0, 0.0, 0.0, 0.0, 0.0);
        let frame = LocalFrame::new(41.9, -87.7, 0.0);
        let mut rng = heimdall_scrub::rng::Rng::seeded(0);
        let mut flight = Flight { id: "a1".into(), points: Vec::new() };
        let mut tt = 1003.0;
        while tt < 1197.0 {
            let p = truth.resample(&[tt]).pos[0];
            let (lat, lon) = frame.to_latlon(p[0] + 5.0 * rng.normal() as f64, p[1] + 5.0 * rng.normal() as f64);
            // heading: maths angle 0 (east) is 90 degrees clockwise from north
            flight.points.push(FlightPoint { time_s: tt, lat_deg: lat, lon_deg: lon, alt_m: p[2], speed_mps: 70.0, heading_deg: 90.0 });
            tt += 1.0;
        }
        let got = track_from_flight(&flight, &frame, 0.25, 8.0).unwrap();
        let inner: Vec<f64> = got.t.iter().copied().filter(|&t| t > 1020.0 && t < 1180.0).collect();
        let a = got.resample(&inner);
        let b = truth.resample(&inner);
        let err = a.pos.iter().zip(&b.pos).map(|(p, q)| ((p[0] - q[0]).powi(2) + (p[1] - q[1]).powi(2)).sqrt()).fold(0.0, f64::max);
        assert!(err < 15.0, "{err}");
    }
}
