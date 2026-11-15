//! The few image operations the whole-file scrub needs (scipy.ndimage's median, uniform, maximum, closing, dilation and
//! labelling), on spectrograms stored frame by frame: `a[t * nb + k]` is bin `k` of frame `t`. Edges repeat the nearest
//! value ("nearest" mode), as the reference does.

/// A spectrogram-shaped grid of `nt` frames by `nb` bins.
#[derive(Clone, Copy)]
pub struct Shape {
    pub nt: usize,
    pub nb: usize,
}

/// Median over `size` (odd) neighbouring bins of every frame.
pub fn median_freq(a: &[f32], s: Shape, size: usize, out: &mut [f32]) {
    let h = size / 2;
    let mut win = vec![0.0f32; size];
    for t in 0..s.nt {
        let row = &a[t * s.nb..(t + 1) * s.nb];
        for k in 0..s.nb {
            for (j, w) in win.iter_mut().enumerate() {
                let kk = (k + j).saturating_sub(h).min(s.nb - 1);
                *w = row[kk];
            }
            let (_, m, _) = win.select_nth_unstable_by(h, |x, y| x.total_cmp(y));
            out[t * s.nb + k] = *m;
        }
    }
}

/// Mean over `size` (odd) neighbouring frames of every bin.
pub fn uniform_time(a: &[f32], s: Shape, size: usize, out: &mut [f32]) {
    let h = (size / 2) as isize;
    let nt = s.nt as isize;
    for k in 0..s.nb {
        let at = |t: isize| a[(t.clamp(0, nt - 1) as usize) * s.nb + k] as f64;
        let mut sum: f64 = (-h..=h).map(at).sum();
        for t in 0..nt {
            out[t as usize * s.nb + k] = (sum / size as f64) as f32;
            sum += at(t + h + 1) - at(t - h);
        }
    }
}

/// Mean over `size` (odd) neighbouring bins of every frame.
pub fn uniform_freq(a: &[f32], s: Shape, size: usize, out: &mut [f32]) {
    let h = (size / 2) as isize;
    let nb = s.nb as isize;
    for t in 0..s.nt {
        let row = &a[t * s.nb..(t + 1) * s.nb];
        let at = |k: isize| row[k.clamp(0, nb - 1) as usize] as f64;
        let mut sum: f64 = (-h..=h).map(at).sum();
        for k in 0..nb {
            out[t * s.nb + k as usize] = (sum / size as f64) as f32;
            sum += at(k + h + 1) - at(k - h);
        }
    }
}

/// Mean of a 1-D array over `size` (odd) neighbours.
pub fn uniform_1d(a: &[f64], size: usize) -> Vec<f64> {
    let h = (size / 2) as isize;
    let n = a.len() as isize;
    let at = |i: isize| a[i.clamp(0, n - 1) as usize];
    (0..n).map(|i| (-h..=h).map(|j| at(i + j)).sum::<f64>() / size as f64).collect()
}

/// Closing along time with a structuring element `width` frames long (odd): fills gaps shorter than it.
pub fn close_time(m: &[bool], s: Shape, width: usize) -> Vec<bool> {
    let h = (width / 2) as isize;
    let nt = s.nt as isize;
    let get = |m: &[bool], t: isize, k: usize| t >= 0 && t < nt && m[t as usize * s.nb + k];
    let mut dil = vec![false; m.len()];
    for t in 0..nt {
        for k in 0..s.nb {
            dil[t as usize * s.nb + k] = (-h..=h).any(|d| get(m, t + d, k));
        }
    }
    // scipy's binary_closing pads with zeros, so the erosion treats outside as unset
    let mut out = vec![false; m.len()];
    for t in 0..nt {
        for k in 0..s.nb {
            out[t as usize * s.nb + k] = (-h..=h).all(|d| get(&dil, t + d, k));
        }
    }
    out
}

/// Dilation by a box of +-`fh` bins and +-`th` frames.
pub fn dilate(m: &[bool], s: Shape, fh: usize, th: usize) -> Vec<bool> {
    // separable: along frequency first, then along time
    let mut a = vec![false; m.len()];
    for t in 0..s.nt {
        let row = &m[t * s.nb..(t + 1) * s.nb];
        let mut last: Option<usize> = None;
        // distance to the nearest set bin on either side, in two passes
        let mut near = vec![usize::MAX; s.nb];
        for k in 0..s.nb {
            if row[k] {
                last = Some(k);
            }
            if let Some(l) = last {
                near[k] = k - l;
            }
        }
        last = None;
        for k in (0..s.nb).rev() {
            if row[k] {
                last = Some(k);
            }
            if let Some(l) = last {
                near[k] = near[k].min(l - k);
            }
        }
        for k in 0..s.nb {
            a[t * s.nb + k] = near[k] <= fh;
        }
    }
    let mut out = vec![false; m.len()];
    for t in 0..s.nt {
        let lo = t.saturating_sub(th);
        let hi = (t + th).min(s.nt - 1);
        for k in 0..s.nb {
            out[t * s.nb + k] = (lo..=hi).any(|u| a[u * s.nb + k]);
        }
    }
    out
}

/// Bounding box of one labelled component.
#[derive(Clone, Copy, Debug)]
pub struct Bbox {
    pub t0: usize,
    pub t1: usize,
    pub k0: usize,
    pub k1: usize,
}

/// Connected components of `m`, where pixels within +-`kh` bins and +-`th` frames are neighbours. Returns the label of
/// every pixel (0 = unset, components from 1) and each component's bounding box.
pub fn label(m: &[bool], s: Shape, kh: usize, th: usize) -> (Vec<u32>, Vec<Bbox>) {
    let mut lab = vec![0u32; m.len()];
    let mut boxes = Vec::new();
    let mut stack = Vec::new();
    for start in 0..m.len() {
        if !m[start] || lab[start] != 0 {
            continue;
        }
        let id = boxes.len() as u32 + 1;
        let (t, k) = (start / s.nb, start % s.nb);
        let mut b = Bbox { t0: t, t1: t, k0: k, k1: k };
        lab[start] = id;
        stack.push(start);
        while let Some(p) = stack.pop() {
            let (t, k) = (p / s.nb, p % s.nb);
            b.t0 = b.t0.min(t);
            b.t1 = b.t1.max(t);
            b.k0 = b.k0.min(k);
            b.k1 = b.k1.max(k);
            for u in t.saturating_sub(th)..=(t + th).min(s.nt - 1) {
                for j in k.saturating_sub(kh)..=(k + kh).min(s.nb - 1) {
                    let q = u * s.nb + j;
                    if m[q] && lab[q] == 0 {
                        lab[q] = id;
                        stack.push(q);
                    }
                }
            }
        }
        boxes.push(b);
    }
    (lab, boxes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_and_uniform_use_nearest_edges() {
        let s = Shape { nt: 1, nb: 5 };
        let a = [5.0, 1.0, 3.0, 2.0, 4.0];
        let mut out = [0.0; 5];
        median_freq(&a, s, 3, &mut out);
        assert_eq!(out, [5.0, 3.0, 2.0, 3.0, 4.0]);
        let s = Shape { nt: 3, nb: 1 };
        let mut out = [0.0; 3];
        uniform_time(&[0.0, 3.0, 6.0], s, 3, &mut out);
        assert_eq!(out, [1.0, 3.0, 5.0]);
    }

    #[test]
    fn closing_fills_one_frame_gaps_and_labels_join_neighbours() {
        let s = Shape { nt: 5, nb: 3 };
        let mut m = vec![false; 15];
        for t in [0, 1, 3, 4] {
            m[t * 3 + 1] = true;
        }
        let c = close_time(&m, s, 3);
        assert!(c[2 * 3 + 1]);
        let (lab, boxes) = label(&m, s, 0, 1);
        assert_eq!(boxes.len(), 2);
        assert_eq!(lab[1], 1);
        let c: Vec<bool> = c.iter().zip(&m).map(|(a, b)| *a || *b).collect();
        let (_, boxes) = label(&c, s, 0, 1);
        assert_eq!(boxes.len(), 1);
        assert_eq!((boxes[0].t0, boxes[0].t1), (0, 4));
    }

    #[test]
    fn dilation_is_a_box() {
        let s = Shape { nt: 3, nb: 7 };
        let mut m = vec![false; 21];
        m[7 + 3] = true;
        let d = dilate(&m, s, 2, 1);
        assert_eq!(d.iter().filter(|&&x| x).count(), 15);
    }
}
