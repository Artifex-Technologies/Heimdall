//! The live scrub as a LADSPA plugin (label `heimdall_scrub`, mono), loaded by PipeWire's filter-chain for the private
//! microphone (packaging/pipewire/). LADSPA is a few C structs and four calls, written out here (ladspa.h, LGPL header,
//! not linked: only its layout is followed).
//!
//! It runs on PipeWire's real-time thread: `run` never allocates, takes no lock and makes no system call (everything is
//! made in `instantiate`). A panic is caught; from then on the instance outputs silence, so a fault never lets the raw
//! microphone through (security first: a call goes quiet rather than unscrubbed).
//!
//! Ports: 0 `Input` (audio in), 1 `Output` (audio out), 2 `latency` (control out, samples; filter-chain reports it as the
//! node's latency).

use std::ffi::{c_char, c_int, c_ulong, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};

use heimdall_scrub::live::Live;
use heimdall_scrub::Config;

type Handle = *mut c_void;

#[repr(C)]
pub struct PortRangeHint {
    hint: c_int,
    lower: f32,
    upper: f32,
}

#[repr(C)]
pub struct Descriptor {
    unique_id: c_ulong,
    label: *const c_char,
    properties: c_int,
    name: *const c_char,
    maker: *const c_char,
    copyright: *const c_char,
    port_count: c_ulong,
    port_descriptors: *const c_int,
    port_names: *const *const c_char,
    port_range_hints: *const PortRangeHint,
    implementation_data: *mut c_void,
    instantiate: Option<unsafe extern "C" fn(*const Descriptor, c_ulong) -> Handle>,
    connect_port: Option<unsafe extern "C" fn(Handle, c_ulong, *mut f32)>,
    activate: Option<unsafe extern "C" fn(Handle)>,
    run: Option<unsafe extern "C" fn(Handle, c_ulong)>,
    run_adding: Option<unsafe extern "C" fn(Handle, c_ulong)>,
    set_run_adding_gain: Option<unsafe extern "C" fn(Handle, f32)>,
    deactivate: Option<unsafe extern "C" fn(Handle)>,
    cleanup: Option<unsafe extern "C" fn(Handle)>,
}

// SAFETY: the descriptor is immutable static data (pointers to static strings and arrays)
unsafe impl Sync for Descriptor {}

const PORT_INPUT: c_int = 0x1;
const PORT_OUTPUT: c_int = 0x2;
const PORT_CONTROL: c_int = 0x4;
const PORT_AUDIO: c_int = 0x8;
const PROPERTY_HARD_RT_CAPABLE: c_int = 0x4;

static PORT_DESCRIPTORS: [c_int; 3] = [PORT_INPUT | PORT_AUDIO, PORT_OUTPUT | PORT_AUDIO, PORT_OUTPUT | PORT_CONTROL];

struct Names([*const c_char; 3]);
// SAFETY: pointers to static C strings, never written
unsafe impl Sync for Names {}
static PORT_NAMES: Names = Names([c"Input".as_ptr(), c"Output".as_ptr(), c"latency".as_ptr()]);

static HINTS: [PortRangeHint; 3] = [
    PortRangeHint { hint: 0, lower: 0.0, upper: 0.0 },
    PortRangeHint { hint: 0, lower: 0.0, upper: 0.0 },
    PortRangeHint { hint: 0, lower: 0.0, upper: 0.0 },
];

struct Instance {
    live: Live,
    input: *const f32,
    output: *mut f32,
    latency: *mut f32,
    failed: bool,
}

unsafe extern "C" fn instantiate(_: *const Descriptor, rate: c_ulong) -> Handle {
    let made = catch_unwind(|| {
        let live = Live::new(&Config::default(), rate as f64);
        Box::new(Instance { live, input: std::ptr::null(), output: std::ptr::null_mut(), latency: std::ptr::null_mut(), failed: false })
    });
    match made {
        Ok(b) => Box::into_raw(b) as Handle,
        Err(_) => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn connect_port(h: Handle, port: c_ulong, data: *mut f32) {
    // SAFETY: h is a handle from instantiate (the host's contract)
    let inst = unsafe { &mut *(h as *mut Instance) };
    match port {
        0 => inst.input = data,
        1 => inst.output = data,
        2 => {
            inst.latency = data;
            if !data.is_null() {
                // the host may read it before the first run
                // SAFETY: a connected control port is one float
                unsafe { *data = inst.live.latency() as f32 };
            }
        }
        _ => {}
    }
}

unsafe extern "C" fn run(h: Handle, n: c_ulong) {
    // SAFETY: h is a handle from instantiate; the host connected the ports to buffers of at least n samples
    let inst = unsafe { &mut *(h as *mut Instance) };
    let n = n as usize;
    if !inst.latency.is_null() {
        // SAFETY: a connected control port is one float
        unsafe { *inst.latency = inst.live.latency() as f32 };
    }
    if inst.output.is_null() || n == 0 {
        return;
    }
    let silence = |out: *mut f32| {
        // SAFETY: the output buffer holds n samples
        unsafe { std::slice::from_raw_parts_mut(out, n) }.fill(0.0);
    };
    if inst.input.is_null() || inst.failed {
        silence(inst.output);
        return;
    }
    let (input, output) = (inst.input, inst.output);
    let live = &mut inst.live;
    let ok = catch_unwind(AssertUnwindSafe(|| {
        // The host may give one buffer for both (in place): each block is copied out of the input before a slice of the
        // output is made, so no two references to the same samples are alive at once.
        let mut i = 0;
        let mut x = [0.0f32; 256];
        while i < n {
            let m = (n - i).min(x.len());
            // SAFETY: the input buffer holds n samples
            x[..m].copy_from_slice(unsafe { std::slice::from_raw_parts(input.add(i), m) });
            // SAFETY: the output buffer holds n samples
            let out = unsafe { std::slice::from_raw_parts_mut(output.add(i), m) };
            live.process(&x[..m], out);
            i += m;
        }
    }));
    if ok.is_err() {
        inst.failed = true;
        silence(inst.output);
    }
}

unsafe extern "C" fn cleanup(h: Handle) {
    if !h.is_null() {
        // SAFETY: h came from Box::into_raw in instantiate and is cleaned up once
        drop(unsafe { Box::from_raw(h as *mut Instance) });
    }
}

static DESCRIPTOR: Descriptor = Descriptor {
    unique_id: 4_850_217,
    label: c"heimdall_scrub".as_ptr(),
    properties: PROPERTY_HARD_RT_CAPABLE,
    name: c"Heimdall location-sound scrub (aircraft tones, mains hum)".as_ptr(),
    maker: c"Artifex Technologies".as_ptr(),
    copyright: c"MPL-2.0 (with MIT parts from flyover-scrub)".as_ptr(),
    port_count: 3,
    port_descriptors: PORT_DESCRIPTORS.as_ptr(),
    port_names: PORT_NAMES.0.as_ptr(),
    port_range_hints: HINTS.as_ptr(),
    implementation_data: std::ptr::null_mut(),
    instantiate: Some(instantiate),
    connect_port: Some(connect_port),
    activate: None,
    run: Some(run),
    run_adding: None,
    set_run_adding_gain: None,
    deactivate: None,
    cleanup: Some(cleanup),
};

/// The LADSPA entry point: one plugin, index 0.
#[no_mangle]
pub extern "C" fn ladspa_descriptor(index: c_ulong) -> *const Descriptor {
    if index == 0 {
        &DESCRIPTOR
    } else {
        std::ptr::null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_can_drive_it_in_place_and_reads_the_latency() {
        let d = ladspa_descriptor(0);
        assert!(!d.is_null());
        assert!(ladspa_descriptor(1).is_null());
        // SAFETY: the static descriptor and its functions, driven the way a host does
        unsafe {
            let d = &*d;
            assert_eq!(std::ffi::CStr::from_ptr(d.label).to_str().unwrap(), "heimdall_scrub");
            let h = d.instantiate.unwrap()(d, 48000);
            assert!(!h.is_null());
            let mut buf = vec![0.0f32; 1024];
            let mut lat = 0.0f32;
            d.connect_port.unwrap()(h, 0, buf.as_mut_ptr());
            d.connect_port.unwrap()(h, 1, buf.as_mut_ptr());
            d.connect_port.unwrap()(h, 2, &mut lat);
            let mut seen = 0usize;
            for block in 0..60 {
                for (i, v) in buf.iter_mut().enumerate() {
                    // a 5 kHz tone: above the band, so it comes out as it went in, 1024 samples later
                    *v = (2.0 * std::f32::consts::PI * 5000.0 * (block * 1024 + i) as f32 / 48000.0).sin() * 0.3;
                }
                d.run.unwrap()(h, 1024);
                // after the first half second (the floor learns the empty band after the tone's onset)
                if block >= 24 {
                    let t0 = (block * 1024) as i64 - lat as i64;
                    for (i, v) in buf.iter().enumerate() {
                        let want = (2.0 * std::f32::consts::PI * 5000.0 * (t0 + i as i64) as f32 / 48000.0).sin() * 0.3;
                        assert!((v - want).abs() < 1e-3, "block {block} sample {i}: {v} vs {want}");
                        seen += 1;
                    }
                }
            }
            assert_eq!(lat, 1024.0);
            assert_eq!(seen, 36 * 1024);
            d.cleanup.unwrap()(h);
        }
    }
}
