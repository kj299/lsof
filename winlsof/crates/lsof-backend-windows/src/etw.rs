//! Opt-in ETW realtime consumer (`--etw`): listens to
//! `Microsoft-Windows-Winsock-AFD` events for a short window. The eventual
//! goal (P2) is to extend `-i` coverage to socket families IP Helper doesn't
//! enumerate (raw, ICMP, AF_UNIX); see `docs/research-roadmap.md` §5 for the
//! P1 spike findings that scoped this work.
//!
//! Iteration 1 (this file): just the session lifecycle and an event-ID
//! histogram. No row emission yet. The histogram lets us verify the FFI
//! machinery (StartTraceW / EnableTraceEx2 / ProcessTrace / ControlTraceW)
//! and the callback flow end-to-end against the same event mix the P1 spike
//! captured, before adding TDH parsing in iteration 2.
//!
//! The session needs Administrator (or *Performance Log Users* membership).
//! `--etw` is opt-in, never default; a setup failure (e.g. not enough
//! privilege) is reported via stderr and the rest of `gather` continues.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

use crate::util::trace;

/// `Microsoft-Windows-Winsock-AFD` provider GUID. AFD's per-socket I/O events
/// fire for *every* socket family it manages (TCP, UDP, raw, ICMP, AF_UNIX,
/// …), confirmed by the P1 spike — which makes it the right hook for the
/// non-TCP/UDP coverage P2 will eventually deliver.
const AFD_PROVIDER_GUID: GUID = GUID {
    data1: 0xE53C_6823,
    data2: 0x7BB8,
    data3: 0x44BB,
    data4: [0x90, 0xDC, 0x3F, 0x86, 0x09, 0x0D, 0x48, 0xA6],
};

const SESSION_NAME_PREFIX: &str = "winlsof-etw-";

/// `ControlCode` value for [`EnableTraceEx2`]: enable the provider.
const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;

/// `Level` value for [`EnableTraceEx2`]: capture everything up to and
/// including Verbose. AFD only uses Info, so this is effectively "all".
const TRACE_LEVEL_VERBOSE: u8 = 0xFF;

/// `Value` of a session handle that means "look up by name" in
/// `ControlTraceW` (used to stop a possibly-stale session before we start a
/// fresh one).
const NULL_CONTROLTRACE_HANDLE: CONTROLTRACE_HANDLE = CONTROLTRACE_HANDLE { Value: 0 };

/// Sentinel returned by [`OpenTraceW`] on failure.
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;

/// Aggregated result of one ETW capture window — the only data iteration 1
/// emits. Iteration 2 will replace this with parsed (PID, endpoint, addr)
/// records.
#[derive(Default, Debug)]
pub struct Summary {
    pub total: usize,
    pub by_event_id: BTreeMap<u16, usize>,
}

impl Summary {
    /// Render a one-line summary plus the top-N event-ID counts, sorted by
    /// frequency. Used to print to stderr after a `--etw` gather so the user
    /// can see what the session actually picked up.
    pub fn render(&self, top_n: usize) -> String {
        let mut by_id: Vec<(&u16, &usize)> = self.by_event_id.iter().collect();
        by_id.sort_by(|a, b| b.1.cmp(a.1));
        let mut out = format!(
            "etw: captured {} events across {} distinct ids",
            self.total,
            self.by_event_id.len()
        );
        for (id, count) in by_id.into_iter().take(top_n) {
            out.push_str(&format!("\netw:   id={id:<5} count={count}"));
        }
        out
    }
}

/// Callback-shared state (event-ID histogram). One `Box<CallbackState>` is
/// leaked into the session via `EVENT_TRACE_LOGFILEW.Context`, reclaimed after
/// the session ends so the buffer is dropped.
struct CallbackState {
    summary: Mutex<Summary>,
}

/// `EVENT_RECORD_CALLBACK` for the AFD realtime session. Runs on the
/// `ProcessTrace` worker thread, per event. Keep it bounded — we only update
/// counters; no allocation or blocking work.
///
/// SAFETY: invoked by ETW with a valid `EVENT_RECORD` pointer; `UserContext`
/// is the `Box<CallbackState>` pointer we passed in, and it outlives the
/// session because the main thread joins the worker before reclaiming it.
unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let r = unsafe { &*record };
    let state_ptr = r.UserContext as *const CallbackState;
    if state_ptr.is_null() {
        return;
    }
    let state = unsafe { &*state_ptr };
    let id = r.EventHeader.EventDescriptor.Id;
    if let Ok(mut s) = state.summary.lock() {
        s.total += 1;
        *s.by_event_id.entry(id).or_insert(0) += 1;
    }
}

/// Build an `EVENT_TRACE_PROPERTIES` buffer sized for the trailing logger-name
/// region the API expects. Returns the backing `Vec<u8>` (caller keeps it
/// alive) and the typed pointer.
fn alloc_props(total_size: usize) -> (Vec<u8>, *mut EVENT_TRACE_PROPERTIES) {
    let mut buf = vec![0u8; total_size];
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    // SAFETY: `buf` is at least `size_of::<EVENT_TRACE_PROPERTIES>()` bytes and
    // zero-initialized; writing through `p` only touches owned memory.
    unsafe {
        let props = &mut *p;
        props.Wnode.BufferSize = total_size as u32;
        // ClientContext = 1 -> QPC timestamps (highest-resolution option).
        props.Wnode.ClientContext = 1;
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        // LogFileNameOffset stays 0 — realtime, no file.
    }
    (buf, p)
}

/// Run a bounded ETW realtime session against the AFD provider for `duration`,
/// returning the per-event-ID histogram. Returns `None` on session setup
/// failure (insufficient privilege, provider missing, etc.) — the caller logs
/// and continues without ETW data.
pub fn capture(duration: Duration) -> Option<Summary> {
    let session_name = format!("{SESSION_NAME_PREFIX}{}", std::process::id());
    let session_name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let props_size = size_of::<EVENT_TRACE_PROPERTIES>();
    let name_bytes = session_name_wide.len() * 2;
    let total_size = props_size + name_bytes;

    // Best-effort stop of any stale session under our name (e.g. a prior
    // `lsof --etw` killed mid-run that didn't clean up). Result is ignored:
    // no stale session is the common case.
    {
        let (_buf, props) = alloc_props(total_size);
        // SAFETY: props is a valid, sized buffer; null-value handle makes
        // ControlTraceW look the session up by name.
        unsafe {
            ControlTraceW(
                NULL_CONTROLTRACE_HANDLE,
                session_name_wide.as_ptr(),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }

    let (mut props_buf, props) = alloc_props(total_size);

    let mut session_handle: CONTROLTRACE_HANDLE = NULL_CONTROLTRACE_HANDLE;
    // SAFETY: session_handle is a CONTROLTRACE_HANDLE output param; props is a
    // valid sized buffer; name is NUL-terminated.
    let rc = unsafe { StartTraceW(&mut session_handle, session_name_wide.as_ptr(), props) };
    if rc != 0 {
        trace(&format!("etw: StartTraceW failed (status {rc})"));
        eprintln!(
            "lsof: --etw could not start an ETW session (status {rc}); a session needs Administrator or Performance Log Users membership"
        );
        return None;
    }

    // SAFETY: session_handle is now valid; the provider GUID is a const we own.
    let rc = unsafe {
        EnableTraceEx2(
            session_handle,
            &AFD_PROVIDER_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            u64::MAX, // match-any keyword: all
            0,        // match-all keyword: none
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        trace(&format!("etw: EnableTraceEx2 failed (status {rc})"));
        // SAFETY: tear down the session we just started.
        unsafe {
            ControlTraceW(
                session_handle,
                std::ptr::null(),
                props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        return None;
    }

    let state = Box::new(CallbackState {
        summary: Mutex::new(Summary::default()),
    });
    let state_addr = Box::into_raw(state) as usize;

    // Hand the session name and the state-pointer to the worker thread. Raw
    // pointers aren't Send; passing an integer address sidesteps that. The
    // main thread keeps `session_name_wide` alive via the worker's clone for
    // the duration ProcessTrace runs.
    let name_for_worker = session_name_wide.clone();
    let worker = thread::spawn(move || {
        let state_ptr = state_addr as *mut CallbackState;
        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
        logfile.LoggerName = name_for_worker.as_ptr() as *mut u16;
        // Writing through a union field does not require `unsafe` (only
        // reads do); we pick the realtime/event-record overlay of each union.
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_callback);
        logfile.Context = state_ptr as *mut c_void;

        // SAFETY: logfile is fully initialized for realtime consumption.
        let trace_handle: PROCESSTRACE_HANDLE = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == INVALID_PROCESSTRACE_HANDLE {
            return;
        }
        // SAFETY: ProcessTrace blocks, dispatching events to the callback,
        // and returns when the session is stopped from the main thread.
        let _ = unsafe { ProcessTrace(&trace_handle, 1, std::ptr::null(), std::ptr::null()) };
        // SAFETY: trace_handle was returned by OpenTraceW above.
        unsafe {
            CloseTrace(trace_handle);
        }
    });

    thread::sleep(duration);

    // Stopping the session makes ProcessTrace return on the worker.
    // SAFETY: session_handle is valid; props buffer is the one we kept alive.
    unsafe {
        ControlTraceW(
            session_handle,
            std::ptr::null(),
            props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
    let _ = worker.join();

    // Reclaim the callback state; the worker is joined so no further events
    // can reference it.
    // SAFETY: we created this Box::into_raw above; it's only reclaimed here.
    let state = unsafe { Box::from_raw(state_addr as *mut CallbackState) };
    Some(state.summary.into_inner().unwrap_or_default())
}
