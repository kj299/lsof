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

use std::collections::{BTreeMap, HashSet};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::slice;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    TdhGetEventInformation, CONTROLTRACE_HANDLE, EVENT_PROPERTY_INFO, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_EVENT_INFO, WNODE_FLAG_TRACED_GUID,
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
    /// Pre-rendered schema text for each unique `(Id, Version)` we've seen.
    /// Captured in the callback via TDH, surfaced at the end so iteration 3
    /// can pick authoritative property names / types instead of guessing
    /// offsets into `EVENT_RECORD.UserData`.
    pub schemas: BTreeMap<(u16, u8), String>,
}

/// `STATUS_BUFFER_TOO_SMALL` returned by `TdhGetEventInformation` when our
/// buffer is too small to hold the full `TRACE_EVENT_INFO` — used to drive
/// the "ask for size, grow, retry" loop.
const STATUS_BUFFER_TOO_SMALL: u32 = 122; // ERROR_INSUFFICIENT_BUFFER

impl Summary {
    /// Render a one-line summary, the top-N event-ID counts (sorted by
    /// frequency), and the captured schemas in `(Id, Version)` order.
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
        for ((id, ver), schema) in &self.schemas {
            out.push_str(&format!("\netw schema: id={id} version={ver}\n{schema}"));
        }
        out
    }
}

/// Callback-shared state. One `Box<CallbackState>` is leaked into the session
/// via `EVENT_TRACE_LOGFILEW.Context`, reclaimed after the session ends so the
/// buffer is dropped.
struct CallbackState {
    summary: Mutex<Summary>,
    /// `(EventId, Version)` pairs whose schema we've already dumped, to keep
    /// the schema work O(1) amortized per unique event.
    schema_seen: Mutex<HashSet<(u16, u8)>>,
}

/// `EVENT_RECORD_CALLBACK` for the AFD realtime session. Runs on the
/// `ProcessTrace` worker thread, per event. The hot path (counters only) is
/// bounded; the schema dump runs at most once per `(Id, Version)`.
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
    let version = r.EventHeader.EventDescriptor.Version;
    if let Ok(mut s) = state.summary.lock() {
        s.total += 1;
        *s.by_event_id.entry(id).or_insert(0) += 1;
    }
    // First time we see this (Id, Version) → ask TDH for the schema and
    // stash a rendered string. The mutex is fine here: this runs at most once
    // per unique event in the capture window (≤ ~20 times for AFD).
    let first_time = state
        .schema_seen
        .lock()
        .map(|mut s| s.insert((id, version)))
        .unwrap_or(false);
    if first_time {
        // SAFETY: `record` is a valid `EVENT_RECORD` for the duration of this
        // callback; `dump_event_schema` only reads from it.
        if let Some(schema) = unsafe { dump_event_schema(record) } {
            if let Ok(mut s) = state.summary.lock() {
                s.schemas.insert((id, version), schema);
            }
        }
    }
}

/// Pull the property schema for one event out of TDH and pretty-print it as
/// `  [i] Name<TAB>InType=… OutType=… Flags=…` lines. Returns `None` if TDH
/// couldn't resolve the schema (e.g. provider manifest not registered).
///
/// SAFETY: `record` must point to a valid `EVENT_RECORD` for the call.
unsafe fn dump_event_schema(record: *const EVENT_RECORD) -> Option<String> {
    // Two-call idiom: ask for required size, then allocate + ask for content.
    let mut size: u32 = 0;
    let rc = unsafe {
        TdhGetEventInformation(record, 0, std::ptr::null(), std::ptr::null_mut(), &mut size)
    };
    if rc != STATUS_BUFFER_TOO_SMALL && rc != 0 {
        trace(&format!(
            "etw: TdhGetEventInformation(size) failed (status {rc})"
        ));
        return None;
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        TdhGetEventInformation(
            record,
            0,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut TRACE_EVENT_INFO,
            &mut size,
        )
    };
    if rc != 0 {
        trace(&format!(
            "etw: TdhGetEventInformation(fetch) failed (status {rc})"
        ));
        return None;
    }

    // SAFETY: TDH wrote `size` bytes; the first sizeof(TRACE_EVENT_INFO) bytes
    // are the header, followed by a trailing array of EVENT_PROPERTY_INFO
    // referenced by offsets the API filled in. We only read.
    let info = unsafe { &*(buf.as_ptr() as *const TRACE_EVENT_INFO) };
    let count = info.PropertyCount as usize;
    if count == 0 {
        return Some("  (no properties)".to_string());
    }
    let props_start = size_of::<TRACE_EVENT_INFO>();
    // SAFETY: TDH guarantees the array of `count` EVENT_PROPERTY_INFO entries
    // follows the header, within `size` bytes.
    let props: &[EVENT_PROPERTY_INFO] =
        unsafe { slice::from_raw_parts(buf.as_ptr().add(props_start) as *const _, count) };

    let mut out = String::new();
    for (i, p) in props.iter().enumerate() {
        let name_offset = p.NameOffset as usize;
        let name = read_wide_at(&buf, name_offset);
        // SAFETY: union read — non-array properties use `nonStructType`. The
        // array variant is uncommon for AFD events; we just print whatever's
        // there as `InType` / `OutType` u16s without interpreting.
        let in_type = unsafe { p.Anonymous1.nonStructType.InType };
        let out_type = unsafe { p.Anonymous1.nonStructType.OutType };
        out.push_str(&format!(
            "  [{i:>2}] {name:<28} InType={in_type:<3} OutType={out_type}\n"
        ));
    }
    // Trim the trailing newline so the renderer's "\n" between schemas is clean.
    if out.ends_with('\n') {
        out.pop();
    }
    Some(out)
}

/// Read a NUL-terminated wide string starting at `offset` inside `buf`,
/// returning a `String`. Used to pull property and event names out of the
/// trailing string area of `TRACE_EVENT_INFO`.
fn read_wide_at(buf: &[u8], offset: usize) -> String {
    if offset >= buf.len() {
        return String::new();
    }
    let mut chars = Vec::new();
    let mut i = offset;
    while i + 1 < buf.len() {
        let c = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if c == 0 {
            break;
        }
        chars.push(c);
        i += 2;
    }
    String::from_utf16_lossy(&chars)
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
    trace(&format!(
        "etw: StartTraceW ok (session handle = {:#x})",
        session_handle.Value
    ));

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
    trace("etw: EnableTraceEx2 ok (AFD provider enabled)");

    let state = Box::new(CallbackState {
        summary: Mutex::new(Summary::default()),
        schema_seen: Mutex::new(HashSet::new()),
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

        trace("etw: worker: OpenTraceW...");
        // SAFETY: logfile is fully initialized for realtime consumption.
        let trace_handle: PROCESSTRACE_HANDLE = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == INVALID_PROCESSTRACE_HANDLE {
            // GetLastError is the only diagnostic — surface it so the user can
            // map e.g. 0xC0000034 (STATUS_OBJECT_NAME_NOT_FOUND) /
            // 1018 (ERROR_WMI_INSTANCE_NOT_FOUND) to the cause.
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            trace(&format!(
                "etw: worker: OpenTraceW returned INVALID_PROCESSTRACE_HANDLE (GetLastError = {err})"
            ));
            return;
        }
        trace(&format!(
            "etw: worker: OpenTraceW ok (trace handle = {:#x}); ProcessTrace start (blocks)",
            trace_handle.Value
        ));
        // SAFETY: ProcessTrace blocks, dispatching events to the callback,
        // and returns when the session is stopped from the main thread.
        let rc = unsafe { ProcessTrace(&trace_handle, 1, std::ptr::null(), std::ptr::null()) };
        trace(&format!("etw: worker: ProcessTrace returned (status {rc})"));
        // SAFETY: trace_handle was returned by OpenTraceW above.
        unsafe {
            CloseTrace(trace_handle);
        }
    });

    thread::sleep(duration);

    // Stopping the session makes ProcessTrace return on the worker.
    // SAFETY: session_handle is valid; props buffer is the one we kept alive.
    let stop_rc = unsafe {
        ControlTraceW(
            session_handle,
            std::ptr::null(),
            props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
    trace(&format!(
        "etw: ControlTraceW STOP issued (status {stop_rc}); joining worker"
    ));
    let _ = worker.join();
    trace("etw: worker joined");

    // Reclaim the callback state; the worker is joined so no further events
    // can reference it.
    // SAFETY: we created this Box::into_raw above; it's only reclaimed here.
    let state = unsafe { Box::from_raw(state_addr as *mut CallbackState) };
    Some(state.summary.into_inner().unwrap_or_default())
}
