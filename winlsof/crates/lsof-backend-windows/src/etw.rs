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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::slice;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile, Protocol, SocketInfo};
use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize, CONTROLTRACE_HANDLE,
    EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR,
    TRACE_EVENT_INFO, WNODE_FLAG_TRACED_GUID,
};

use crate::util::trace;

// --- AFD socket families and protocols we recognize ---
// AddressFamily values (per `ws2def.h`).
const AF_UNSPEC: u16 = 0;
const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

// IP protocols (per `IANA` / `winsock2.h`).
const IPPROTO_ICMP: u32 = 1;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const IPPROTO_ICMPV6: u32 = 58;
const IPPROTO_RAW: u32 = 255;

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

// --- AFD event IDs we parse (confirmed by the iteration-2 schema dump) ---
/// `AfdCreate` — Process, Endpoint, AddressFamily, SocketType, Protocol.
const EVENT_ID_AFD_CREATE: u16 = 1000;
/// Address-bearing AFD events. Each carries `Endpoint` and the variable-size
/// `Address` blob (a sockaddr) we decode via `parse_sockaddr`.
const EVENT_IDS_AFD_WITH_ADDRESS: &[u16] = &[
    1007, // SendTo
    1009, // RecvFrom (older variant)
    1013, // RecvFrom (V2 variant, same shape as 1015 per the schema dump)
    1015, // RecvMsg with addr
    1018, // RecvFrom (newer variant)
    1030, // ConnectWithAddress
    3004, // Data indication (with addr)
];

// SOCK_* values from winsock2.h, used as the SocketType in AfdCreate.
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;

/// Aggregated result of one ETW capture window — the only data iteration 1
/// emits. Iteration 2 will replace this with parsed (PID, endpoint, addr)
/// records.
#[derive(Default, Debug)]
pub struct Summary {
    pub total: usize,
    pub by_event_id: BTreeMap<u16, usize>,
    /// Pre-rendered schema text for each unique `(Id, Version)` we've seen.
    /// Captured in the callback via TDH; useful for diagnosing/extending
    /// `parse_afd_create` / `parse_afd_address` on future Windows builds.
    pub schemas: BTreeMap<(u16, u8), String>,
    /// AFD-observed sockets, keyed by Endpoint pointer. The caller
    /// (`backend::gather`) filters out IP-Helper-covered rows via
    /// [`EtwSocket::is_covered_by_ip_helper`] and emits the rest as `-i`
    /// rows. Empty if the capture window saw no AfdCreate / address events.
    pub sockets: Vec<EtwSocket>,
}

/// `STATUS_BUFFER_TOO_SMALL` returned by `TdhGetEventInformation` when our
/// buffer is too small to hold the full `TRACE_EVENT_INFO` — used to drive
/// the "ask for size, grow, retry" loop.
const STATUS_BUFFER_TOO_SMALL: u32 = 122; // ERROR_INSUFFICIENT_BUFFER

/// One AFD-observed socket, keyed by `Endpoint` (the kernel AFD-endpoint
/// pointer that uniquely identifies a socket within a boot session). Populated
/// from AfdCreate (Id 1000) and refined by the address-bearing events.
#[derive(Clone, Debug)]
pub struct EtwSocket {
    pub pid: u32,
    pub endpoint: u64,
    /// Raw AddressFamily from AfdCreate (`AF_INET`, `AF_INET6`, `AF_UNIX`, …).
    pub family: u16,
    pub socket_type: u32,
    pub protocol_raw: u32,
    /// Last remote address observed via an addr-bearing AFD event.
    pub last_remote: Option<SocketAddr>,
}

impl EtwSocket {
    /// IP protocol number, after the `socket(..., 0)` fallback. Callers should
    /// use this rather than `protocol_raw`: AfdCreate records the value passed
    /// to the userland `socket()` call verbatim, which is commonly `0`
    /// ("default for this socket type"). Without the fallback every
    /// `socket(AF_INET, SOCK_STREAM, 0)` (i.e. every normal TCP socket) would
    /// look like "unknown protocol" and dodge the IP-Helper-coverage filter.
    pub fn effective_protocol(&self) -> u32 {
        if self.protocol_raw != 0 {
            return self.protocol_raw;
        }
        match self.socket_type {
            SOCK_STREAM => IPPROTO_TCP,
            SOCK_DGRAM => IPPROTO_UDP,
            SOCK_RAW => IPPROTO_RAW,
            _ => 0,
        }
    }

    /// Whether this endpoint is one IP Helper's TCP/UDP tables already cover —
    /// in which case our [`emit_extras`] caller should skip it. We surface only
    /// the rows IP Helper *doesn't* enumerate.
    pub fn is_covered_by_ip_helper(&self) -> bool {
        let proto = self.effective_protocol();
        (self.family == AF_INET || self.family == AF_INET6)
            && (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
    }

    /// lsof-style protocol label (NODE column) — TCP/UDP for the boring rows,
    /// "ICMP"/"ICMPV6"/"RAW"/"AF_UNIX"/etc. for the interesting ones.
    pub fn protocol(&self) -> Protocol {
        let proto = self.effective_protocol();
        match (self.family, proto) {
            (_, IPPROTO_TCP) => Protocol::Tcp,
            (_, IPPROTO_UDP) => Protocol::Udp,
            (_, IPPROTO_ICMP) => Protocol::Other("ICMP"),
            (_, IPPROTO_ICMPV6) => Protocol::Other("ICMPV6"),
            (_, IPPROTO_RAW) => Protocol::Other("RAW"),
            (AF_UNIX, _) => Protocol::Other("AF_UNIX"),
            (AF_UNSPEC, _) => Protocol::Other("AF_UNSPEC"),
            _ => Protocol::Other("OTHER"),
        }
    }

    /// lsof TYPE-column code (IPv4 / IPv6 / unix / unknown) for this endpoint.
    fn file_type(&self) -> FileType {
        match self.family {
            AF_INET => FileType::Ipv4,
            AF_INET6 => FileType::Ipv6,
            AF_UNIX => FileType::Unix,
            _ => FileType::Unknown,
        }
    }
}

/// Build an `OpenFile` row from an AFD-observed socket. The IP-Helper-covered
/// rows are filtered out upstream by [`EtwSocket::is_covered_by_ip_helper`];
/// what this emits is the non-TCP/UDP coverage the `--etw` mode exists for.
pub fn to_open_file(sock: &EtwSocket) -> OpenFile {
    let protocol = sock.protocol();
    // ETW doesn't reliably expose the local bind address (AfdBind's address
    // sits in an unnamed binary property — see the schema dump). The
    // renderer prints `*:*` for an absent local, which is lsof's convention.
    let info = SocketInfo {
        protocol,
        local: None,
        remote: sock.last_remote,
        state: None,
    };
    // Use lsof's NAME convention: `*:*->1.2.3.4:443` when we have a remote
    // (the local `*:*` reflects unknown bind). For endpoints we only saw via
    // create/bind/connect events (no addr), fall back to the kernel
    // endpoint pointer so the row still identifies the socket uniquely.
    let name = if sock.last_remote.is_some() {
        info.display_name(true, true)
    } else {
        format!("(endpoint 0x{:x})", sock.endpoint)
    };
    OpenFile {
        fd: FdType::Unknown,
        access: AccessMode::ReadWrite,
        file_type: sock.file_type(),
        name,
        device: None,
        size: None,
        offset: None,
        node: Some(protocol.as_str().to_string()),
        socket: Some(info),
    }
}

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
        if !self.sockets.is_empty() {
            let extras: usize = self
                .sockets
                .iter()
                .filter(|s| !s.is_covered_by_ip_helper())
                .count();
            out.push_str(&format!(
                "\netw: aggregated {} unique endpoints ({} non-TCP/UDP)",
                self.sockets.len(),
                extras
            ));
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
    /// Aggregator keyed by AFD `Endpoint` pointer — accumulates create info
    /// (family/type/protocol) and refines with any address-bearing event.
    sockets: Mutex<HashMap<u64, EtwSocket>>,
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
    let pid = r.EventHeader.ProcessId;
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
    // Per-event aggregation. SAFETY: `record` is valid; helpers only read.
    if id == EVENT_ID_AFD_CREATE {
        if let Some((endpoint, family, sock_type, protocol)) = unsafe { parse_afd_create(record) } {
            if let Ok(mut socks) = state.sockets.lock() {
                socks
                    .entry(endpoint)
                    .and_modify(|e| {
                        e.family = family;
                        e.socket_type = sock_type;
                        e.protocol_raw = protocol;
                    })
                    .or_insert(EtwSocket {
                        pid,
                        endpoint,
                        family,
                        socket_type: sock_type,
                        protocol_raw: protocol,
                        last_remote: None,
                    });
            }
        }
    } else if EVENT_IDS_AFD_WITH_ADDRESS.contains(&id) {
        if let Some((endpoint, addr)) = unsafe { parse_afd_address(record) } {
            if let Ok(mut socks) = state.sockets.lock() {
                socks
                    .entry(endpoint)
                    .and_modify(|e| e.last_remote = Some(addr))
                    .or_insert(EtwSocket {
                        pid,
                        endpoint,
                        // No create event was seen in this window: family
                        // unknown. Infer from the sockaddr family if we can.
                        family: match addr {
                            SocketAddr::V4(_) => AF_INET,
                            SocketAddr::V6(_) => AF_INET6,
                        },
                        socket_type: 0,
                        protocol_raw: 0,
                        last_remote: Some(addr),
                    });
            }
        }
    }
}

/// Pull `(Endpoint, AddressFamily, SocketType, Protocol)` out of an AfdCreate
/// (Id 1000) event using TDH-by-name. Property names confirmed by the
/// iteration-2 schema dump.
///
/// SAFETY: `record` must point to a valid `EVENT_RECORD` for the call.
unsafe fn parse_afd_create(record: *const EVENT_RECORD) -> Option<(u64, u16, u32, u32)> {
    let endpoint = unsafe { get_property_u64(record, "Endpoint") }?;
    let family = unsafe { get_property_u32(record, "AddressFamily") }? as u16;
    let socket_type = unsafe { get_property_u32(record, "SocketType") }.unwrap_or(0);
    let protocol = unsafe { get_property_u32(record, "Protocol") }.unwrap_or(0);
    Some((endpoint, family, socket_type, protocol))
}

/// Pull `(Endpoint, sockaddr)` out of an address-bearing AFD event (Id 1007 /
/// 1009 / 1015 / 1018 / 1030 / 3004).
///
/// SAFETY: `record` must point to a valid `EVENT_RECORD` for the call.
unsafe fn parse_afd_address(record: *const EVENT_RECORD) -> Option<(u64, SocketAddr)> {
    let endpoint = unsafe { get_property_u64(record, "Endpoint") }?;
    let blob = unsafe { get_property_bytes(record, "Address") }?;
    let addr = parse_sockaddr(&blob)?;
    Some((endpoint, addr))
}

/// Decode a Windows `SOCKADDR_IN` / `SOCKADDR_IN6` blob to a `SocketAddr`.
/// The first 2 bytes are `sin_family` (little-endian u16); for `AF_INET` the
/// next 2 are the port (network order) and the next 4 are the IPv4 address;
/// for `AF_INET6` the next 2 are the port, then 4 bytes flowinfo, then 16
/// bytes of address. Returns `None` if the blob is too short or the family
/// isn't an IP family.
fn parse_sockaddr(blob: &[u8]) -> Option<SocketAddr> {
    if blob.len() < 2 {
        return None;
    }
    let family = u16::from_le_bytes([blob[0], blob[1]]);
    match family {
        AF_INET if blob.len() >= 8 => {
            let port = u16::from_be_bytes([blob[2], blob[3]]);
            let addr = Ipv4Addr::new(blob[4], blob[5], blob[6], blob[7]);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        AF_INET6 if blob.len() >= 24 => {
            let port = u16::from_be_bytes([blob[2], blob[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&blob[8..24]);
            let addr = Ipv6Addr::from(octets);
            Some(SocketAddr::new(IpAddr::V6(addr), port))
        }
        _ => None,
    }
}

/// `TdhGetProperty` wrapper for fixed-width scalars. Returns `None` if TDH
/// can't find or read the named property.
///
/// SAFETY: `record` must point to a valid `EVENT_RECORD`.
unsafe fn get_property_scalar<T: Copy + Default>(
    record: *const EVENT_RECORD,
    name: &str,
) -> Option<T> {
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name_wide.as_ptr() as u64,
        ArrayIndex: 0,
        Reserved: 0,
    };
    let mut value: T = T::default();
    let rc = unsafe {
        TdhGetProperty(
            record,
            0,
            std::ptr::null(),
            1,
            &descriptor,
            size_of::<T>() as u32,
            &mut value as *mut T as *mut u8,
        )
    };
    (rc == 0).then_some(value)
}

unsafe fn get_property_u32(record: *const EVENT_RECORD, name: &str) -> Option<u32> {
    unsafe { get_property_scalar::<u32>(record, name) }
}

unsafe fn get_property_u64(record: *const EVENT_RECORD, name: &str) -> Option<u64> {
    unsafe { get_property_scalar::<u64>(record, name) }
}

/// `TdhGetProperty` wrapper for variable-length byte properties (e.g. the
/// AFD `Address` sockaddr blob). Returns `None` if TDH can't find/read it.
///
/// SAFETY: `record` must point to a valid `EVENT_RECORD`.
unsafe fn get_property_bytes(record: *const EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name_wide.as_ptr() as u64,
        ArrayIndex: 0,
        Reserved: 0,
    };
    let mut size: u32 = 0;
    let rc = unsafe { TdhGetPropertySize(record, 0, std::ptr::null(), 1, &descriptor, &mut size) };
    if rc != 0 || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        TdhGetProperty(
            record,
            0,
            std::ptr::null(),
            1,
            &descriptor,
            size,
            buf.as_mut_ptr(),
        )
    };
    (rc == 0).then_some(buf)
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
        sockets: Mutex::new(HashMap::new()),
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
    let CallbackState {
        summary, sockets, ..
    } = *state;
    let mut summary = summary.into_inner().unwrap_or_default();
    // Drain the aggregator into the Summary so the caller doesn't need to
    // know about the internal mutex.
    if let Ok(map) = sockets.into_inner() {
        summary.sockets = map.into_values().collect();
    }
    Some(summary)
}
