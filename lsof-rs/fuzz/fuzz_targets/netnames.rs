#![no_main]

// Fuzz the readers of the files `-i` resolves a host or service name from
// (lsof-core, `netnames`; DIVERGENCES 38): `/etc/hosts`, `/etc/services`,
// `/etc/host.conf` and `/etc/nsswitch.conf`, each root-owned and only as
// well-formed as its last editor left it, searched for a name typed on the
// command line; and the rule for a name that is a number. Contract: no
// panic on arbitrary bytes, and a bounded answer.

use libfuzzer_sys::fuzz_target;
use lsof_core::netnames::{
    bool_arg, host_conf_multi, hosts_lookup, inet_aton, nsswitch_files_first, numeric_host,
    services_lookup, MAX_ADDRESSES,
};

fuzz_target!(|data: &[u8]| {
    // The first line is the name asked for, the rest the file.
    let mut parts = data.splitn(2, |&b| b == b'\n');
    let name = parts.next().unwrap_or_default();
    let text = parts.next().unwrap_or_default();
    for v6 in [false, true] {
        let one = hosts_lookup(text, name, v6, false);
        let all = hosts_lookup(text, name, v6, true);
        // Without `multi`, the first address alone; with it, a bounded
        // number, the first the same; and every one of the family asked.
        assert!(one.len() <= 1);
        assert!(all.len() <= MAX_ADDRESSES);
        assert_eq!(one.first(), all.first());
        assert!(all.iter().all(|ip| ip.is_ipv6() == v6));
        // A number is answered with one IPv4 address, or none.
        if let Some(answer) = numeric_host(name, v6) {
            assert!(answer.is_none_or(|ip| ip.is_ipv4() && !v6));
        }
    }
    for protocol in [&b"tcp"[..], b"udp", b"udplite", b""] {
        let _ = services_lookup(text, name, protocol);
    }
    // A name `gethostbyname2()` answers as a number, `inet_aton()` reads.
    if let Some(Some(std::net::IpAddr::V4(ip))) = numeric_host(name, false) {
        assert_eq!(inet_aton(name, false), Some(ip));
        assert_eq!(inet_aton(name, true), Some(ip));
    }
    let _ = inet_aton(name, true);
    let _ = host_conf_multi(data);
    let _ = bool_arg(name);
    let order = nsswitch_files_first(data, b"hosts");
    assert!(order.first || !order.only);
});
