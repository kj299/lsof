//! Well-known TCP/UDP port → service-name table for `-P` (port-name) output.
//!
//! lsof resolves ports against the system services database; Windows has no
//! stable equivalent file, so we ship a compact table of the common services.
//! This is the portable half of `-n`/`-P`: host (reverse-DNS) resolution lives
//! in the platform backend, but port naming is pure and unit-tested here.

use crate::model::Protocol;

/// Return the conventional service name for a well-known port, or `None`.
///
/// `proto` is accepted for future protocol-specific entries; today the common
/// services share a name across TCP and UDP, so it is currently unused beyond
/// documenting intent.
pub fn name(port: u16, _proto: Protocol) -> Option<&'static str> {
    let n = match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        67 => "bootps",
        68 => "bootpc",
        69 => "tftp",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "sunrpc",
        123 => "ntp",
        135 => "epmap",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        500 => "isakmp",
        514 => "syslog",
        515 => "printer",
        587 => "submission",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql-s",
        1434 => "ms-sql-m",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        3268 => "msft-gc",
        3269 => "msft-gc-ssl",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5060 => "sip",
        5432 => "postgresql",
        5671 => "amqps",
        5672 => "amqp",
        5900 => "vnc",
        5985 => "wsman",
        5986 => "wsmans",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => return None,
    };
    Some(n)
}

/// Format a port for display: the service name unless `numeric` (the `-P`
/// behavior) or the port is unknown.
pub fn format_port(port: u16, proto: Protocol, numeric: bool) -> String {
    if !numeric {
        if let Some(n) = name(port, proto) {
            return n.to_string();
        }
    }
    port.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports() {
        assert_eq!(name(443, Protocol::Tcp), Some("https"));
        assert_eq!(name(22, Protocol::Tcp), Some("ssh"));
        assert_eq!(name(445, Protocol::Tcp), Some("microsoft-ds"));
        assert_eq!(name(65000, Protocol::Tcp), None);
    }

    #[test]
    fn format_honors_numeric() {
        assert_eq!(format_port(443, Protocol::Tcp, false), "https");
        assert_eq!(format_port(443, Protocol::Tcp, true), "443");
        assert_eq!(format_port(65000, Protocol::Tcp, false), "65000");
    }
}
