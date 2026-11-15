use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::{unspecified, Family, Proto, SockState, SocketRec, TcpStats};

/// `INET_DIAG_INFO` is a host-endian copy of `struct tcp_info`.
/// Offsets match the kernel layout through `tcpi_bytes_received` (136 bytes).
pub fn parse_tcp_info(bytes: &[u8]) -> Option<TcpStats> {
    if bytes.len() < 104 {
        return None;
    }
    let rtt_us = read_u32(bytes, 68)?;
    let total_retrans = read_u32(bytes, 100)?;
    let bytes_acked = if bytes.len() >= 128 {
        read_u64(bytes, 120)?
    } else {
        0
    };
    let bytes_received = if bytes.len() >= 136 {
        read_u64(bytes, 128)?
    } else {
        0
    };
    Some(TcpStats {
        rtt_us,
        total_retrans,
        bytes_acked,
        bytes_received,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_ne_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    Some(u64::from_ne_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

/// Parse `lsof -nP -F pcPTtin` field output.
pub fn parse_lsof_field(text: &str) -> Vec<SocketRec> {
    let mut out = Vec::new();
    let mut pid: u32 = 0;
    let mut proto = Proto::Tcp;
    let mut v6 = false;
    let mut state = SockState::Close;
    let mut inode = 0u64;
    let mut saw_state = false;
    for line in text.lines() {
        let mut chars = line.chars();
        let Some(tag) = chars.next() else {
            continue;
        };
        let value = chars.as_str();
        match tag {
            'p' => {
                pid = value.parse().unwrap_or(0);
                inode = 0;
                saw_state = false;
                state = SockState::Close;
            }
            'P' => {
                proto = if value.eq_ignore_ascii_case("UDP") {
                    Proto::Udp
                } else {
                    Proto::Tcp
                };
            }
            't' => {
                v6 = value.to_ascii_uppercase().contains("IPv6") || value == "IPv6";
            }
            'T' => {
                if let Some(name) = value.split('=').nth(1) {
                    state = SockState::from_name(name);
                    saw_state = true;
                }
            }
            'i' => inode = value.parse().unwrap_or(0),
            'n' => {
                if let Some(sock) = socket_from_name(value, proto, v6, state, saw_state, pid, inode)
                {
                    out.push(sock);
                }
            }
            _ => {}
        }
    }
    out
}

fn socket_from_name(
    name: &str,
    proto: Proto,
    v6: bool,
    state: SockState,
    saw_state: bool,
    pid: u32,
    inode: u64,
) -> Option<SocketRec> {
    let family = if v6 { Family::V6 } else { Family::V4 };
    let (local, remote) = split_endpoints(name, family)?;
    let mut resolved = state;
    if !saw_state {
        resolved = if remote.1 == 0 {
            if proto == Proto::Tcp {
                SockState::Listen
            } else {
                SockState::Close
            }
        } else {
            SockState::Established
        };
    }
    let mut sock = SocketRec::new(
        proto, family, resolved, local.0, local.1, remote.0, remote.1,
    );
    sock.inode = inode;
    if pid != 0 {
        sock.pids.push(pid);
    }
    Some(sock)
}

/// Parse `ss -H -ltnup` / `ss -H -tnup` lines.
pub fn parse_ss(text: &str) -> Vec<SocketRec> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(state_tok) = parts.next() else {
            continue;
        };
        let Some(recv_q) = parts.next() else {
            continue;
        };
        if recv_q.chars().any(|c| !c.is_ascii_digit()) {
            continue;
        }
        let Some(_send_q) = parts.next() else {
            continue;
        };
        let Some(local) = parts.next() else {
            continue;
        };
        let Some(remote) = parts.next() else {
            continue;
        };
        let rest = parts.collect::<Vec<_>>().join(" ");
        let state = SockState::from_name(state_tok);
        let lower = line.to_ascii_lowercase();
        let proto = if state_tok.eq_ignore_ascii_case("UNCONN")
            || state_tok.eq_ignore_ascii_case("udp")
            || lower.contains("udp")
        {
            Proto::Udp
        } else {
            Proto::Tcp
        };
        let family = if local.starts_with('[') || local.starts_with("::") {
            Family::V6
        } else {
            Family::V4
        };
        let Some((local_ep, remote_ep)) = split_endpoints(&format!("{local}->{remote}"), family)
        else {
            continue;
        };
        // split_endpoints on "local->remote" works. But remote might already be the peer.
        let mut sock = SocketRec::new(
            proto,
            family,
            state,
            local_ep.0,
            local_ep.1,
            remote_ep.0,
            remote_ep.1,
        );
        sock.pids = pids_from_users(&rest);
        out.push(sock);
    }
    out
}

/// Parse Linux `netstat -lntup` lines.
pub fn parse_netstat(text: &str) -> Vec<SocketRec> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Active") || line.starts_with("Proto") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let proto_tok = parts[0].to_ascii_lowercase();
        let proto = if proto_tok.starts_with("udp") {
            Proto::Udp
        } else if proto_tok.starts_with("tcp") {
            Proto::Tcp
        } else {
            continue;
        };
        let v6 = proto_tok.contains('6');
        let family = if v6 { Family::V6 } else { Family::V4 };
        // proto recv send local foreign [state] pid/prog
        if parts.len() < 6 {
            continue;
        }
        let local = parts[3];
        let foreign = parts[4];
        let (state, pid_field) = if parts.len() >= 7 && looks_like_state(parts[5]) {
            (SockState::from_name(parts[5]), parts[6])
        } else {
            let state = if proto == Proto::Udp {
                SockState::Close
            } else {
                SockState::Listen
            };
            (state, parts[5])
        };
        let Some(local_ep) = parse_endpoint(local, family) else {
            continue;
        };
        let remote_ep = parse_endpoint(foreign, family).unwrap_or((unspecified(family), 0));
        let mut sock = SocketRec::new(
            proto,
            family,
            state,
            local_ep.0,
            local_ep.1,
            remote_ep.0,
            remote_ep.1,
        );
        if let Some(pid) = pid_field.split('/').next().and_then(|p| p.parse().ok()) {
            if pid != 0 {
                sock.pids.push(pid);
            }
        }
        out.push(sock);
    }
    out
}

fn looks_like_state(token: &str) -> bool {
    let upper = token.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "LISTEN"
            | "ESTABLISHED"
            | "ESTAB"
            | "TIME_WAIT"
            | "TIME-WAIT"
            | "CLOSE_WAIT"
            | "CLOSE-WAIT"
            | "SYN_SENT"
            | "SYN-SENT"
            | "FIN_WAIT1"
            | "FIN_WAIT2"
            | "CLOSING"
            | "LAST_ACK"
    ) || upper.contains("WAIT")
        || upper.contains("LISTEN")
}

fn pids_from_users(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for (index, part) in text.split("pid=").enumerate() {
        if index == 0 {
            continue;
        }
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = digits.parse::<u32>() {
            if pid != 0 && !out.contains(&pid) {
                out.push(pid);
            }
        }
    }
    out
}

fn split_endpoints(name: &str, family: Family) -> Option<((IpAddr, u16), (IpAddr, u16))> {
    if let Some((local, remote)) = name.split_once("->") {
        let local = parse_endpoint(local, family)?;
        let remote = parse_endpoint(remote, family).unwrap_or((unspecified(family), 0));
        Some((local, remote))
    } else {
        Some((parse_endpoint(name, family)?, (unspecified(family), 0)))
    }
}

/// `/proc/net/udp` and `/proc/net/udp6`. Used when the kernel has no UDP diag.
pub fn parse_proc_net_udp(text: &str, v6: bool) -> Vec<SocketRec> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some(local) = parse_proc_endpoint(cols[1], v6) else {
            continue;
        };
        let remote = parse_proc_endpoint(cols[2], v6)
            .unwrap_or((unspecified(if v6 { Family::V6 } else { Family::V4 }), 0));
        let state = u8::from_str_radix(cols[3], 16).unwrap_or(7);
        let uid = cols[7].parse().unwrap_or(0);
        let inode = cols[9].parse().unwrap_or(0);
        let family = if v6 { Family::V6 } else { Family::V4 };
        let mut sock = SocketRec::new(
            Proto::Udp,
            family,
            SockState::from_kernel(state),
            local.0,
            local.1,
            remote.0,
            remote.1,
        );
        sock.uid = uid;
        sock.inode = inode;
        out.push(sock);
    }
    out
}

fn parse_proc_endpoint(text: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let (addr, port_hex) = text.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if v6 {
        IpAddr::V6(parse_proc_ipv6(addr)?)
    } else {
        IpAddr::V4(parse_proc_ipv4(addr)?)
    };
    Some((ip, port))
}

fn parse_proc_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let mut raw = [0u8; 4];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    // The proc file stores the address little-endian.
    Some(Ipv4Addr::new(raw[3], raw[2], raw[1], raw[0]))
}

fn parse_proc_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for word in 0..4 {
        let start = word * 8;
        let mut raw = [0u8; 4];
        for (index, byte) in raw.iter_mut().enumerate() {
            let at = start + index * 2;
            *byte = u8::from_str_radix(&hex[at..at + 2], 16).ok()?;
        }
        out[word * 4] = raw[3];
        out[word * 4 + 1] = raw[2];
        out[word * 4 + 2] = raw[1];
        out[word * 4 + 3] = raw[0];
    }
    Some(Ipv6Addr::from(out))
}

pub fn parse_endpoint(text: &str, family: Family) -> Option<(IpAddr, u16)> {
    let text = text.trim();
    if text.is_empty() || text == "*" || text == "*:*" {
        return Some((unspecified(family), 0));
    }
    if let Some(rest) = text.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        return Some((parse_ip(addr, Family::V6)?, parse_port_star(port)?));
    }
    // netstat prints v6 wildcard as `:::3000`.
    if let Some(port) = text.strip_prefix(":::") {
        return Some((
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            parse_port_star(port).unwrap_or(0),
        ));
    }
    let (host, port) = text.rsplit_once(':')?;
    let port = parse_port_star(port)?;
    if host.is_empty() || host == "*" {
        return Some((unspecified(family), port));
    }
    Some((parse_ip(host, family)?, port))
}

fn parse_port_star(text: &str) -> Option<u16> {
    if text.is_empty() || text == "*" {
        Some(0)
    } else {
        text.parse().ok()
    }
}

fn parse_ip(text: &str, family: Family) -> Option<IpAddr> {
    if text == "*" || text == "0.0.0.0" {
        return Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    if text == "::" || text == "[::]" {
        return Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(ip);
    }
    // `*` already handled. Fall back to the family unspecified address.
    let _ = family;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_info_offsets() {
        let mut buf = vec![0u8; 136];
        buf[68..72].copy_from_slice(&1_500u32.to_ne_bytes());
        buf[100..104].copy_from_slice(&3u32.to_ne_bytes());
        buf[120..128].copy_from_slice(&1_000u64.to_ne_bytes());
        buf[128..136].copy_from_slice(&2_000u64.to_ne_bytes());
        let info = parse_tcp_info(&buf).unwrap();
        assert_eq!(info.rtt_us, 1_500);
        assert_eq!(info.total_retrans, 3);
        assert_eq!(info.bytes_acked, 1_000);
        assert_eq!(info.bytes_received, 2_000);
        assert!(parse_tcp_info(&[0u8; 16]).is_none());
    }

    #[test]
    fn lsof_field_listener() {
        let text = "\
p4242
cnode
PTCP
tIPv4
TST=LISTEN
i99887
n127.0.0.1:3000
PUDP
tIPv4
i111
n127.0.0.1:5353
";
        let socks = parse_lsof_field(text);
        assert_eq!(socks.len(), 2);
        assert_eq!(socks[0].local_port, 3000);
        assert_eq!(socks[0].state, SockState::Listen);
        assert_eq!(socks[0].inode, 99887);
        assert_eq!(socks[0].pids, vec![4242]);
        assert_eq!(socks[1].protocol, Proto::Udp);
        assert_eq!(socks[1].local_port, 5353);
        assert_eq!(socks[1].pids, vec![4242]);
    }

    #[test]
    fn ss_and_netstat_lines() {
        let ss = "LISTEN 0 128 127.0.0.1:3000 0.0.0.0:* users:((\"node\",pid=4242,fd=21))\n\
ESTAB 0 0 127.0.0.1:40000 127.0.0.1:3000 users:((\"curl\",pid=9,fd=3))\n\
UNCONN 0 0 127.0.0.1:5353 0.0.0.0:* users:((\"python\",pid=3,fd=5))\n";
        let socks = parse_ss(ss);
        assert_eq!(socks.len(), 3);
        assert_eq!(socks[0].state, SockState::Listen);
        assert_eq!(socks[0].pids, vec![4242]);
        assert_eq!(socks[1].state, SockState::Established);
        assert_eq!(socks[1].remote_port, 3000);
        assert_eq!(socks[2].protocol, Proto::Udp);

        let netstat = "\
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      4242/node
tcp6       0      0 :::3000                 :::*                    LISTEN      4242/node
udp        0      0 0.0.0.0:68              0.0.0.0:*                           999/dhclient
";
        let socks = parse_netstat(netstat);
        assert_eq!(socks.len(), 3);
        assert_eq!(socks[0].local_port, 3000);
        assert_eq!(socks[0].state, SockState::Listen);
        assert_eq!(socks[1].family, Family::V6);
        assert_eq!(socks[1].local_port, 3000);
        assert!(socks[1].local_addr.is_unspecified());
        assert_eq!(socks[2].protocol, Proto::Udp);
        assert_eq!(socks[2].pids, vec![999]);
    }

    #[test]
    fn proc_net_udp_line() {
        let text = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 5938: 0100007F:973B 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 21934 2 0000000048d44c25 0
";
        let socks = parse_proc_net_udp(text, false);
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(socks[0].local_port, 0x973B);
        assert_eq!(socks[0].remote_port, 0);
        assert_eq!(socks[0].state, SockState::Close);
        assert_eq!(socks[0].uid, 1000);
        assert_eq!(socks[0].inode, 21934);
        assert_eq!(socks[0].protocol, Proto::Udp);
    }
}
