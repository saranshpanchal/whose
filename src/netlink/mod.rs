mod fallback;
#[cfg(target_os = "linux")]
mod linux;
mod parse;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::Result;
use crate::model::SocketRec;

static FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

pub fn list_sockets() -> Result<(Vec<SocketRec>, String)> {
    #[cfg(target_os = "linux")]
    {
        match linux::dump_sockets() {
            Ok(sockets) => return Ok((merge_sockets(sockets), "sock_diag".to_string())),
            Err(err) => {
                if !FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "whose: NETLINK_SOCK_DIAG failed ({err}); falling back to lsof/ss/netstat"
                    );
                }
            }
        }
    }
    let sockets = fallback::from_commands()?;
    Ok((merge_sockets(sockets), "fallback".to_string()))
}

/// Collapse the IPv4 and IPv6 views of one dual-stack socket (same inode).
pub fn merge_sockets(sockets: Vec<SocketRec>) -> Vec<SocketRec> {
    let mut by_inode: HashMap<u64, SocketRec> = HashMap::new();
    let mut solo = Vec::new();
    for sock in sockets {
        if sock.inode == 0 {
            solo.push(sock);
            continue;
        }
        match by_inode.remove(&sock.inode) {
            None => {
                by_inode.insert(sock.inode, sock);
            }
            Some(prev) => {
                by_inode.insert(sock.inode, merge_pair(prev, sock));
            }
        }
    }
    let mut out: Vec<SocketRec> = by_inode.into_values().collect();
    out.extend(solo);
    out.sort_by(|a, b| {
        (a.local_port, proto_key(a), a.inode, a.remote_port).cmp(&(
            b.local_port,
            proto_key(b),
            b.inode,
            b.remote_port,
        ))
    });
    out
}

fn proto_key(sock: &SocketRec) -> u8 {
    match sock.protocol {
        crate::model::Proto::Tcp => 0,
        crate::model::Proto::Udp => 1,
    }
}

fn merge_pair(mut left: SocketRec, right: SocketRec) -> SocketRec {
    for pid in right.pids {
        if !left.pids.contains(&pid) {
            left.pids.push(pid);
        }
    }
    if left.tcp.is_none() {
        left.tcp = right.tcp;
    }
    if left.v6only.is_none() {
        left.v6only = right.v6only;
    }
    if left.family != right.family {
        left.seen_both_families = true;
        left.v6only = Some(false);
        if right.family == crate::model::Family::V6 && right.local_addr.is_unspecified() {
            left.family = right.family;
            left.local_addr = right.local_addr;
            left.local_port = right.local_port;
        }
    }
    if left.uid == 0 {
        left.uid = right.uid;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Family, Proto, SockState};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn dual_stack_inode_merges_to_one_socket() {
        let mut v4 = SocketRec::new(
            Proto::Tcp,
            Family::V4,
            SockState::Listen,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            3000,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        );
        v4.inode = 42;
        v4.uid = 1000;
        let mut v6 = SocketRec::new(
            Proto::Tcp,
            Family::V6,
            SockState::Listen,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            3000,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            0,
        );
        v6.inode = 42;
        v6.uid = 1000;
        let merged = merge_sockets(vec![v4, v6]);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].seen_both_families);
        assert_eq!(merged[0].v6only, Some(false));
        assert_eq!(merged[0].family, Family::V6);
        assert!(crate::model::exposure_of(&merged[0]) == crate::model::Exposure::DualStack);
    }
}
