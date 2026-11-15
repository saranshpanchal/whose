use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;

use crate::model::{
    is_listener, is_outbound_state, is_wildcard_ip, unknown_owner_group, FlowReport,
    OutboundFilter, OutboundGroup, OwnerReport, SockState, SocketRec, TcpInfoOut,
};

/// Close-wait sockets at or above this count are reported as a leak warning.
pub const CLOSE_WAIT_FLAG: usize = 5;

pub struct ListenIndex {
    pub by_pid: HashMap<u32, HashSet<u16>>,
    pub any: HashSet<u16>,
    pub ephemeral: (u16, u16),
}

impl ListenIndex {
    pub fn from_sockets(sockets: &[SocketRec]) -> Self {
        let mut by_pid: HashMap<u32, HashSet<u16>> = HashMap::new();
        let mut any = HashSet::new();
        for sock in sockets {
            if !is_listener(sock) {
                continue;
            }
            any.insert(sock.local_port);
            for pid in &sock.pids {
                by_pid.entry(*pid).or_default().insert(sock.local_port);
            }
        }
        Self {
            by_pid,
            any,
            ephemeral: ephemeral_range(),
        }
    }
}

pub fn assemble(
    sockets: &[SocketRec],
    owners: &BTreeMap<u32, OwnerReport>,
    filter: &OutboundFilter,
    listens: &ListenIndex,
) -> OutboundGroupSet {
    let mut groups: BTreeMap<String, OutboundGroup> = BTreeMap::new();
    for sock in sockets {
        if !is_outbound_state(sock.state) {
            continue;
        }
        let inbound = is_inbound(sock, listens);
        if inbound && !filter.include_inbound {
            continue;
        }
        if !socket_matches(sock, owners, filter) {
            continue;
        }
        let flow = flow_report(sock, inbound);
        if sock.pids.is_empty() {
            let key = unknown_owner_group(sock.uid);
            let group = groups.entry(key.clone()).or_insert_with(|| OutboundGroup {
                pid: None,
                uid: sock.uid,
                comm: String::new(),
                cmdline: key,
                repo: None,
                worktree: None,
                branch: None,
                close_wait: 0,
                sockets: Vec::new(),
            });
            if sock.state == SockState::CloseWait {
                group.close_wait += 1;
            }
            group.sockets.push(flow);
            continue;
        }
        for pid in &sock.pids {
            let owner = owners.get(pid);
            if !owner_matches(owner, filter) {
                continue;
            }
            let key = format!("pid:{pid}");
            let group = groups
                .entry(key)
                .or_insert_with(|| group_from_owner(*pid, sock.uid, owner));
            if sock.state == SockState::CloseWait {
                group.close_wait += 1;
            }
            group.sockets.push(flow.clone());
        }
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by(|a, b| a.cmdline.cmp(&b.cmdline).then(a.pid.cmp(&b.pid)));
    let mut warnings = warnings_for(&groups);
    warnings.extend(wildcard_warnings(sockets, owners, filter));
    OutboundGroupSet { groups, warnings }
}

pub struct OutboundGroupSet {
    pub groups: Vec<OutboundGroup>,
    pub warnings: Vec<String>,
}

fn socket_matches(
    sock: &SocketRec,
    owners: &BTreeMap<u32, OwnerReport>,
    filter: &OutboundFilter,
) -> bool {
    if let Some(pid) = filter.pid {
        if !sock.pids.contains(&pid) {
            return false;
        }
    }
    if filter.process.is_none() {
        return true;
    }
    if sock.pids.is_empty() {
        return false;
    }
    sock.pids
        .iter()
        .any(|pid| owner_matches(owners.get(pid), filter))
}

fn owner_matches(owner: Option<&OwnerReport>, filter: &OutboundFilter) -> bool {
    let Some(needle) = filter.process.as_deref() else {
        return true;
    };
    let Some(owner) = owner else {
        return false;
    };
    let needle = needle.to_ascii_lowercase();
    owner.comm.to_ascii_lowercase().contains(&needle)
        || owner.cmdline.to_ascii_lowercase().contains(&needle)
}

fn group_from_owner(pid: u32, uid: u32, owner: Option<&OwnerReport>) -> OutboundGroup {
    match owner {
        Some(owner) => OutboundGroup {
            pid: Some(pid),
            uid: owner.uid,
            comm: owner.comm.clone(),
            cmdline: owner.cmdline.clone(),
            repo: owner.git.as_ref().map(|g| g.repo_name.clone()),
            worktree: owner.git.as_ref().map(|g| g.worktree.clone()),
            branch: owner.git.as_ref().map(|g| g.branch.clone()),
            close_wait: 0,
            sockets: Vec::new(),
        },
        None => OutboundGroup {
            pid: Some(pid),
            uid,
            comm: String::new(),
            cmdline: format!("pid {pid}"),
            repo: None,
            worktree: None,
            branch: None,
            close_wait: 0,
            sockets: Vec::new(),
        },
    }
}

pub(crate) fn is_inbound(sock: &SocketRec, listens: &ListenIndex) -> bool {
    if sock.pids.is_empty() {
        return listens.any.contains(&sock.local_port);
    }
    let same_process = sock.pids.iter().any(|pid| {
        listens
            .by_pid
            .get(pid)
            .is_some_and(|ports| ports.contains(&sock.local_port))
    });
    if same_process {
        return true;
    }
    let (start, end) = listens.ephemeral;
    let ephemeral = sock.local_port >= start && sock.local_port <= end;
    !ephemeral && listens.any.contains(&sock.local_port)
}

fn ephemeral_range() -> (u16, u16) {
    let Ok(text) = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") else {
        return (32768, 60999);
    };
    let mut parts = text.split_whitespace();
    let start = parts
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(32768);
    let end = parts
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(60999);
    (start, end)
}

fn flow_report(sock: &SocketRec, inbound: bool) -> FlowReport {
    let tcp = sock.tcp.as_ref().map(TcpInfoOut::from);
    FlowReport {
        protocol: sock.protocol.as_str().to_string(),
        state: sock.state.as_str().to_string(),
        direction: if inbound {
            "inbound".to_string()
        } else {
            "outbound".to_string()
        },
        local: crate::model::format_addr(sock.local_addr, sock.local_port),
        remote: crate::model::format_addr(sock.remote_addr, sock.remote_port),
        uid: sock.uid,
        inode: sock.inode,
        rtt_us: tcp.as_ref().map(|t| t.rtt_us),
        rtt_ms: tcp.as_ref().map(|t| t.rtt_ms),
        total_retrans: tcp.as_ref().map(|t| t.total_retrans),
        bytes_acked: tcp.as_ref().map(|t| t.bytes_acked),
        bytes_received: tcp.as_ref().map(|t| t.bytes_received),
    }
}

fn warnings_for(groups: &[OutboundGroup]) -> Vec<String> {
    groups
        .iter()
        .filter(|group| group.close_wait >= CLOSE_WAIT_FLAG)
        .map(|group| {
            format!(
                "{}: {} CLOSE_WAIT sockets (possible leaked connections)",
                group.cmdline, group.close_wait
            )
        })
        .collect()
}

fn wildcard_warnings(
    sockets: &[SocketRec],
    owners: &BTreeMap<u32, OwnerReport>,
    filter: &OutboundFilter,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for sock in sockets {
        if !is_listener(sock) || !is_wildcard_ip(sock.local_addr) {
            continue;
        }
        if filter.pid.is_some() && !sock.pids.iter().any(|pid| filter.pid == Some(*pid)) {
            continue;
        }
        if let Some(needle) = filter.process.as_deref() {
            let matched = sock.pids.iter().any(|pid| {
                owners.get(pid).is_some_and(|owner| {
                    owner
                        .comm
                        .to_ascii_lowercase()
                        .contains(&needle.to_ascii_lowercase())
                        || owner
                            .cmdline
                            .to_ascii_lowercase()
                            .contains(&needle.to_ascii_lowercase())
                })
            });
            if !matched {
                continue;
            }
        }
        let local = crate::model::format_addr(sock.local_addr, sock.local_port);
        let who = if sock.pids.is_empty() {
            format!("uid {}", sock.uid)
        } else {
            sock.pids
                .iter()
                .map(|pid| {
                    owners
                        .get(pid)
                        .map(|o| format!("{pid} {}", o.comm))
                        .unwrap_or_else(|| pid.to_string())
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        warnings.push(format!(
            "{local} {} LISTEN {who} (0.0.0.0 / wildcard bind)",
            sock.protocol.as_str()
        ));
    }
    warnings
}
