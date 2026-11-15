use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::error::{Error, Result};

/// Inclusive local-port query (`3000`, `:3000`, `3000-3010`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSpec {
    pub start: u16,
    pub end: u16,
}

impl PortSpec {
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    pub fn ports(self) -> impl Iterator<Item = u16> {
        self.start..=self.end
    }
}

pub fn parse_port_spec(raw: &str) -> Result<PortSpec> {
    let text = raw.trim();
    if text.is_empty() {
        return Err(Error::new("empty port"));
    }
    let text = text.strip_prefix(':').unwrap_or(text);
    // Allow `127.0.0.1:3000` by keeping the final numeric field.
    let text = if let Some((host, port)) = text.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit())
            && (host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('['))
        {
            port
        } else {
            text
        }
    } else {
        text
    };
    if let Some((left, right)) = text.split_once('-') {
        let start = parse_port_token(left)?;
        let end = parse_port_token(right)?;
        if end < start {
            return Err(Error::new(format!("port range {start}-{end} is reversed")));
        }
        return Ok(PortSpec { start, end });
    }
    Ok(PortSpec::single(parse_port_token(text)?))
}

fn parse_port_token(text: &str) -> Result<u16> {
    let text = text.trim().strip_prefix(':').unwrap_or(text.trim());
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::new(format!("not a port: {text}")));
    }
    let port: u16 = text
        .parse()
        .map_err(|_| Error::new(format!("port out of range: {text}")))?;
    if port == 0 {
        return Err(Error::new("port 0 is not a bindable service port"));
    }
    Ok(port)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// Kernel `TCP_*` state. UDP unconnected sockets surface as `Close`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Other(u8),
}

impl SockState {
    pub fn from_kernel(value: u8) -> Self {
        match value {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            other => Self::Other(other),
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_uppercase().as_str() {
            "ESTABLISHED" | "ESTAB" => Self::Established,
            "SYN_SENT" | "SYN-SENT" => Self::SynSent,
            "SYN_RECV" | "SYN-RECV" => Self::SynRecv,
            "FIN_WAIT1" | "FIN-WAIT-1" | "FIN_WAIT_1" => Self::FinWait1,
            "FIN_WAIT2" | "FIN-WAIT-2" | "FIN_WAIT_2" => Self::FinWait2,
            "TIME_WAIT" | "TIME-WAIT" => Self::TimeWait,
            "CLOSE" | "CLOSED" | "UNCONN" => Self::Close,
            "CLOSE_WAIT" | "CLOSE-WAIT" => Self::CloseWait,
            "LAST_ACK" | "LAST-ACK" => Self::LastAck,
            "LISTEN" | "LISTENING" => Self::Listen,
            "CLOSING" => Self::Closing,
            _ => Self::Other(0),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Established => "ESTABLISHED",
            Self::SynSent => "SYN_SENT",
            Self::SynRecv => "SYN_RECV",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::TimeWait => "TIME_WAIT",
            Self::Close => "CLOSE",
            Self::CloseWait => "CLOSE_WAIT",
            Self::LastAck => "LAST_ACK",
            Self::Listen => "LISTEN",
            Self::Closing => "CLOSING",
            Self::Other(_) => "OTHER",
        }
    }
}

/// How a bound address is exposed on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    Loopback,
    Wildcard,
    DualStack,
    Specific,
}

impl Exposure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Wildcard => "wildcard",
            Self::DualStack => "dual-stack",
            Self::Specific => "specific",
        }
    }
}

/// Fields we keep from `struct tcp_info` (`INET_DIAG_INFO`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpStats {
    pub rtt_us: u32,
    pub total_retrans: u32,
    pub bytes_acked: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpInfoOut {
    pub rtt_us: u32,
    pub rtt_ms: f64,
    pub total_retrans: u32,
    pub bytes_acked: u64,
    pub bytes_received: u64,
}

impl From<&TcpStats> for TcpInfoOut {
    fn from(value: &TcpStats) -> Self {
        Self {
            rtt_us: value.rtt_us,
            rtt_ms: f64::from(value.rtt_us) / 1000.0,
            total_retrans: value.total_retrans,
            bytes_acked: value.bytes_acked,
            bytes_received: value.bytes_received,
        }
    }
}

/// One inet/inet6 socket after diag and `/proc` inode join.
#[derive(Debug, Clone)]
pub struct SocketRec {
    pub protocol: Proto,
    pub family: Family,
    pub state: SockState,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub uid: u32,
    pub inode: u64,
    pub v6only: Option<bool>,
    /// Same inode was returned by both the IPv4 and IPv6 dumps.
    pub seen_both_families: bool,
    pub tcp: Option<TcpStats>,
    pub pids: Vec<u32>,
}

impl SocketRec {
    pub fn new(
        protocol: Proto,
        family: Family,
        state: SockState,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
    ) -> Self {
        Self {
            protocol,
            family,
            state,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            uid: 0,
            inode: 0,
            v6only: None,
            seen_both_families: false,
            tcp: None,
            pids: Vec::new(),
        }
    }
}

pub fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        // Only IPv4-mapped addresses (`::ffff:a.b.c.d`) collapse to IPv4.
        // `::1` is an IPv4-compatible address in the old sense and must stay
        // `[::1]`, which is loopback. `to_ipv4()` would turn it into `0.0.0.1`.
        IpAddr::V6(v6) => mapped_ipv4(v6).map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

fn mapped_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = addr.octets();
    if octets[..10].iter().all(|byte| *byte == 0) && octets[10] == 0xff && octets[11] == 0xff {
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

pub const UNKNOWN_OWNER: &str = "unknown (no /proc access)";

pub fn unknown_owner_group(uid: u32) -> String {
    format!("{UNKNOWN_OWNER} uid {uid}")
}

pub fn format_addr(addr: IpAddr, port: u16) -> String {
    match normalize_ip(addr) {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

pub fn exposure_of(sock: &SocketRec) -> Exposure {
    let ip = normalize_ip(sock.local_addr);
    if ip.is_loopback() {
        return Exposure::Loopback;
    }
    if ip.is_unspecified() {
        let dual = matches!(sock.family, Family::V6)
            && (sock.v6only == Some(false) || sock.seen_both_families);
        if dual {
            return Exposure::DualStack;
        }
        return Exposure::Wildcard;
    }
    Exposure::Specific
}

pub fn exposure_warning(exposure: Exposure, local: &str) -> Option<String> {
    match exposure {
        Exposure::Loopback => None,
        Exposure::Wildcard => Some(format!("{local} is bound on all interfaces")),
        Exposure::DualStack => Some(format!("{local} is a dual-stack bind on all interfaces")),
        Exposure::Specific => Some(format!("{local} is not a loopback address")),
    }
}

pub fn is_listener(sock: &SocketRec) -> bool {
    match sock.protocol {
        Proto::Tcp => sock.state == SockState::Listen,
        Proto::Udp => sock.local_port != 0 && sock.remote_port == 0,
    }
}

pub fn is_outbound_state(state: SockState) -> bool {
    matches!(
        state,
        SockState::Established | SockState::SynSent | SockState::CloseWait | SockState::TimeWait
    )
}

pub fn is_wildcard_ip(addr: IpAddr) -> bool {
    normalize_ip(addr).is_unspecified()
}

#[derive(Debug, Clone, Default)]
pub struct QueryOpts {
    pub show_secrets: bool,
}

#[derive(Debug, Clone)]
pub struct KillOpts {
    pub yes: bool,
    pub force: bool,
    pub grace_ms: u64,
    /// When true and stdin is a terminal, prompt before signaling a sensitive daemon.
    pub interactive: bool,
    /// Print the pids that would be signaled and do not signal them.
    pub dry_run: bool,
    /// Do not signal unless `yes` is set. The MCP tool sets this.
    pub require_yes: bool,
    /// Signal the listener and its descendants. This is always the scope; the
    /// flag is accepted so `whose kill --tree` matches the preview.
    pub tree: bool,
}

impl Default for KillOpts {
    fn default() -> Self {
        Self {
            yes: false,
            force: false,
            grace_ms: 2000,
            interactive: false,
            dry_run: false,
            require_yes: false,
            tree: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OutboundFilter {
    pub pid: Option<u32>,
    pub process: Option<String>,
    /// Include accepted sockets whose local port is one this process is listening on.
    pub include_inbound: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EnvPair {
    pub key: String,
    pub value: String,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GitInfo {
    pub repo_name: String,
    pub repo_root: String,
    pub worktree: String,
    pub branch: String,
    pub detached: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SupervisorInfo {
    pub kind: String,
    pub name: String,
    pub stop: String,
    pub detail: String,
    /// When set, `whose kill` will not signal this process unless `--force` is passed.
    pub blocks_kill: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Ancestor {
    pub pid: u32,
    pub comm: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OwnerReport {
    pub pid: u32,
    pub uid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub comm: String,
    pub cmdline: String,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub uptime: String,
    pub uptime_secs: u64,
    pub rss_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    pub ancestry: Vec<Ancestor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<GitInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor: Option<SupervisorInfo>,
    pub env: Vec<EnvPair>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortReport {
    pub protocol: String,
    pub state: String,
    pub local: String,
    pub remote: String,
    pub port: u16,
    pub exposure: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    pub uid: u32,
    pub inode: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v6only: Option<bool>,
    /// `known`, `unknown` (our uid, no `/proc` fd), or `other-uid`.
    pub owner_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpInfoOut>,
    pub owners: Vec<OwnerReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectGroup {
    pub project: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub ports: Vec<PortReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectReport {
    pub socket_source: String,
    pub ports: Vec<PortReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListenReport {
    pub socket_source: String,
    pub groups: Vec<ProjectGroup>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowReport {
    pub protocol: String,
    pub state: String,
    /// `outbound` for connections this process opened, `inbound` for accepted ones.
    pub direction: String,
    pub local: String,
    pub remote: String,
    pub uid: u32,
    pub inode: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_retrans: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_acked: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundGroup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub uid: u32,
    pub comm: String,
    pub cmdline: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub close_wait: usize,
    pub sockets: Vec<FlowReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundReport {
    pub socket_source: String,
    pub groups: Vec<OutboundGroup>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Topology {
    pub socket_source: String,
    pub projects: Vec<ProjectNode>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectNode {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub processes: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessNode {
    pub pid: u32,
    pub cmdline: String,
    pub ancestry: Vec<String>,
    pub uptime: String,
    pub rss_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<String>,
    pub env: Vec<EnvPair>,
    pub listens: Vec<PortBrief>,
    pub outbound: Vec<FlowReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortBrief {
    pub protocol: String,
    pub state: String,
    pub local: String,
    pub port: u16,
    pub exposure: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpInfoOut>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FreeAction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgid: Option<u32>,
    pub cmdline: String,
    /// `signaled`, `escalated`, `refused`, `needs-confirm`, `needs-force`, or `unmapped`.
    pub result: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FreeReport {
    pub ports: Vec<u16>,
    pub executed: bool,
    pub freed: bool,
    pub dry_run: bool,
    /// Exact pids that were signaled, or that a dry-run would signal.
    pub pids: Vec<u32>,
    pub actions: Vec<FreeAction>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct KillTarget {
    pub ports: Vec<u16>,
    pub pid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub uid: u32,
    pub comm: String,
    pub args0: String,
    pub exe: String,
    pub cmdline: String,
    pub supervisor: Option<SupervisorInfo>,
}

#[derive(Debug, Clone)]
pub struct UnmappedListen {
    pub port: u16,
    pub protocol: Proto,
    pub uid: u32,
    pub local: String,
}

/// Parsed identity used by the kill policy. Pure so the rules can be tested
/// without signaling anyone.
#[derive(Debug, Clone)]
pub struct Identity {
    pub pid: u32,
    pub uid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub ancestors: Vec<u32>,
}

pub fn unspecified(family: Family) -> IpAddr {
    match family {
        Family::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Family::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let n = bytes as f64;
    if n < KIB {
        format!("{bytes} B")
    } else if n < KIB * KIB {
        format!("{:.1} KiB", n / KIB)
    } else if n < KIB * KIB * KIB {
        format!("{:.1} MiB", n / KIB / KIB)
    } else {
        format!("{:.1} GiB", n / KIB / KIB / KIB)
    }
}

pub fn format_uptime(secs: u64) -> String {
    humantime::format_duration(std::time::Duration::from_secs(secs)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port_forms() {
        assert_eq!(parse_port_spec("3000").unwrap(), PortSpec::single(3000));
        assert_eq!(parse_port_spec(":3000").unwrap(), PortSpec::single(3000));
        assert_eq!(
            parse_port_spec("3000-3010").unwrap(),
            PortSpec {
                start: 3000,
                end: 3010
            }
        );
        assert_eq!(
            parse_port_spec(":3000-3010").unwrap(),
            PortSpec {
                start: 3000,
                end: 3010
            }
        );
        assert_eq!(
            parse_port_spec("127.0.0.1:3000").unwrap(),
            PortSpec::single(3000)
        );
        assert!(parse_port_spec("0").is_err());
        assert!(parse_port_spec("3010-3000").is_err());
        assert!(parse_port_spec("nope").is_err());
    }

    #[test]
    fn exposure_classifies_binds() {
        let mut sock = SocketRec::new(
            Proto::Tcp,
            Family::V4,
            SockState::Listen,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            3000,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        );
        assert_eq!(exposure_of(&sock), Exposure::Loopback);
        sock.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(exposure_of(&sock), Exposure::Wildcard);
        sock.family = Family::V6;
        sock.local_addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        sock.seen_both_families = true;
        assert_eq!(exposure_of(&sock), Exposure::DualStack);
        sock.seen_both_families = false;
        sock.v6only = Some(true);
        assert_eq!(exposure_of(&sock), Exposure::Wildcard);
    }

    #[test]
    fn ipv6_loopback_is_not_rendered_as_ipv4() {
        let loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(format_addr(loopback, 3000), "[::1]:3000");
        let mut sock = SocketRec::new(
            Proto::Tcp,
            Family::V6,
            SockState::Listen,
            loopback,
            3000,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            0,
        );
        assert_eq!(exposure_of(&sock), Exposure::Loopback);
        assert!(exposure_warning(exposure_of(&sock), &format_addr(loopback, 3000)).is_none());

        let mapped_loop = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        assert_eq!(format_addr(mapped_loop, 80), "127.0.0.1:80");
        sock.local_addr = mapped_loop;
        assert_eq!(exposure_of(&sock), Exposure::Loopback);

        let mapped_public = IpAddr::V6(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped());
        assert_eq!(format_addr(mapped_public, 443), "1.2.3.4:443");
        sock.local_addr = mapped_public;
        assert_eq!(exposure_of(&sock), Exposure::Specific);

        assert_eq!(
            format_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            "127.0.0.1:9"
        );
        assert_eq!(
            unknown_owner_group(1000),
            "unknown (no /proc access) uid 1000"
        );
        assert!(!unknown_owner_group(1000).contains("uid 0"));
    }
}
