use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::time::Duration;

use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST,
};
use netlink_packet_sock_diag::{
    constants::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP},
    inet::{nlas::Nla, ExtensionFlags, InetRequest, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

use super::parse::parse_tcp_info;
use crate::error::{Error, Result};
use crate::model::{Family, Proto, SockState, SocketRec};

pub fn dump_sockets() -> Result<Vec<SocketRec>> {
    let mut last = Error::new("sock_diag dump produced no result");
    for _ in 0..3 {
        match dump_once() {
            Ok(Dump::Done(sockets)) => return Ok(sockets),
            Ok(Dump::Interrupted) => {
                last = Error::new("sock_diag dump interrupted by a socket table change");
            }
            Err(err) => return Err(err),
        }
    }
    Err(last)
}

enum Dump {
    Done(Vec<SocketRec>),
    Interrupted,
}

fn dump_once() -> Result<Dump> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)
        .map_err(|err| Error::new(format!("open NETLINK_SOCK_DIAG: {err}")))?;
    socket
        .bind_auto()
        .map_err(|err| Error::new(format!("bind netlink: {err}")))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|err| Error::new(format!("connect netlink: {err}")))?;
    let _ = socket.set_rx_buf_sz(1 << 20);
    set_recv_timeout(socket.as_raw_fd(), Duration::from_secs(2));

    let queries = [
        (AF_INET, IPPROTO_TCP, Proto::Tcp, Family::V4),
        (AF_INET, IPPROTO_UDP, Proto::Udp, Family::V4),
        (AF_INET6, IPPROTO_TCP, Proto::Tcp, Family::V6),
        (AF_INET6, IPPROTO_UDP, Proto::Udp, Family::V6),
    ];
    let mut all = Vec::new();
    for (index, (family, protocol, proto, fam)) in queries.iter().copied().enumerate() {
        let (rows, interrupted) =
            dump_query(&socket, family, protocol, proto, fam, (index as u32) + 1)?;
        all.extend(rows);
        if interrupted {
            return Ok(Dump::Interrupted);
        }
    }
    // Some kernels ship CONFIG_INET_TCP_DIAG without CONFIG_INET_UDP_DIAG.
    // UDP has no tcp_info; /proc/net/udp still exposes address, state, uid, inode.
    if let Ok(text) = std::fs::read_to_string("/proc/net/udp") {
        all.extend(super::parse::parse_proc_net_udp(&text, false));
    }
    if let Ok(text) = std::fs::read_to_string("/proc/net/udp6") {
        all.extend(super::parse::parse_proc_net_udp(&text, true));
    }
    Ok(Dump::Done(all))
}

fn dump_query(
    socket: &Socket,
    family: u8,
    protocol: u8,
    proto: Proto,
    fam: Family,
    sequence: u32,
) -> Result<(Vec<SocketRec>, bool)> {
    let socket_id = if fam == Family::V6 {
        SocketId::new_v6()
    } else {
        SocketId::new_v4()
    };
    let request = InetRequest {
        family,
        protocol,
        extensions: ExtensionFlags::INFO,
        states: StateFlags::all(),
        socket_id,
    };
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    header.sequence_number = sequence;
    let mut packet = NetlinkMessage::new(header, SockDiagMessage::InetRequest(request).into());
    packet.finalize();
    let mut buf = vec![0u8; packet.buffer_len()];
    packet.serialize(&mut buf[..]);
    socket
        .send(&buf[..], 0)
        .map_err(|err| Error::new(format!("send sock_diag: {err}")))?;

    let mut recv_buf = vec![0u8; 256 * 1024];
    let mut rows = Vec::new();
    let mut interrupted = false;
    loop {
        let size = match socket.recv(&mut &mut recv_buf[..], 0) {
            Ok(size) => size,
            Err(err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut =>
            {
                if rows.is_empty() {
                    return Err(Error::new(format!(
                        "timed out waiting for sock_diag {proto:?}/{fam:?}: {err}"
                    )));
                }
                break;
            }
            Err(err) if err.raw_os_error() == Some(libc::EINTR) => continue,
            Err(err) => return Err(Error::new(format!("recv sock_diag: {err}"))),
        };
        if size == 0 {
            break;
        }
        let mut offset = 0usize;
        let mut saw_done = false;
        while offset + 16 <= size {
            let message = NetlinkMessage::<SockDiagMessage>::deserialize(&recv_buf[offset..size])
                .map_err(|err| Error::new(format!("decode sock_diag: {err}")))?;
            let len = message.header.length as usize;
            if len < 16 {
                break;
            }
            if message.header.flags & NLM_F_DUMP_INTR != 0 {
                interrupted = true;
            }
            match message.payload {
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    rows.push(convert(&response, proto, fam));
                }
                NetlinkPayload::Done(_) => saw_done = true,
                NetlinkPayload::Error(error) => {
                    if let Some(code) = error.code {
                        return Err(Error::new(format!(
                            "sock_diag error {code} for {proto:?}/{fam:?}"
                        )));
                    }
                }
                NetlinkPayload::Noop | NetlinkPayload::Overrun(_) => {}
                NetlinkPayload::InnerMessage(_) => {}
                _ => {}
            }
            offset += align(len);
            if offset > size {
                break;
            }
        }
        if saw_done {
            break;
        }
    }
    Ok((rows, interrupted))
}

fn convert(
    response: &netlink_packet_sock_diag::inet::InetResponse,
    proto: Proto,
    fallback_family: Family,
) -> SocketRec {
    let header = &response.header;
    let family = if header.family == AF_INET6 {
        Family::V6
    } else if header.family == AF_INET {
        Family::V4
    } else {
        fallback_family
    };
    let id = &header.socket_id;
    let mut tcp = None;
    let mut v6only = None;
    for nla in &response.nlas {
        match nla {
            Nla::TcpInfo(bytes) => tcp = parse_tcp_info(bytes),
            Nla::SkV6Only(value) => v6only = Some(*value),
            _ => {}
        }
    }
    let mut sock = SocketRec::new(
        proto,
        family,
        SockState::from_kernel(header.state),
        id.source_address,
        id.source_port,
        id.destination_address,
        id.destination_port,
    );
    sock.uid = header.uid;
    sock.inode = u64::from(header.inode);
    sock.v6only = v6only;
    sock.tcp = tcp;
    let _ = proto;
    sock
}

fn align(len: usize) -> usize {
    (len + 3) & !3
}

fn set_recv_timeout(fd: std::os::fd::RawFd, timeout: Duration) {
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeval as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}
