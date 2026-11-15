#![cfg(target_os = "linux")]

use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

use whose::{inspect_ports, parse_port_spec, QueryOpts};

#[test]
fn tcp_and_udp_listeners_map_to_this_process() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let udp_port = udp.local_addr().unwrap().port();
    let opts = QueryOpts {
        show_secrets: false,
    };
    let tcp_hit = wait_socket(tcp_port, "tcp", &opts);
    let udp_hit = wait_socket(udp_port, "udp", &opts);
    let pid = std::process::id();
    let cwd = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
    let exe = std::env::args().next().unwrap();
    let inodes = our_socket_inodes();

    assert_eq!(tcp_hit.state, "LISTEN");
    assert_eq!(tcp_hit.exposure, "loopback");
    assert!(tcp_hit.local.starts_with("127.0.0.1:"));
    let owner = tcp_hit
        .owners
        .iter()
        .find(|owner| owner.pid == pid)
        .expect("tcp owner");
    assert_eq!(owner.args.first().map(String::as_str), Some(exe.as_str()));
    assert_eq!(owner.cwd.as_deref(), Some(cwd.to_str().unwrap()));
    assert!(owner.ancestry.iter().any(|item| item.pid == pid));
    assert!(
        inodes.contains(&tcp_hit.inode),
        "tcp inode {} missing from {inodes:?}",
        tcp_hit.inode
    );

    assert_eq!(udp_hit.protocol, "udp");
    assert!(udp_hit.owners.iter().any(|owner| owner.pid == pid));
    assert!(
        inodes.contains(&udp_hit.inode),
        "udp inode {} missing from {inodes:?}",
        udp_hit.inode
    );
}

fn wait_socket(port: u16, protocol: &str, opts: &QueryOpts) -> whose::PortReport {
    let spec = parse_port_spec(&port.to_string()).unwrap();
    let mut last = String::new();
    for _ in 0..20 {
        match inspect_ports(spec, opts) {
            Ok(report) => {
                if let Some(hit) = report
                    .ports
                    .into_iter()
                    .find(|item| item.port == port && item.protocol == protocol)
                {
                    if hit
                        .owners
                        .iter()
                        .any(|owner| owner.pid == std::process::id())
                    {
                        return hit;
                    }
                    last = format!("found {protocol}:{port} without our pid");
                } else {
                    last = format!("no {protocol}:{port} yet, source {}", report.socket_source);
                }
            }
            Err(err) => last = err.to_string(),
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("listener {protocol}:{port} not observed: {last}");
}

fn our_socket_inodes() -> Vec<u64> {
    let mut inodes = Vec::new();
    let Ok(dir) = fs::read_dir("/proc/self/fd") else {
        return inodes;
    };
    for entry in dir.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let Some(text) = target.to_str() else {
            continue;
        };
        if let Some(inode) = text
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|rest| rest.parse().ok())
        {
            inodes.push(inode);
        }
    }
    inodes
}
