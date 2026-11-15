#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use whose::{outbound_report, OutboundFilter, QueryOpts};

#[test]
fn established_socket_exposes_tcp_info() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 128];
        let _ = sock.read(&mut buf);
        thread::sleep(Duration::from_secs(3));
    });
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.set_nodelay(true).unwrap();
    client
        .write_all(b"hello whose outbound tcp_info payload")
        .unwrap();
    client.flush().unwrap();

    let opts = QueryOpts {
        show_secrets: false,
    };
    let filter = OutboundFilter {
        pid: Some(std::process::id()),
        process: None,
        include_inbound: false,
    };
    let mut saw = false;
    let mut detail = String::new();
    for _ in 0..30 {
        let report = outbound_report(&filter, &opts).unwrap();
        for group in &report.groups {
            for flow in &group.sockets {
                let touches = flow.local.ends_with(&format!(":{port}"))
                    || flow.remote.ends_with(&format!(":{port}"));
                if !touches || flow.state != "ESTABLISHED" {
                    continue;
                }
                detail = format!("{flow:?}");
                let acked = flow.bytes_acked.unwrap_or(0);
                let received = flow.bytes_received.unwrap_or(0);
                if flow.rtt_us.is_some() && acked + received > 0 {
                    saw = true;
                    break;
                }
            }
        }
        if saw {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        saw,
        "expected ESTABLISHED tcp_info with bytes on :{port}, last {detail}"
    );
    let report = outbound_report(&filter, &opts).unwrap();
    let accepted = report
        .groups
        .iter()
        .flat_map(|group| &group.sockets)
        .any(|flow| flow.local.ends_with(&format!(":{port}")) && flow.state == "ESTABLISHED");
    assert!(
        !accepted,
        "accepted socket on the listen port should be omitted by default"
    );
    let mut with_inbound = filter.clone();
    with_inbound.include_inbound = true;
    let report = outbound_report(&with_inbound, &opts).unwrap();
    let accepted = report
        .groups
        .iter()
        .flat_map(|group| &group.sockets)
        .any(|flow| {
            flow.local.ends_with(&format!(":{port}"))
                && flow.state == "ESTABLISHED"
                && flow.direction == "inbound"
        });
    assert!(accepted, "include_inbound should show the accepted socket");
    drop(client);
    let _ = server.join();
}
