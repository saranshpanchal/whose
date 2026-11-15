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
    drop(client);
    let _ = server.join();
}
