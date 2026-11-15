#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use whose::{inspect_ports, parse_port_spec, QueryOpts};

#[test]
fn dashboard_binds_loopback_and_serves_json() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut child = Command::new(env!("CARGO_BIN_EXE_whose"))
        .args(["serve", "--port", &port.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut connected = false;
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            connected = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(connected, "dashboard did not accept connections");

    let page = http_get(port, "/");
    assert!(page.contains("200"));
    assert!(page.contains("whose"));
    let api = http_get(port, "/api/ports");
    assert!(api.contains("200"));
    assert!(api.contains("groups"));
    let topo = http_get(port, "/api/topology");
    assert!(topo.contains("projects"));

    let report = inspect_ports(
        parse_port_spec(&port.to_string()).unwrap(),
        &QueryOpts {
            show_secrets: false,
        },
    )
    .unwrap();
    assert!(report.ports.iter().any(|item| {
        item.port == port && item.local.starts_with("127.0.0.1:") && item.exposure == "loopback"
    }));

    let _ = child.kill();
    let _ = child.wait();
}

fn http_get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut body = String::new();
    let _ = stream.read_to_string(&mut body);
    body
}
