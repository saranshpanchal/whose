#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::Value;

#[test]
fn stdio_jsonrpc_whose_port_and_list() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_whose"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut send = |message: &str| {
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    };
    send(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
    );
    send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    send(&format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"whose_port","arguments":{{"port":{port}}}}}}}"#
    ));
    send(
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"whose_list_ports","arguments":{}}}"#,
    );

    let mut replies = Vec::new();
    for _ in 0..4 {
        replies.push(
            rx.recv_timeout(Duration::from_secs(10))
                .expect("timed out waiting for MCP reply"),
        );
    }
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();

    let init: Value = serde_json::from_str(replies[0].trim()).unwrap();
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "whose");

    let listed: Value = serde_json::from_str(replies[1].trim()).unwrap();
    assert_eq!(listed["id"], 2);
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(names.contains(&"whose_port"));
    assert!(names.contains(&"whose_list_ports"));

    let called: Value = serde_json::from_str(replies[2].trim()).unwrap();
    assert_eq!(called["id"], 3);
    assert_eq!(called["result"]["isError"], false);
    let text = called["result"]["content"][0]["text"].as_str().unwrap();
    let body: Value = serde_json::from_str(text).unwrap();
    let hit = body["ports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["port"] == port && item["protocol"] == "tcp")
        .unwrap_or_else(|| panic!("port {port} missing from {text}"));
    let pid = std::process::id();
    assert!(hit["owners"]
        .as_array()
        .unwrap()
        .iter()
        .any(|owner| owner["pid"] == pid));

    let listed_ports: Value = serde_json::from_str(replies[3].trim()).unwrap();
    assert_eq!(listed_ports["id"], 4);
    let text = listed_ports["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let body: Value = serde_json::from_str(text).unwrap();
    assert!(body.get("groups").is_some());
    let _keep = listener;
}

#[test]
fn free_port_without_yes_does_not_signal() {
    let script = r#"
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(8)
print(s.getsockname()[1], flush=True)
while True:
    time.sleep(3600)
"#;
    let mut server = Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(server.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let port: u16 = line.trim().parse().unwrap();

    let mut mcp = Command::new(env!("CARGO_BIN_EXE_whose"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = mcp.stdin.take().unwrap();
    let stdout = mcp.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-11-25","capabilities":{{}},"clientInfo":{{"name":"test","version":"0"}}}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"whose_free_port","arguments":{{"port":{port}}}}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();
    let _init = rx.recv_timeout(Duration::from_secs(8)).unwrap();
    let reply = rx.recv_timeout(Duration::from_secs(8)).unwrap();
    let reply: Value = serde_json::from_str(reply.trim()).unwrap();
    assert_eq!(reply["result"]["isError"], false);
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    let body: Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["executed"], false, "{text}");
    assert_eq!(body["dry_run"], true, "{text}");
    assert!(
        body["message"].as_str().unwrap_or("").contains("yes"),
        "{text}"
    );
    assert!(
        TcpListener::bind(("127.0.0.1", port)).is_err(),
        "port was freed without yes"
    );
    let _ = server.kill();
    let _ = server.wait();
    drop(stdin);
    let _ = mcp.kill();
    let _ = mcp.wait();
}
