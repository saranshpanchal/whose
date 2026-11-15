#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use whose::{free_port, parse_port_spec, KillOpts};

const SCRIPT: &str = r#"
import os, socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(8)
port = s.getsockname()[1]
pid = os.fork()
if pid == 0:
    try:
        import sys
        sys.stdout.close()
    except Exception:
        pass
    while True:
        time.sleep(3600)
else:
    print(f"ready {port} {os.getpid()} {pid}", flush=True)
    while True:
        time.sleep(3600)
"#;

#[test]
fn kill_frees_parent_and_child_process_group() {
    let mut command = Command::new("python3");
    command
        .arg("-c")
        .arg(SCRIPT)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.process_group(0);
    let mut child = command.spawn().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    assert_eq!(parts.next(), Some("ready"), "{line}");
    let port: u16 = parts.next().unwrap().parse().unwrap();
    let parent: u32 = parts.next().unwrap().parse().unwrap();
    let kid: u32 = parts.next().unwrap().parse().unwrap();

    let report = free_port(
        parse_port_spec(&port.to_string()).unwrap(),
        KillOpts {
            yes: true,
            force: false,
            grace_ms: 2000,
            interactive: false,
        },
    )
    .unwrap();
    assert!(
        report.executed,
        "expected a signal, got {}",
        serde_json::to_string(&report).unwrap()
    );
    assert!(
        report.freed,
        "port still busy: {}",
        serde_json::to_string(&report).unwrap()
    );

    let mut kid_stopped = false;
    for _ in 0..20 {
        match proc_state(kid) {
            None | Some('Z') => {
                kid_stopped = true;
                break;
            }
            _ => thread::sleep(Duration::from_millis(50)),
        }
    }
    assert!(
        kid_stopped,
        "child {kid} still running ({:?})",
        proc_state(kid)
    );

    let status = child.wait().unwrap();
    assert!(!status.success() || proc_state(parent).is_none());
    assert!(
        proc_state(parent).is_none(),
        "parent {parent} still visible as {:?}",
        proc_state(parent)
    );

    let mut rebound = false;
    for _ in 0..20 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            rebound = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(rebound, "could not bind :{port} after free");
}

fn proc_state(pid: u32) -> Option<char> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = text.rfind(')')?;
    text[end + 1..].split_whitespace().next()?.chars().next()
}
