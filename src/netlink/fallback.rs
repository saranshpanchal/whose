use std::process::Command;
use std::time::Duration;

use super::parse::{parse_lsof_field, parse_netstat, parse_ss};
use crate::error::{Error, Result};
use crate::model::SocketRec;

/// macOS and any host where `NETLINK_SOCK_DIAG` is unavailable.
/// Prefers `lsof -F`, then `ss`, then `netstat`. There is no `tcp_info`.
pub fn from_commands() -> Result<Vec<SocketRec>> {
    if let Some(text) = run("lsof", &["-n", "-P", "-F", "pcPTtin", "-iTCP", "-iUDP"]) {
        let sockets = parse_lsof_field(&text);
        if !sockets.is_empty() || text.contains('\n') {
            return Ok(sockets);
        }
    }
    if let Some(text) = run("ss", &["-H", "-tuanp"]) {
        return Ok(parse_ss(&text));
    }
    if let Some(text) = run("netstat", &["-an", "-p", "tcp"]) {
        // BSD netstat and Linux netstat differ. Try the Linux form next if this
        // produced nothing useful.
        let parsed = parse_netstat(&text);
        if !parsed.is_empty() {
            return Ok(parsed);
        }
    }
    if let Some(text) = run("netstat", &["-lntup"]) {
        return Ok(parse_netstat(&text));
    }
    Err(Error::new(
        "no socket source: sock_diag failed and lsof/ss/netstat were unavailable",
    ))
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let finished = wait_timeout(&mut child, Duration::from_secs(3));
    match finished {
        Some(Ok(status)) if status.success() => {
            let mut output = String::new();
            if let Some(mut stdout) = child.stdout.take() {
                use std::io::Read;
                let _ = stdout.read_to_string(&mut output);
            }
            Some(output)
        }
        Some(_) => None,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

fn wait_timeout(
    child: &mut std::process::Child,
    limit: Duration,
) -> Option<std::io::Result<std::process::ExitStatus>> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(Ok(status)),
            Ok(None) if start.elapsed() >= limit => return None,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(err) => return Some(Err(err)),
        }
    }
}
