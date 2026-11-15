use std::io::{self, IsTerminal, Write};
use std::thread;
use std::time::{Duration, Instant};

use crate::context::is_sensitive_daemon;
use crate::engine;
use crate::error::Result;
use crate::model::{FreeAction, FreeReport, Identity, KillOpts, KillTarget, PortSpec};
use crate::proc::parse_stat;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Assessment {
    hard: Option<String>,
    force: Option<String>,
    confirm: Option<String>,
}

pub fn free_port(spec: PortSpec, mut opts: KillOpts) -> Result<FreeReport> {
    let (targets, unmapped, _source) = engine::listener_targets(spec)?;
    let ports = collect_ports(&targets, &unmapped);
    if targets.is_empty() && unmapped.is_empty() {
        return Ok(FreeReport {
            ports: spec.ports().collect(),
            executed: false,
            freed: true,
            actions: Vec::new(),
            message: format!("no listener on {}", format_spec(spec)),
        });
    }
    let me = current_identity();
    let assessments: Vec<Assessment> = targets.iter().map(|target| assess(target, &me)).collect();
    let needs_confirm = assessments.iter().any(|item| item.confirm.is_some());
    if needs_confirm && !opts.yes && opts.interactive {
        let reason = assessments
            .iter()
            .filter_map(|item| item.confirm.clone())
            .collect::<Vec<_>>()
            .join("; ");
        if prompt_yes(&reason) {
            opts.yes = true;
        }
    }
    let hold_for_confirm = assessments.iter().any(|item| item.confirm.is_some()) && !opts.yes;
    let mut actions = Vec::new();
    let mut signaled: Vec<u32> = Vec::new();
    for (target, assessment) in targets.iter().zip(assessments.iter()) {
        if let Some(reason) = &assessment.hard {
            actions.push(action(target, "refused", reason));
            continue;
        }
        if hold_for_confirm {
            let detail = assessment
                .confirm
                .clone()
                .or_else(|| assessment.force.clone())
                .unwrap_or_else(|| "confirmation required".to_string());
            actions.push(action(target, "needs-confirm", &detail));
            continue;
        }
        if assessment.force.is_some() && !opts.force {
            actions.push(action(
                target,
                "needs-force",
                assessment.force.as_deref().unwrap_or("supervised"),
            ));
            continue;
        }
        match signal_group(target.pgid, libc::SIGTERM) {
            Ok(()) => {
                signaled.push(target.pgid);
                actions.push(action(
                    target,
                    "signaled",
                    "SIGTERM process group; waiting for the port to leave LISTEN",
                ));
            }
            Err(err) => actions.push(action(target, "refused", &err.to_string())),
        }
    }
    for item in &unmapped {
        actions.push(FreeAction {
            pid: None,
            pgid: None,
            cmdline: item.local.clone(),
            result: "unmapped".to_string(),
            detail: format!(
                "{} listener uid {} has no readable /proc fd",
                item.protocol.as_str(),
                item.uid
            ),
        });
    }
    let executed = actions.iter().any(|item| item.result == "signaled");
    let watch_ports: Vec<u16> = if ports.is_empty() {
        spec.ports().collect()
    } else {
        ports.clone()
    };
    if executed {
        let cleared = wait_until_clear(&watch_ports, opts.grace_ms)?;
        if !cleared {
            for pgid in &signaled {
                let _ = signal_group(*pgid, libc::SIGKILL);
            }
            for action in &mut actions {
                if action.result == "signaled" {
                    action.result = "escalated".to_string();
                    action.detail = format!(
                        "still listening after {} ms; sent SIGKILL to the process group",
                        opts.grace_ms
                    );
                }
            }
            let _ = wait_until_clear(&watch_ports, 200)?;
        }
    }
    let freed = watch_ports.iter().try_fold(true, |ok, port| {
        Ok::<bool, crate::error::Error>(ok && !engine::port_is_listening(*port)?)
    })?;
    let message = if freed && executed {
        format!("freed {}", format_ports(&watch_ports))
    } else if freed {
        format!("{} is free", format_ports(&watch_ports))
    } else if hold_for_confirm {
        format!(
            "not signaled; pass --yes to confirm ({})",
            format_ports(&watch_ports)
        )
    } else if actions.iter().any(|item| item.result == "needs-force") {
        format!(
            "not fully signaled; a supervisor or other uid needs --force ({})",
            format_ports(&watch_ports)
        )
    } else {
        format!("port still bound: {}", format_ports(&watch_ports))
    };
    Ok(FreeReport {
        ports: watch_ports,
        executed,
        freed,
        actions,
        message,
    })
}

fn assess(target: &KillTarget, me: &Identity) -> Assessment {
    let mut assessment = Assessment {
        hard: None,
        force: None,
        confirm: None,
    };
    if target.pid <= 1 || target.pgid == 1 || target.pgid == 0 {
        assessment.hard = Some(format!(
            "refusing to signal pid {} (pgid {})",
            target.pid, target.pgid
        ));
        return assessment;
    }
    if target.pid == me.pid {
        assessment.hard = Some("refusing to signal this whose process".to_string());
        return assessment;
    }
    if me.ancestors.contains(&target.pid) {
        assessment.hard = Some(format!("refusing to signal ancestor pid {}", target.pid));
        return assessment;
    }
    if target.pgid == me.pgid && me.pgid != 0 {
        assessment.hard = Some("refusing to signal our own process group".to_string());
        return assessment;
    }
    let targets_session_leader = target.sid != 0 && target.pid == target.sid;
    if me.sid != 0
        && (target.pid == me.sid
            || target.pgid == me.sid
            || (targets_session_leader && target.sid == me.sid))
    {
        assessment.hard = Some("refusing to signal the session leader".to_string());
        return assessment;
    }
    if target.uid != me.uid {
        assessment.force = Some(format!(
            "pid {} is uid {}, not {} (pass --force to signal another user)",
            target.pid, target.uid, me.uid
        ));
    }
    if let Some(supervisor) = target.supervisor.as_ref().filter(|item| item.blocks_kill) {
        assessment.force = Some(format!(
            "supervised by {} {} — {}",
            supervisor.kind, supervisor.name, supervisor.stop
        ));
    }
    if is_sensitive_daemon(&target.comm, &target.args0, &target.exe) {
        assessment.confirm = Some(format!(
            "{} looks like a database or shared daemon",
            target.comm
        ));
    }
    assessment
}

fn action(target: &KillTarget, result: &str, detail: &str) -> FreeAction {
    FreeAction {
        pid: Some(target.pid),
        pgid: Some(target.pgid),
        cmdline: target.cmdline.clone(),
        result: result.to_string(),
        detail: detail.to_string(),
    }
}

fn collect_ports(targets: &[KillTarget], unmapped: &[crate::model::UnmappedListen]) -> Vec<u16> {
    let mut ports = Vec::new();
    for target in targets {
        for port in &target.ports {
            if !ports.contains(port) {
                ports.push(*port);
            }
        }
    }
    for item in unmapped {
        if !ports.contains(&item.port) {
            ports.push(item.port);
        }
    }
    ports.sort_unstable();
    ports
}

fn wait_until_clear(ports: &[u16], grace_ms: u64) -> Result<bool> {
    if ports_clear(ports)? {
        return Ok(true);
    }
    let deadline = Instant::now() + Duration::from_millis(grace_ms);
    while Instant::now() < deadline {
        let slice = 50.min(grace_ms.max(1));
        thread::sleep(Duration::from_millis(slice));
        if ports_clear(ports)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ports_clear(ports: &[u16]) -> Result<bool> {
    for port in ports {
        if engine::port_is_listening(*port)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn signal_group(pgid: u32, signal: i32) -> Result<()> {
    if pgid == 0 || pgid > i32::MAX as u32 {
        return Err(crate::error::Error::new(
            "refusing to signal process group 0",
        ));
    }
    // Map through nix so the signal we pass to killpg is one of the named
    // constants. killpg reaches every member of the group (parent and child).
    let named = match signal {
        libc::SIGKILL => nix::sys::signal::Signal::SIGKILL,
        _ => nix::sys::signal::Signal::SIGTERM,
    };
    let rc = unsafe { libc::killpg(pgid as i32, named as i32) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(err.into())
    }
}

fn current_identity() -> Identity {
    let pid = nix::unistd::getpid().as_raw();
    let uid = nix::unistd::geteuid().as_raw();
    let pgid = nix::unistd::getpgid(None)
        .map(|value| value.as_raw())
        .unwrap_or(pid);
    let sid = nix::unistd::getsid(None)
        .map(|value| value.as_raw())
        .unwrap_or(pid);
    Identity {
        pid: pid as u32,
        uid,
        pgid: pgid as u32,
        sid: sid as u32,
        ancestors: ancestor_pids(pid as u32),
    }
}

fn ancestor_pids(mut pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for _ in 0..64 {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            break;
        };
        let Some(stat) = parse_stat(&text) else {
            break;
        };
        if stat.ppid == 0 || stat.ppid == pid {
            break;
        }
        out.push(stat.ppid);
        pid = stat.ppid;
    }
    out
}

fn prompt_yes(reason: &str) -> bool {
    if !io::stdin().is_terminal() {
        return false;
    }
    let mut err = io::stderr();
    let _ = write!(err, "whose: {reason}\nproceed with SIGTERM? [y/N] ");
    let _ = err.flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}

fn format_spec(spec: PortSpec) -> String {
    if spec.start == spec.end {
        format!(":{}", spec.start)
    } else {
        format!(":{}-{}", spec.start, spec.end)
    }
}

fn format_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "no port".to_string();
    }
    ports
        .iter()
        .map(|port| format!(":{port}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SupervisorInfo;

    fn sample_target(pid: u32, pgid: u32, uid: u32, comm: &str) -> KillTarget {
        KillTarget {
            ports: vec![3000],
            pid,
            pgid,
            sid: pgid,
            uid,
            comm: comm.to_string(),
            args0: comm.to_string(),
            exe: comm.to_string(),
            cmdline: comm.to_string(),
            supervisor: None,
        }
    }

    fn me() -> Identity {
        Identity {
            pid: 10,
            uid: 1000,
            pgid: 10,
            sid: 2,
            ancestors: vec![2, 1],
        }
    }

    #[test]
    fn policy_refuses_init_ancestors_and_our_group() {
        let me = me();
        assert!(assess(&sample_target(1, 1, 0, "systemd"), &me)
            .hard
            .is_some());
        assert!(assess(&sample_target(2, 2, 1000, "zsh"), &me)
            .hard
            .is_some());
        assert!(assess(&sample_target(10, 10, 1000, "whose"), &me)
            .hard
            .is_some());
        let mut sibling = sample_target(50, 10, 1000, "node");
        sibling.sid = 2;
        assert!(assess(&sibling, &me).hard.is_some());
    }

    #[test]
    fn policy_confirms_databases_and_blocks_supervisors() {
        let me = me();
        let postgres = sample_target(80, 80, 1000, "postgres");
        let decision = assess(&postgres, &me);
        assert!(decision.hard.is_none());
        assert!(decision.confirm.is_some());
        assert!(decision.force.is_none());

        let mut node = sample_target(90, 90, 1000, "node");
        node.supervisor = Some(SupervisorInfo {
            kind: "systemd".to_string(),
            name: "app.service".to_string(),
            stop: "systemctl stop app.service".to_string(),
            detail: String::new(),
            blocks_kill: true,
        });
        let decision = assess(&node, &me);
        assert!(decision.force.as_deref().unwrap().contains("systemctl"));

        let mut other = sample_target(91, 91, 0, "nginx");
        other.sid = 91;
        assert!(assess(&other, &me).force.is_some());

        let mut plain = sample_target(100, 100, 1000, "node");
        plain.sid = 100;
        let decision = assess(&plain, &me);
        assert!(decision.hard.is_none());
        assert!(decision.force.is_none());
        assert!(decision.confirm.is_none());
    }
}
