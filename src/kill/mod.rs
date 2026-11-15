use std::collections::{HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::thread;
use std::time::{Duration, Instant};

use crate::context::is_sensitive_daemon;
use crate::engine;
use crate::error::Result;
use crate::model::{FreeAction, FreeReport, Identity, KillOpts, KillTarget, PortSpec};
use crate::proc::{self, parse_stat};

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
            dry_run: opts.dry_run,
            pids: Vec::new(),
            actions: Vec::new(),
            message: format!("no listener on {}", format_spec(spec)),
        });
    }
    let me = current_identity();
    let snap = proc::scan_basic()?;
    let rows: Vec<(u32, u32, u32)> = snap
        .procs
        .values()
        .map(|proc| (proc.pid, proc.ppid, proc.pgid))
        .collect();
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
    let preview_only = opts.dry_run || (opts.require_yes && !opts.yes);
    let hold_for_confirm = assessments.iter().any(|item| item.confirm.is_some()) && !opts.yes;
    let mut actions = Vec::new();
    let mut shots: Vec<Shot> = Vec::new();
    let mut planned: Vec<u32> = Vec::new();
    for (target, assessment) in targets.iter().zip(assessments.iter()) {
        if let Some(reason) = &assessment.hard {
            actions.push(action(target, "refused", reason));
            continue;
        }
        if assessment.confirm.is_some() && !opts.yes {
            let detail = assessment.confirm.clone().unwrap_or_default();
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
        let scope = scope_for(target.pid, target.pgid, &rows, &me);
        for pid in &scope.pids {
            if !planned.contains(pid) {
                planned.push(*pid);
            }
        }
        let listed = scope
            .pids
            .iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let scope_name = if opts.tree {
            "listener subtree (--tree)"
        } else {
            "listener subtree"
        };
        if preview_only {
            let why = if opts.require_yes && !opts.yes {
                format!("dry-run (yes is not set); would signal {scope_name} pids {listed}")
            } else {
                format!("dry-run; would signal {scope_name} pids {listed}")
            };
            actions.push(action(target, "dry-run", &why));
            continue;
        }
        shots.push(scope);
        actions.push(action(
            target,
            "signaled",
            &format!("SIGTERM {scope_name} pids {listed}"),
        ));
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
    if !shots.is_empty() {
        for shot in &shots {
            let _ = deliver(shot, libc::SIGTERM);
        }
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
            for shot in &shots {
                let _ = deliver(shot, libc::SIGKILL);
            }
            for action in &mut actions {
                if action.result == "signaled" {
                    action.result = "escalated".to_string();
                    action.detail = format!(
                        "still listening after {} ms; sent SIGKILL to the listener subtree",
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
    } else if preview_only {
        let why = if opts.require_yes && !opts.yes {
            "refusing to signal without yes: true"
        } else {
            "dry-run"
        };
        format!(
            "{why}; would signal pids {} on {}",
            format_pid_list(&planned),
            format_ports(&watch_ports)
        )
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
    planned.sort_unstable();
    planned.dedup();
    Ok(FreeReport {
        ports: watch_ports,
        executed,
        freed,
        dry_run: preview_only,
        pids: planned,
        actions,
        message,
    })
}

struct Shot {
    kill_group: Option<u32>,
    pids: Vec<u32>,
}

fn scope_for(listener: u32, pgid: u32, rows: &[(u32, u32, u32)], me: &Identity) -> Shot {
    let (kill_group, mut pids) = scope_pids(listener, pgid, rows, me);
    pids.sort_unstable();
    pids.dedup();
    Shot { kill_group, pids }
}

/// Pids to signal for one listener. `kill_group` is set only when the process
/// group leader is the listener or one of its descendants and every member of
/// that group is inside the subtree. Ancestors are never included.
fn scope_pids(
    listener: u32,
    pgid: u32,
    rows: &[(u32, u32, u32)],
    me: &Identity,
) -> (Option<u32>, Vec<u32>) {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, ppid, _) in rows {
        children.entry(*ppid).or_default().push(*pid);
    }
    let mut tree = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![listener];
    while let Some(pid) = stack.pop() {
        if pid <= 1 || !seen.insert(pid) {
            continue;
        }
        if pid == me.pid || me.ancestors.contains(&pid) {
            continue;
        }
        tree.push(pid);
        if let Some(kids) = children.get(&pid) {
            stack.extend(kids.iter().copied());
        }
    }
    if tree.is_empty() && listener > 1 && listener != me.pid && !me.ancestors.contains(&listener) {
        tree.push(listener);
    }
    let members: Vec<u32> = rows
        .iter()
        .filter(|(_, _, group)| *group == pgid && pgid != 0)
        .map(|(pid, _, _)| *pid)
        .collect();
    if pgid == me.pgid {
        return (None, tree);
    }
    let leader_in_tree = pgid > 1 && tree.contains(&pgid);
    let group_safe = leader_in_tree
        && !members.is_empty()
        && members.iter().all(|pid| tree.contains(pid))
        && !members
            .iter()
            .any(|pid| me.ancestors.contains(pid) || *pid == me.pid);
    if group_safe {
        (Some(pgid), members)
    } else {
        (None, tree)
    }
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

fn deliver(shot: &Shot, signal: i32) -> Result<()> {
    if let Some(pgid) = shot.kill_group {
        signal_group(pgid, signal)
    } else {
        for pid in &shot.pids {
            signal_one(*pid, signal)?;
        }
        Ok(())
    }
}

fn signal_one(pid: u32, signal: i32) -> Result<()> {
    if pid <= 1 {
        return Err(crate::error::Error::new("refusing to signal pid 1"));
    }
    let named = match signal {
        libc::SIGKILL => nix::sys::signal::Signal::SIGKILL,
        _ => nix::sys::signal::Signal::SIGTERM,
    };
    let rc = unsafe { libc::kill(pid as i32, named as i32) };
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

fn format_pid_list(pids: &[u32]) -> String {
    if pids.is_empty() {
        return "none".to_string();
    }
    pids.iter()
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(",")
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
        assert!(
            assess(&sibling, &me).hard.is_none(),
            "a listener that shares our process group is signaled by pid"
        );
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

    #[test]
    fn scope_never_includes_an_ancestor_that_shares_the_group() {
        let me = Identity {
            pid: 99,
            uid: 1000,
            pgid: 99,
            sid: 99,
            ancestors: vec![1],
        };
        // 5 is the group leader and the parent. 10 listens. 11 is 10's child.
        let rows = [(5, 1, 5), (10, 5, 5), (11, 10, 5)];
        let (group, mut pids) = scope_pids(10, 5, &rows, &me);
        pids.sort_unstable();
        assert!(group.is_none());
        assert_eq!(pids, vec![10, 11]);
        assert!(!pids.contains(&5));

        // The listener is the group leader, so the group is safe.
        let rows = [(10, 1, 10), (11, 10, 10)];
        let (group, mut pids) = scope_pids(10, 10, &rows, &me);
        pids.sort_unstable();
        assert_eq!(group, Some(10));
        assert_eq!(pids, vec![10, 11]);
    }
}
