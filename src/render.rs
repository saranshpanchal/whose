use owo_colors::OwoColorize;

use crate::model::{
    format_bytes, FlowReport, FreeReport, InspectReport, ListenReport, OutboundReport, OwnerReport,
    PortReport,
};

enum Tone {
    Port,
    Ok,
    Warn,
    Bad,
    Dim,
}

fn paint(color: bool, text: &str, tone: Tone) -> String {
    if !color {
        return text.to_string();
    }
    match tone {
        Tone::Port => text.cyan().bold().to_string(),
        Tone::Ok => text.green().to_string(),
        Tone::Warn => text.yellow().to_string(),
        Tone::Bad => text.red().to_string(),
        Tone::Dim => text.dimmed().to_string(),
    }
}

pub fn inspect(report: &InspectReport, color: bool) -> String {
    if report.ports.is_empty() {
        return "no socket matched".to_string();
    }
    let mut lines = Vec::new();
    if report.socket_source != "sock_diag" {
        lines.push(paint(
            color,
            &format!("socket source: {}", report.socket_source),
            Tone::Warn,
        ));
    }
    for port in &report.ports {
        lines.push(port_block(port, color));
    }
    lines.join("\n")
}

pub fn list(report: &ListenReport, color: bool) -> String {
    if report.groups.is_empty() {
        return "no listening tcp or udp sockets".to_string();
    }
    let mut lines = Vec::new();
    if report.socket_source != "sock_diag" {
        lines.push(paint(
            color,
            &format!("socket source: {}", report.socket_source),
            Tone::Warn,
        ));
    }
    for group in &report.groups {
        lines.push(paint(color, &group.project, Tone::Port));
        for port in &group.ports {
            lines.push(format!("  {}", port_line(port, color)));
        }
    }
    lines.join("\n")
}

pub fn outbound(report: &OutboundReport, color: bool) -> String {
    let mut lines = Vec::new();
    if report.socket_source != "sock_diag" {
        lines.push(paint(
            color,
            &format!("socket source: {}", report.socket_source),
            Tone::Warn,
        ));
    }
    if report.groups.is_empty() {
        lines.push("no outbound sockets".to_string());
    }
    for group in &report.groups {
        let title = match group.pid {
            Some(pid) => format!("{pid} {}", group.cmdline),
            None => group.cmdline.clone(),
        };
        let place = match (&group.repo, &group.branch) {
            (Some(repo), Some(branch)) => format!("  {repo} ({branch})"),
            _ => String::new(),
        };
        lines.push(format!("{}{}", paint(color, &title, Tone::Port), place));
        for flow in &group.sockets {
            lines.push(format!("  {}", flow_line(flow, color)));
        }
    }
    for warning in &report.warnings {
        lines.push(paint(color, warning, Tone::Warn));
    }
    lines.join("\n")
}

pub fn free(report: &FreeReport, color: bool) -> String {
    let tone = if report.freed { Tone::Ok } else { Tone::Bad };
    let mut lines = vec![paint(color, &report.message, tone)];
    for action in &report.actions {
        let who = match action.pid {
            Some(pid) => format!(
                "pid {pid} pgid {:?} {}",
                action.pgid.unwrap_or(0),
                action.cmdline
            ),
            None => action.cmdline.clone(),
        };
        lines.push(format!(
            "  {}  {who}  {}",
            action.result,
            paint(color, &action.detail, Tone::Dim)
        ));
    }
    lines.join("\n")
}

fn port_block(port: &PortReport, color: bool) -> String {
    let mut lines = vec![port_line(port, color)];
    if let Some(warning) = &port.warning {
        lines.push(format!("  {}", paint(color, warning, Tone::Warn)));
    }
    if port.owners.is_empty() {
        lines.push(format!(
            "  {}",
            paint(
                color,
                &format!("owner {} (uid {})", port.owner_status, port.uid),
                Tone::Warn
            )
        ));
    }
    for owner in &port.owners {
        lines.extend(owner_lines(owner, color));
    }
    if let Some(tcp) = &port.tcp {
        lines.push(format!(
            "  tcp   rtt {:.2} ms  retrans {}  acked {}  recv {}",
            tcp.rtt_ms,
            tcp.total_retrans,
            format_bytes(tcp.bytes_acked),
            format_bytes(tcp.bytes_received)
        ));
    }
    lines.join("\n")
}

fn port_line(port: &PortReport, color: bool) -> String {
    let head = format!(
        "{} {} {}",
        port.protocol,
        port.state,
        paint(color, &port.local, Tone::Port)
    );
    let owner = port
        .owners
        .first()
        .map(|owner| format!("pid {} {}", owner.pid, owner.comm))
        .unwrap_or_else(|| format!("uid {} {}", port.uid, port.owner_status));
    format!("{head}  {owner}  {}", port.exposure)
}

fn owner_lines(owner: &OwnerReport, color: bool) -> Vec<String> {
    let chain = owner
        .ancestry
        .iter()
        .map(|item| item.comm.as_str())
        .collect::<Vec<_>>()
        .join(" → ");
    let mut lines = vec![format!(
        "  owner {}  {}  up {}  rss {}",
        owner.pid,
        owner.cmdline,
        owner.uptime,
        format_bytes(owner.rss_bytes)
    )];
    if !chain.is_empty() {
        lines.push(format!("  chain {chain}"));
    }
    if let Some(cwd) = &owner.cwd {
        lines.push(format!("  cwd   {cwd}"));
    }
    if let Some(git) = &owner.git {
        lines.push(format!(
            "  git   {} @ {} ({})",
            git.repo_name, git.worktree, git.branch
        ));
    }
    if let Some(supervisor) = &owner.supervisor {
        let tone = if supervisor.blocks_kill {
            Tone::Warn
        } else {
            Tone::Dim
        };
        lines.push(format!(
            "  svc   {}",
            paint(
                color,
                &format!(
                    "{} {} — {}",
                    supervisor.kind, supervisor.name, supervisor.stop
                ),
                tone
            )
        ));
    }
    if !owner.env.is_empty() {
        let env = owner
            .env
            .iter()
            .map(|item| format!("{}={}", item.key, item.value))
            .collect::<Vec<_>>()
            .join("  ");
        lines.push(format!("  env   {env}"));
    }
    lines
}

fn flow_line(flow: &FlowReport, color: bool) -> String {
    let stats = match (
        flow.rtt_ms,
        flow.total_retrans,
        flow.bytes_acked,
        flow.bytes_received,
    ) {
        (Some(rtt), Some(retrans), Some(acked), Some(recv)) => format!(
            "rtt {rtt:.2} ms  retrans {retrans}  acked {}  recv {}",
            format_bytes(acked),
            format_bytes(recv)
        ),
        _ => "tcp_info unavailable".to_string(),
    };
    let state_tone = if flow.state == "CLOSE_WAIT" {
        Tone::Warn
    } else {
        Tone::Dim
    };
    format!(
        "{} {} {} -> {}  {}",
        flow.protocol,
        paint(color, &flow.state, state_tone),
        flow.local,
        flow.remote,
        stats
    )
}
