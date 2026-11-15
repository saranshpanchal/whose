use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::SystemTime;

use crate::context::{ancestry, classify, filter_env, find_git, SupervisorFacts};
use crate::error::Result;
use crate::model::{
    exposure_of, exposure_warning, format_addr, format_uptime, is_listener, is_outbound_state,
    FlowReport, InspectReport, KillTarget, ListenReport, OutboundFilter, OutboundReport,
    OwnerReport, PortBrief, PortReport, ProcessNode, ProjectGroup, ProjectNode, QueryOpts,
    SocketRec, TcpInfoOut, Topology, UnmappedListen,
};
use crate::netlink;
use crate::outbound;
use crate::proc::{self, ProcessRec};

struct World {
    sockets: Vec<SocketRec>,
    procs: HashMap<u32, ProcessRec>,
    uptime_secs: u64,
    ticks: u64,
    page_size: u64,
    boot: SystemTime,
    self_cgroup: String,
    self_uid: u32,
    source: String,
}

fn load(want_details: impl Fn(&SocketRec) -> bool) -> Result<World> {
    let (mut sockets, source) = netlink::list_sockets()?;
    let snap = proc::scan_basic()?;
    for sock in &mut sockets {
        if sock.inode == 0 {
            continue;
        }
        if let Some(pids) = snap.inodes.get(&sock.inode) {
            for pid in pids {
                if !sock.pids.contains(pid) {
                    sock.pids.push(*pid);
                }
            }
        }
    }
    let mut procs = snap.procs;
    let mut need = HashSet::new();
    for sock in &sockets {
        if want_details(sock) {
            need.extend(sock.pids.iter().copied());
        }
    }
    for pid in need {
        if let Some(proc) = procs.get_mut(&pid) {
            proc::fill_details(proc);
        }
    }
    let self_uid = unsafe { libc::geteuid() };
    Ok(World {
        sockets,
        procs,
        uptime_secs: snap.uptime_secs,
        ticks: snap.ticks,
        page_size: snap.page_size,
        boot: snap.boot,
        self_cgroup: snap.self_cgroup,
        self_uid,
        source,
    })
}

pub fn inspect_ports(spec: crate::model::PortSpec, opts: &QueryOpts) -> Result<InspectReport> {
    let world = load(|sock| spec.contains(sock.local_port))?;
    let listeners: Vec<&SocketRec> = world
        .sockets
        .iter()
        .filter(|sock| spec.contains(sock.local_port) && is_listener(sock))
        .collect();
    let chosen: Vec<&SocketRec> = if listeners.is_empty() {
        world
            .sockets
            .iter()
            .filter(|sock| spec.contains(sock.local_port))
            .collect()
    } else {
        listeners
    };
    let mut ports = chosen
        .into_iter()
        .map(|sock| port_report(&world, sock, opts))
        .collect::<Vec<_>>();
    ports.sort_by(|a, b| a.port.cmp(&b.port).then(a.protocol.cmp(&b.protocol)));
    Ok(InspectReport {
        socket_source: world.source,
        ports,
    })
}

pub fn list_listening(opts: &QueryOpts) -> Result<ListenReport> {
    let world = load(is_listener)?;
    Ok(ListenReport {
        socket_source: world.source.clone(),
        groups: group_listeners(&world, opts),
    })
}

pub fn outbound_report(filter: &OutboundFilter, opts: &QueryOpts) -> Result<OutboundReport> {
    let world = load(|sock| is_outbound_state(sock.state) || is_listener(sock))?;
    let owners = owners_for(&world, opts);
    let assembled = outbound::assemble(&world.sockets, &owners, filter);
    Ok(OutboundReport {
        socket_source: world.source,
        groups: assembled.groups,
        warnings: assembled.warnings,
    })
}

pub fn topology(opts: &QueryOpts) -> Result<Topology> {
    let world = load(|sock| is_listener(sock) || is_outbound_state(sock.state))?;
    let owners = owners_for(&world, opts);
    let mut projects: BTreeMap<String, ProjectAccum> = BTreeMap::new();
    for sock in &world.sockets {
        if !is_listener(sock) {
            continue;
        }
        push_listen(&mut projects, &owners, sock);
    }
    for sock in &world.sockets {
        if !is_outbound_state(sock.state) {
            continue;
        }
        push_outbound(&mut projects, &owners, sock);
    }
    let assembled = outbound::assemble(&world.sockets, &owners, &OutboundFilter::default());
    let mut project_nodes = Vec::new();
    for (_label, acc) in projects {
        let mut processes: Vec<_> = acc.processes.into_values().collect();
        processes.sort_by_key(|proc| proc.pid);
        project_nodes.push(ProjectNode {
            label: acc.label,
            repo: acc.repo,
            worktree: acc.worktree,
            branch: acc.branch,
            processes,
        });
    }
    Ok(Topology {
        socket_source: world.source,
        projects: project_nodes,
        warnings: assembled.warnings,
    })
}

pub fn listener_targets(
    spec: crate::model::PortSpec,
) -> Result<(Vec<KillTarget>, Vec<UnmappedListen>, String)> {
    let world = load(|sock| spec.contains(sock.local_port) && is_listener(sock))?;
    let mut targets: BTreeMap<u32, KillTarget> = BTreeMap::new();
    let mut unmapped = Vec::new();
    for sock in &world.sockets {
        if !(spec.contains(sock.local_port) && is_listener(sock)) {
            continue;
        }
        if sock.pids.is_empty() {
            unmapped.push(UnmappedListen {
                port: sock.local_port,
                protocol: sock.protocol,
                uid: sock.uid,
                local: format_addr(sock.local_addr, sock.local_port),
            });
            continue;
        }
        for pid in &sock.pids {
            let Some(proc) = world.procs.get(pid) else {
                unmapped.push(UnmappedListen {
                    port: sock.local_port,
                    protocol: sock.protocol,
                    uid: sock.uid,
                    local: format_addr(sock.local_addr, sock.local_port),
                });
                continue;
            };
            let target = targets
                .entry(*pid)
                .or_insert_with(|| kill_target(&world, proc));
            if !target.ports.contains(&sock.local_port) {
                target.ports.push(sock.local_port);
            }
        }
    }
    for target in targets.values_mut() {
        target.ports.sort_unstable();
    }
    Ok((targets.into_values().collect(), unmapped, world.source))
}

pub fn port_is_listening(port: u16) -> Result<bool> {
    let (sockets, _) = netlink::list_sockets()?;
    Ok(sockets
        .iter()
        .any(|sock| sock.local_port == port && is_listener(sock)))
}

fn group_listeners(world: &World, opts: &QueryOpts) -> Vec<ProjectGroup> {
    #[derive(Default)]
    struct Bucket {
        repo: Option<String>,
        worktree: Option<String>,
        branch: Option<String>,
        ports: Vec<PortReport>,
    }
    let mut buckets: BTreeMap<String, Bucket> = BTreeMap::new();
    for sock in &world.sockets {
        if !is_listener(sock) {
            continue;
        }
        let owners = resolve_owners(world, sock, opts);
        if owners.is_empty() {
            let report = port_report_with(world, sock, owners);
            buckets
                .entry("(unknown owner)".to_string())
                .or_default()
                .ports
                .push(report);
            continue;
        }
        let mut by_key: BTreeMap<String, Vec<OwnerReport>> = BTreeMap::new();
        for owner in owners {
            let (label, _, _, _) = project_key(&owner);
            by_key.entry(label).or_default().push(owner);
        }
        for (label, group_owners) in by_key {
            let (repo, worktree, branch) = group_owners
                .first()
                .map(|owner| {
                    let (_, repo, worktree, branch) = project_key(owner);
                    (repo, worktree, branch)
                })
                .unwrap_or((None, None, None));
            let report = port_report_with(world, sock, group_owners);
            let bucket = buckets.entry(label).or_default();
            bucket.repo = repo;
            bucket.worktree = worktree;
            bucket.branch = branch;
            bucket.ports.push(report);
        }
    }
    buckets
        .into_iter()
        .map(|(project, bucket)| {
            let mut ports = bucket.ports;
            ports.sort_by(|a, b| a.port.cmp(&b.port).then(a.protocol.cmp(&b.protocol)));
            ProjectGroup {
                project,
                repo: bucket.repo,
                worktree: bucket.worktree,
                branch: bucket.branch,
                ports,
            }
        })
        .collect()
}

fn project_key(owner: &OwnerReport) -> (String, Option<String>, Option<String>, Option<String>) {
    if let Some(git) = &owner.git {
        let label = format!("{} @ {} ({})", git.repo_name, git.worktree, git.branch);
        return (
            label,
            Some(git.repo_name.clone()),
            Some(git.worktree.clone()),
            Some(git.branch.clone()),
        );
    }
    if let Some(supervisor) = &owner.supervisor {
        return (
            format!("{}:{}", supervisor.kind, supervisor.name),
            None,
            None,
            None,
        );
    }
    ("(no project)".to_string(), None, None, None)
}

fn port_report(world: &World, sock: &SocketRec, opts: &QueryOpts) -> PortReport {
    let owners = resolve_owners(world, sock, opts);
    port_report_with(world, sock, owners)
}

fn port_report_with(world: &World, sock: &SocketRec, owners: Vec<OwnerReport>) -> PortReport {
    let local = format_addr(sock.local_addr, sock.local_port);
    let exposure = exposure_of(sock);
    let owner_status = if !owners.is_empty() {
        "known"
    } else if sock.uid != world.self_uid {
        "other-uid"
    } else {
        "unknown"
    };
    PortReport {
        protocol: sock.protocol.as_str().to_string(),
        state: sock.state.as_str().to_string(),
        local: local.clone(),
        remote: format_addr(sock.remote_addr, sock.remote_port),
        port: sock.local_port,
        exposure: exposure.as_str().to_string(),
        warning: exposure_warning(exposure, &local),
        uid: sock.uid,
        inode: sock.inode,
        v6only: sock.v6only,
        owner_status: owner_status.to_string(),
        tcp: sock.tcp.as_ref().map(TcpInfoOut::from),
        owners,
    }
}

fn resolve_owners(world: &World, sock: &SocketRec, opts: &QueryOpts) -> Vec<OwnerReport> {
    let mut owners = Vec::new();
    for pid in &sock.pids {
        if let Some(owner) = owner_report(world, *pid, opts) {
            owners.push(owner);
        }
    }
    owners.sort_by_key(|owner| owner.pid);
    owners
}

fn owners_for(world: &World, opts: &QueryOpts) -> BTreeMap<u32, OwnerReport> {
    let mut ids = HashSet::new();
    for sock in &world.sockets {
        if is_listener(sock) || is_outbound_state(sock.state) {
            ids.extend(sock.pids.iter().copied());
        }
    }
    let mut map = BTreeMap::new();
    for pid in ids {
        if let Some(owner) = owner_report(world, pid, opts) {
            map.insert(pid, owner);
        }
    }
    map
}

fn owner_report(world: &World, pid: u32, opts: &QueryOpts) -> Option<OwnerReport> {
    let proc = world.procs.get(&pid)?;
    let cmdline = cmdline_of(proc);
    let args0 = proc.args.first().cloned().unwrap_or_default();
    let exe = proc.exe.clone().unwrap_or_default();
    let chain = ancestry(&world.procs, pid);
    let ancestry_comms: Vec<String> = chain.iter().map(|item| item.comm.clone()).collect();
    let supervisor = classify(&SupervisorFacts {
        comm: &proc.comm,
        args0: &args0,
        exe: &exe,
        cmdline: &cmdline,
        cgroup: &proc.cgroup,
        environ: &proc.environ,
        ancestry_comms: &ancestry_comms,
        self_cgroup: &world.self_cgroup,
    });
    let git = proc.cwd.as_deref().and_then(|cwd| find_git(Path::new(cwd)));
    let uptime_secs = uptime_of(proc, world);
    Some(OwnerReport {
        pid,
        uid: proc.uid.unwrap_or(0),
        pgid: proc.pgid,
        sid: proc.sid,
        comm: proc.comm.clone(),
        cmdline,
        args: proc.args.clone(),
        exe: proc.exe.clone(),
        cwd: proc.cwd.clone(),
        uptime: format_uptime(uptime_secs),
        uptime_secs,
        rss_bytes: proc.rss_pages.saturating_mul(world.page_size.max(1)),
        started_at: started_at(world, proc),
        ancestry: chain,
        git,
        supervisor,
        env: filter_env(&proc.environ, opts.show_secrets),
    })
}

fn kill_target(world: &World, proc: &ProcessRec) -> KillTarget {
    let opts = QueryOpts {
        show_secrets: false,
    };
    let owner = owner_report(world, proc.pid, &opts);
    let args0 = proc.args.first().cloned().unwrap_or_default();
    KillTarget {
        ports: Vec::new(),
        pid: proc.pid,
        pgid: proc.pgid,
        sid: proc.sid,
        uid: proc.uid.unwrap_or(0),
        comm: proc.comm.clone(),
        args0,
        exe: proc.exe.clone().unwrap_or_default(),
        cmdline: cmdline_of(proc),
        supervisor: owner.and_then(|owner| owner.supervisor),
    }
}

fn cmdline_of(proc: &ProcessRec) -> String {
    if proc.args.is_empty() {
        format!("[{}]", proc.comm)
    } else {
        proc.args.join(" ")
    }
}

fn uptime_of(proc: &ProcessRec, world: &World) -> u64 {
    let ticks = world.ticks.max(1);
    let start = proc.start_ticks / ticks;
    world.uptime_secs.saturating_sub(start)
}

fn started_at(world: &World, proc: &ProcessRec) -> Option<String> {
    let ticks = world.ticks.max(1);
    let started = world
        .boot
        .checked_add(std::time::Duration::from_secs(proc.start_ticks / ticks))?;
    let stamp: chrono::DateTime<chrono::Utc> = started.into();
    Some(stamp.to_rfc3339())
}

struct ProjectAccum {
    label: String,
    repo: Option<String>,
    worktree: Option<String>,
    branch: Option<String>,
    processes: BTreeMap<u32, ProcessNode>,
}

fn push_listen(
    projects: &mut BTreeMap<String, ProjectAccum>,
    owners: &BTreeMap<u32, OwnerReport>,
    sock: &SocketRec,
) {
    let brief = PortBrief {
        protocol: sock.protocol.as_str().to_string(),
        state: sock.state.as_str().to_string(),
        local: format_addr(sock.local_addr, sock.local_port),
        port: sock.local_port,
        exposure: exposure_of(sock).as_str().to_string(),
        warning: exposure_warning(
            exposure_of(sock),
            &format_addr(sock.local_addr, sock.local_port),
        ),
        tcp: sock.tcp.as_ref().map(TcpInfoOut::from),
    };
    if sock.pids.is_empty() {
        let acc = projects
            .entry("(unknown owner)".to_string())
            .or_insert_with(|| ProjectAccum {
                label: "(unknown owner)".to_string(),
                repo: None,
                worktree: None,
                branch: None,
                processes: BTreeMap::new(),
            });
        let node = acc.processes.entry(0).or_insert_with(|| ProcessNode {
            pid: 0,
            cmdline: format!("uid {}", sock.uid),
            ancestry: Vec::new(),
            uptime: String::new(),
            rss_bytes: 0,
            supervisor: None,
            stop: None,
            env: Vec::new(),
            listens: Vec::new(),
            outbound: Vec::new(),
        });
        node.listens.push(brief);
        return;
    }
    for pid in &sock.pids {
        let Some(owner) = owners.get(pid) else {
            continue;
        };
        let node = process_slot(projects, owner);
        node.listens.push(brief.clone());
    }
}

fn push_outbound(
    projects: &mut BTreeMap<String, ProjectAccum>,
    owners: &BTreeMap<u32, OwnerReport>,
    sock: &SocketRec,
) {
    let flow = flow_of(sock);
    for pid in &sock.pids {
        let Some(owner) = owners.get(pid) else {
            continue;
        };
        let node = process_slot(projects, owner);
        node.outbound.push(flow.clone());
    }
}

fn process_slot<'a>(
    projects: &'a mut BTreeMap<String, ProjectAccum>,
    owner: &OwnerReport,
) -> &'a mut ProcessNode {
    let (label, repo, worktree, branch) = project_key(owner);
    let acc = projects
        .entry(label.clone())
        .or_insert_with(|| ProjectAccum {
            label,
            repo,
            worktree,
            branch,
            processes: BTreeMap::new(),
        });
    acc.processes
        .entry(owner.pid)
        .or_insert_with(|| process_node(owner))
}

fn process_node(owner: &OwnerReport) -> ProcessNode {
    ProcessNode {
        pid: owner.pid,
        cmdline: owner.cmdline.clone(),
        ancestry: owner
            .ancestry
            .iter()
            .map(|item| item.comm.clone())
            .collect(),
        uptime: owner.uptime.clone(),
        rss_bytes: owner.rss_bytes,
        supervisor: owner
            .supervisor
            .as_ref()
            .map(|s| format!("{}:{}", s.kind, s.name)),
        stop: owner.supervisor.as_ref().map(|s| s.stop.clone()),
        env: owner.env.clone(),
        listens: Vec::new(),
        outbound: Vec::new(),
    }
}

fn flow_of(sock: &SocketRec) -> FlowReport {
    let tcp = sock.tcp.as_ref().map(TcpInfoOut::from);
    FlowReport {
        protocol: sock.protocol.as_str().to_string(),
        state: sock.state.as_str().to_string(),
        local: format_addr(sock.local_addr, sock.local_port),
        remote: format_addr(sock.remote_addr, sock.remote_port),
        uid: sock.uid,
        inode: sock.inode,
        rtt_us: tcp.as_ref().map(|info| info.rtt_us),
        rtt_ms: tcp.as_ref().map(|info| info.rtt_ms),
        total_retrans: tcp.as_ref().map(|info| info.total_retrans),
        bytes_acked: tcp.as_ref().map(|info| info.bytes_acked),
        bytes_received: tcp.as_ref().map(|info| info.bytes_received),
    }
}
