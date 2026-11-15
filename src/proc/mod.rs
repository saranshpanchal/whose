mod parse;

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

pub use parse::{
    parse_socket_inode, parse_stat, parse_uid, split_cmdline, split_environ, StatFields,
};

use crate::error::{Error, Result};

/// One process row. `environ` is the raw table; display paths run it through
/// [`crate::context::filter_env`] before it leaves the process.
#[derive(Debug, Clone)]
pub struct ProcessRec {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub uid: Option<u32>,
    pub comm: String,
    pub state: char,
    pub start_ticks: u64,
    pub rss_pages: u64,
    pub args: Vec<String>,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub environ: Vec<(String, String)>,
    pub cgroup: String,
    pub details: bool,
}

#[derive(Debug, Clone)]
pub struct ProcSnap {
    pub procs: HashMap<u32, ProcessRec>,
    pub inodes: HashMap<u64, Vec<u32>>,
    pub uptime_secs: u64,
    pub ticks: u64,
    pub page_size: u64,
    pub boot: SystemTime,
    pub self_cgroup: String,
}

impl ProcSnap {
    fn bare() -> Self {
        Self {
            procs: HashMap::new(),
            inodes: HashMap::new(),
            uptime_secs: 0,
            ticks: 100,
            page_size: 4096,
            boot: SystemTime::UNIX_EPOCH,
            self_cgroup: String::new(),
        }
    }
}

/// Single pass over `/proc`: stat, status uid, cgroup, and `fd` socket inodes.
/// Command lines and environ are filled later, only for processes we display.
pub fn scan_basic() -> Result<ProcSnap> {
    if !Path::new("/proc/self").exists() {
        return Ok(ProcSnap::bare());
    }
    let ticks = sysconf(libc::_SC_CLK_TCK, 100);
    let page_size = sysconf(libc::_SC_PAGESIZE, 4096);
    let uptime_secs = read_uptime();
    let boot = SystemTime::now()
        .checked_sub(Duration::from_secs(uptime_secs))
        .unwrap_or_else(SystemTime::now);
    let mut procs = HashMap::new();
    let mut inodes: HashMap<u64, Vec<u32>> = HashMap::new();
    let dir = fs::read_dir("/proc").map_err(|e| Error::new(format!("read /proc: {e}")))?;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            continue;
        };
        let Ok(pid) = text.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let Some(stat) = read_stat_file(pid) else {
            continue;
        };
        collect_inodes(pid, &mut inodes);
        procs.insert(
            pid,
            ProcessRec {
                pid,
                ppid: stat.ppid,
                pgid: stat.pgrp,
                sid: stat.session,
                uid: read_uid_file(pid),
                comm: stat.comm,
                state: stat.state,
                start_ticks: stat.start_ticks,
                rss_pages: stat.rss_pages,
                args: Vec::new(),
                exe: None,
                cwd: None,
                environ: Vec::new(),
                cgroup: read_text(&format!("/proc/{pid}/cgroup")),
                details: false,
            },
        );
    }
    Ok(ProcSnap {
        procs,
        inodes,
        uptime_secs,
        ticks,
        page_size,
        boot,
        self_cgroup: read_text("/proc/self/cgroup"),
    })
}

pub fn fill_details(proc: &mut ProcessRec) {
    if proc.details {
        return;
    }
    let pid = proc.pid;
    proc.args = split_cmdline(&read_bytes(&format!("/proc/{pid}/cmdline")));
    proc.exe = read_link(&format!("/proc/{pid}/exe"));
    proc.cwd = read_link(&format!("/proc/{pid}/cwd"));
    proc.environ = split_environ(&read_bytes(&format!("/proc/{pid}/environ")));
    if proc.cgroup.is_empty() {
        proc.cgroup = read_text(&format!("/proc/{pid}/cgroup"));
    }
    proc.details = true;
}

/// Read one process, including environ. Used by tests and by callers that
/// already know the pid.
pub fn load_process(pid: u32) -> Result<ProcessRec> {
    let stat = read_stat_file(pid).ok_or_else(|| Error::new(format!("no /proc/{pid}/stat")))?;
    let mut proc = ProcessRec {
        pid,
        ppid: stat.ppid,
        pgid: stat.pgrp,
        sid: stat.session,
        uid: read_uid_file(pid),
        comm: stat.comm,
        state: stat.state,
        start_ticks: stat.start_ticks,
        rss_pages: stat.rss_pages,
        args: Vec::new(),
        exe: None,
        cwd: None,
        environ: Vec::new(),
        cgroup: read_text(&format!("/proc/{pid}/cgroup")),
        details: false,
    };
    fill_details(&mut proc);
    Ok(proc)
}

fn read_stat_file(pid: u32) -> Option<StatFields> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat(&text)
}

fn read_uid_file(pid: u32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_uid(&text)
}

fn collect_inodes(pid: u32, map: &mut HashMap<u64, Vec<u32>>) {
    let Ok(dir) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return;
    };
    for entry in dir.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let Some(text) = target.to_str() else {
            continue;
        };
        let Some(inode) = parse_socket_inode(text) else {
            continue;
        };
        let slot = map.entry(inode).or_default();
        if !slot.contains(&pid) {
            slot.push(pid);
        }
    }
}

fn read_text(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn read_bytes(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn read_link(path: &str) -> Option<String> {
    fs::read_link(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
}

fn read_uptime() -> u64 {
    let Ok(text) = fs::read_to_string("/proc/uptime") else {
        return 0;
    };
    let Some(first) = text.split_whitespace().next() else {
        return 0;
    };
    first.parse::<f64>().unwrap_or(0.0).max(0.0) as u64
}

fn sysconf(name: libc::c_int, fallback: u64) -> u64 {
    let value = unsafe { libc::sysconf(name) };
    if value <= 0 {
        fallback
    } else {
        value as u64
    }
}
