mod attrib;
mod git;

use std::collections::HashMap;

pub use attrib::{classify, filter_env, is_sensitive_daemon, SupervisorFacts};
pub use git::find_git;

use crate::model::{Ancestor, GitInfo, SupervisorInfo};
use crate::proc::ProcessRec;

pub use crate::model::EnvPair;

pub fn ancestry(procs: &HashMap<u32, ProcessRec>, pid: u32) -> Vec<Ancestor> {
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..64 {
        let Some(proc) = procs.get(&current) else {
            break;
        };
        chain.push(Ancestor {
            pid: current,
            comm: proc.comm.clone(),
        });
        if proc.ppid == 0 || proc.ppid == current {
            break;
        }
        current = proc.ppid;
    }
    chain.reverse();
    chain
}
