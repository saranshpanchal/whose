//! whose — who owns this localhost port?
//!
//! Linux collects sockets with `NETLINK_SOCK_DIAG` and joins them to processes
//! through `/proc/<pid>/fd` socket inodes. Other platforms parse `lsof` or `netstat`.

mod cli;
mod context;
mod engine;
mod error;
mod kill;
mod mcp;
mod model;
mod netlink;
mod outbound;
mod proc;
mod render;
mod tui;
mod web;

pub use context::{filter_env, find_git};
pub use engine::{inspect_ports, list_listening, outbound_report, topology};
pub use error::{Error, Result};
pub use kill::free_port;
pub use model::{
    parse_port_spec, FlowReport, FreeReport, InspectReport, KillOpts, ListenReport, OutboundFilter,
    OutboundReport, PortReport, PortSpec, QueryOpts,
};
pub use proc::load_process;

pub fn run() -> Result<i32> {
    cli::run()
}
