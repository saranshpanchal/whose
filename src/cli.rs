use std::io::{self, IsTerminal, Write};

use clap::{Parser, Subcommand};
use serde::Serialize;

use crate::engine::{inspect_ports, list_listening, outbound_report};
use crate::error::Result;
use crate::kill::free_port;
use crate::mcp;
use crate::model::{parse_port_spec, KillOpts, OutboundFilter, QueryOpts};
use crate::render;
use crate::tui;
use crate::web;

#[derive(Parser, Debug)]
#[command(
    name = "whose",
    version,
    about = "Whose port or socket is this?",
    subcommand_precedence_over_arg = true,
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    /// Port (`3000`, `:3000`) or inclusive range (`3000-3010`).
    #[arg(value_name = "PORT")]
    pub port: Option<String>,

    #[command(subcommand)]
    pub command: Option<Cmd>,

    /// Emit JSON on stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// Show secret-shaped environment values (off by default).
    #[arg(long, global = true)]
    pub show_secrets: bool,

    /// Never colorize, even on a terminal.
    #[arg(long, global = true)]
    pub no_color: bool,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List listening TCP and UDP sockets grouped by git worktree.
    Ls,
    /// Outbound sockets with RTT, retransmits, and byte counters.
    Outbound {
        /// Only sockets owned by this pid.
        #[arg(long)]
        pid: Option<u32>,
        /// Only processes whose name or command line contains this text.
        #[arg(long = "proc")]
        process: Option<String>,
        /// Also show accepted sockets on a port this process is listening on.
        #[arg(long)]
        inbound: bool,
    },
    /// Free a listener: SIGTERM its process group, then SIGKILL after the grace period.
    #[command(alias = "free")]
    Kill {
        /// Port (`:3000`) or range (`3000-3010`).
        port: String,
        /// Confirm signaling a database or other shared daemon.
        #[arg(long)]
        yes: bool,
        /// Also signal a supervised process or another user's process.
        #[arg(long)]
        force: bool,
        /// Milliseconds to wait after SIGTERM before SIGKILL.
        #[arg(long, default_value_t = 2000)]
        grace_ms: u64,
        /// Show the pids that would be signaled and do not signal them.
        #[arg(long)]
        dry_run: bool,
        /// Signal the listener and its descendants. This is the default scope.
        #[arg(long, default_value_t = true)]
        tree: bool,
    },
    /// Live dashboard. `tui` is an alias.
    #[command(alias = "tui")]
    Watch,
    /// Serve a loopback-only topology page.
    Serve {
        /// TCP port to bind on 127.0.0.1.
        #[arg(long, default_value_t = 7070)]
        port: u16,
    },
    /// Speak MCP (JSON-RPC 2.0) on stdin and stdout.
    Mcp,
}

pub fn run() -> Result<i32> {
    let cli = Cli::parse();
    let color = color_enabled(&cli);
    let opts = QueryOpts {
        show_secrets: cli.show_secrets,
    };
    match cli.command {
        None => match cli.port {
            Some(port) => {
                let spec = parse_port_spec(&port)?;
                let report = inspect_ports(spec, &opts)?;
                let empty = report.ports.is_empty();
                if cli.json {
                    emit_json(&report)?;
                } else {
                    emit(&render::inspect(&report, color))?;
                }
                Ok(if empty { 1 } else { 0 })
            }
            None => emit_list(&opts, cli.json, color),
        },
        Some(Cmd::Ls) => emit_list(&opts, cli.json, color),
        Some(Cmd::Outbound {
            pid,
            process,
            inbound,
        }) => {
            let report = outbound_report(
                &OutboundFilter {
                    pid,
                    process,
                    include_inbound: inbound,
                },
                &opts,
            )?;
            if cli.json {
                emit_json(&report)?;
            } else {
                emit(&render::outbound(&report, color))?;
            }
            Ok(0)
        }
        Some(Cmd::Kill {
            port,
            yes,
            force,
            grace_ms,
            dry_run,
            tree,
        }) => {
            let spec = parse_port_spec(&port)?;
            let report = free_port(
                spec,
                KillOpts {
                    yes,
                    force,
                    grace_ms,
                    interactive: !cli.json && io::stdin().is_terminal() && !dry_run,
                    dry_run,
                    require_yes: false,
                    tree,
                },
            )?;
            if cli.json {
                emit_json(&report)?;
            } else {
                emit(&render::free(&report, color))?;
            }
            Ok(if report.dry_run || report.freed { 0 } else { 1 })
        }
        Some(Cmd::Watch) => tui::run(),
        Some(Cmd::Serve { port }) => {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|err| crate::error::Error::new(err.to_string()))?;
            runtime.block_on(web::serve(port))?;
            Ok(0)
        }
        Some(Cmd::Mcp) => {
            mcp::run_stdio()?;
            Ok(0)
        }
    }
}

fn emit_list(opts: &QueryOpts, json: bool, color: bool) -> Result<i32> {
    let report = list_listening(opts)?;
    if json {
        emit_json(&report)?;
    } else {
        emit(&render::list(&report, color))?;
    }
    Ok(0)
}

fn color_enabled(cli: &Cli) -> bool {
    !cli.json
        && !cli.no_color
        && std::env::var_os("NO_COLOR").is_none()
        && io::stdout().is_terminal()
}

fn emit(text: &str) -> Result<()> {
    let mut out = io::stdout();
    if let Err(err) = writeln!(out, "{text}") {
        if err.kind() == io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(err.into());
    }
    Ok(())
}

fn emit_json<T: Serialize>(value: &T) -> Result<()> {
    emit(&serde_json::to_string_pretty(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_query_and_kill_parse() {
        let cli = Cli::try_parse_from(["whose", ":3000", "--json"]).unwrap();
        assert!(cli.json);
        assert_eq!(cli.port.as_deref(), Some(":3000"));
        assert!(cli.command.is_none());

        let cli =
            Cli::try_parse_from(["whose", "kill", ":3000", "--yes", "--grace-ms", "500"]).unwrap();
        match cli.command {
            Some(Cmd::Kill {
                port,
                yes,
                grace_ms,
                force,
                dry_run,
                tree,
            }) => {
                assert_eq!(port, ":3000");
                assert!(yes);
                assert!(!force);
                assert!(!dry_run);
                assert!(tree);
                assert_eq!(grace_ms, 500);
            }
            other => panic!("unexpected {other:?}"),
        }

        let cli = Cli::try_parse_from(["whose", "free", "3000"]).unwrap();
        assert!(matches!(cli.command, Some(Cmd::Kill { .. })));

        let cli = Cli::try_parse_from(["whose", "tui"]).unwrap();
        assert!(matches!(cli.command, Some(Cmd::Watch)));

        let cli =
            Cli::try_parse_from(["whose", "outbound", "--pid", "42", "--proc", "node"]).unwrap();
        match cli.command {
            Some(Cmd::Outbound {
                pid,
                process,
                inbound,
            }) => {
                assert_eq!(pid, Some(42));
                assert_eq!(process.as_deref(), Some("node"));
                assert!(!inbound);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
