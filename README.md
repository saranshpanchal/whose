# whose

Whose port or socket is this? (`whose :3000`)

`whose` is a fast, unprivileged, Linux-first CLI for the case where several coding agents, in separate git worktrees, are all fighting over `:3000`. It tells you who owns a localhost port (repo, worktree, branch, process ancestry, supervisor or container, uptime, memory, TCP stats), lists outbound sockets with the same stats, and frees a port without blindly `SIGKILL`ing one child.

## Install

```bash
cargo install --path .
# or
cargo build --release
./target/release/whose --help
```

Rust 1.74 or newer. The useful path is Linux. On macOS the same binary builds and shells out to `lsof` or `netstat`; it will not have `tcp_info`.

## Usage

```bash
whose :3000                 # who is listening, with ancestry and worktree
whose 3000                  # same
whose 3000-3010             # inclusive range
whose                       # listening sockets grouped by worktree
whose ls
whose outbound              # ESTABLISHED, SYN_SENT, CLOSE_WAIT, TIME_WAIT
whose outbound --pid 4242
whose outbound --proc node
whose kill :3000            # SIGTERM the process group, then SIGKILL if needed
whose free :3000 --yes      # alias of kill; --yes confirms shared daemons
whose watch                 # live TUI (alias: whose tui)
whose serve --port 7070     # 127.0.0.1 dashboard
whose mcp                   # stdio MCP server
whose :3000 --json
```

`whose kill` sends `SIGTERM` to the listener's **process group** (parent and children that share the group), polls sock_diag every 50 ms, and escalates to `SIGKILL` only if the port is still in `LISTEN` after the grace period (default 2000 ms, `--grace-ms`).

It will not signal pid 1, its own process, an ancestor, its own process group, or the session leader. Another user's process, and anything supervised by systemd, pm2, or `docker-proxy`, is reported with the clean stop command instead of a kill. Pass `--force` to signal those anyway. Databases and other shared daemons (`postgres`, `redis-server`, `sshd`, …) need `--yes`, or an interactive confirmation when stdin is a terminal.

Environment values shown next to a process are limited to `PORT`, `HOST`, `NODE_ENV`, `VIRTUAL_ENV`, `VITE_*`, `NEXT_*`, and `DATABASE_URL`. Keys ending in `_KEY`, `_SECRET`, `_TOKEN`, or `_PASSWORD`, plus `DATABASE_URL`, are replaced with `<redacted>` unless `--show-secrets` is set.

### TUI keys

| Key | Action |
| --- | --- |
| `j` / `↓` | next row |
| `u` / `↑` | previous row |
| `/` | filter, `Esc` clears, `Enter` applies |
| `Enter` | toggle the detail pane |
| `o` | toggle outbound sockets |
| `k` then `y` | SIGTERM the selected listener's process group |
| `q` | quit |

### Dashboard

`whose serve` binds **127.0.0.1 only** and serves a single HTML page that polls `/api/topology`. Also available: `/api/ports`, `/api/outbound`.

### MCP

`whose mcp` speaks JSON-RPC 2.0 on stdio. Newline framing and `Content-Length` framing both work. Tools:

| Tool | What it does |
| --- | --- |
| `whose_port` | Inspect one port or a range. `port` is a number or string. |
| `whose_list_ports` | Listening sockets grouped by worktree. |
| `whose_outbound_sockets` | Outbound sockets. Optional `pid`, `process`. |
| `whose_free_port` | Same policy as `whose kill`. **Does nothing unless `yes` is true.** Supervised targets also need `force`. |

```json
{ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": { "name": "example", "version": "0" } } }
{ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "whose_port", "arguments": { "port": 3000 } } }
```

## Privilege model

No root, no raw sockets, no packet capture, no setuid helper.

On Linux the socket table comes from `NETLINK_SOCK_DIAG` (`SOCK_DIAG_BY_FAMILY` for `AF_INET` and `AF_INET6`, TCP and UDP). Requesting `INET_DIAG_INFO` returns `struct tcp_info`, including `tcpi_rtt`, `tcpi_total_retrans`, `tcpi_bytes_acked`, and `tcpi_bytes_received`, for sockets in the caller's network namespace. An unprivileged user can read those counters; `ss -i` uses the same interface.

Ownership is a join on the socket inode. One pass over `/proc/<pid>/fd` builds `inode → pids` from `socket:[inode]` links. Command line, cwd, exe, start time, RSS, cgroup, and environ come from the same `/proc` tree. `/proc` entries we cannot read are skipped; the socket is still shown, with the uid from sock_diag and `owner_status` of `unknown` or `other-uid`.

Git context walks up from the process cwd. A `.git` directory is the main worktree. A `.git` file (`gitdir: …`) is a linked worktree; the branch is read from that gitdir's `HEAD`, and the repo name comes from the common git directory (`commondir`).

Nothing in this tool shells out to `lsof` or `ss` on Linux unless sock_diag itself fails. The fallback parser exists so the crate builds on macOS and other targets.

## How this is positioned

| Tool | Unprivileged per-socket RTT / bytes | Repo and worktree | Safe free |
| --- | --- | --- | --- |
| **whose** | Yes, via sock_diag `INET_DIAG_INFO` | Yes, from cwd | Process group, supervisor-aware |
| `ss` / `lsof` | `ss -i` has the counters; no project context | No | No |
| Sonar / raskrebs | eBPF, often privileged | No | No |
| portless | Shares a port through a proxy; it does not answer who owns it | n/a | n/a |
| procs | Process list, not sockets | cwd only | No |
| bandwhich | Bandwidth, often root | No | No |
| Little Snitch | macOS, commercial, not a port-ownership CLI | No | No |
| RustNet | Rust traffic monitor | Limited | No |

The gap is the join: socket stats and "which worktree's agent is this?" in one unprivileged query.

## Layout

```
src/netlink/    SOCK_DIAG_BY_FAMILY, tcp_info parse, lsof/ss/netstat fallback
src/proc/       /proc stat, status, fd, cmdline, cwd, environ, cgroup
src/context/    ancestry, git worktree, cgroup/compose/pm2, env redaction
src/kill/       process-group SIGTERM → poll → SIGKILL, with refusals
src/outbound/   established sockets, CLOSE_WAIT and wildcard warnings
src/tui/        ratatui dashboard
src/web/        axum loopback page
src/mcp.rs      stdio JSON-RPC
src/cli.rs      clap
```

## Limitations

- **Other uids.** `tcp_info` is collected for every socket sock_diag returns. Mapping that socket to a pid needs `/proc/<pid>/fd`, which is often hidden for other users (`hidepid`, Yama ptrace scope). You still see the socket and the uid.
- **UDP diag is optional.** TCP always comes from sock_diag (`CONFIG_INET_TCP_DIAG`). UDP uses the same request, and when the kernel was built without `CONFIG_INET_UDP_DIAG` the UDP rows are filled from `/proc/net/udp` and `/proc/net/udp6` (address, state, uid, inode). UDP has no `tcp_info`.
- **Other network namespaces.** Containers with their own netns are invisible. On the host you usually see `docker-proxy`; `whose` reports that and the `docker stop` path instead of killing the proxy (it would respawn).
- **`idiag_inode` is 32-bit.** Inodes that do not fit are not representable in the classic inet_diag header.
- **`IPV6_V6ONLY` does not fit in the `u8` extension bitmask** (`INET_DIAG_SKV6ONLY` is bit 10). If the kernel includes the attribute we honor it. Otherwise a socket that appears in both the IPv4 and IPv6 dumps under one inode is treated as dual-stack.
- **Full `/proc` walk.** The sock_diag dump itself is the fast part (the target is a few milliseconds). Walking every process fd table is what dominates on a machine with a huge process list, and the 50 ms kill poll uses sock_diag only so it does not repeat that walk.
- **Process group kill.** `SIGTERM` goes to the listener's group, not to one child. A dev runner that shares the group (`npm` in the same group as `node`) receives it too. We do not walk the tree and `SIGKILL` children one by one.
- **Same-cgroup containers.** Compose / docker attribution is shown even when `whose` is inside the same container. Kill is allowed there, because the process will not be respawned by the runtime just because it shares a cgroup. systemd, pm2, and `docker-proxy` still block without `--force`.
- **macOS.** No `tcp_info`. Addresses and pids come from `lsof -F` or `netstat`.

## Tests

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

Integration tests on Linux cover ephemeral TCP and UDP listeners (pid, cmdline, cwd, inode), a hand-built linked worktree plus secret redaction through `/proc/<pid>/environ`, an established local connection's `tcp_info`, `whose` freeing a forked parent+child process group, the MCP stdio round trip, and the loopback dashboard.
