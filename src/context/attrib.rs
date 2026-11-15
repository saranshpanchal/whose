use super::{EnvPair, SupervisorInfo};

/// Facts used to attribute a process to systemd, compose, pm2, or a container.
pub struct SupervisorFacts<'a> {
    pub comm: &'a str,
    pub args0: &'a str,
    pub exe: &'a str,
    /// Full command line, used to recognize `docker-proxy` flags.
    pub cmdline: &'a str,
    pub cgroup: &'a str,
    pub environ: &'a [(String, String)],
    pub ancestry_comms: &'a [String],
    pub self_cgroup: &'a str,
}

pub fn filter_env(env: &[(String, String)], show_secrets: bool) -> Vec<EnvPair> {
    let mut out = Vec::new();
    for (key, value) in env {
        if !is_allowlisted(key) {
            continue;
        }
        let secret = is_secret_key(key);
        if secret && !show_secrets {
            out.push(EnvPair {
                key: key.clone(),
                value: "<redacted>".to_string(),
                redacted: true,
            });
        } else {
            out.push(EnvPair {
                key: key.clone(),
                value: value.clone(),
                redacted: false,
            });
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

fn is_allowlisted(key: &str) -> bool {
    matches!(
        key,
        "PORT" | "HOST" | "NODE_ENV" | "VIRTUAL_ENV" | "DATABASE_URL"
    ) || key.starts_with("VITE_")
        || key.starts_with("NEXT_")
}

fn is_secret_key(key: &str) -> bool {
    key == "DATABASE_URL"
        || key.ends_with("_KEY")
        || key.ends_with("_SECRET")
        || key.ends_with("_TOKEN")
        || key.ends_with("_PASSWORD")
        || key.ends_with("_PASSWD")
}

pub fn classify(facts: &SupervisorFacts<'_>) -> Option<SupervisorInfo> {
    if let Some(info) = docker_proxy(facts) {
        return Some(info);
    }
    if let Some(info) = compose(facts) {
        return Some(info);
    }
    if let Some(info) = pm2(facts) {
        return Some(info);
    }
    if let Some(info) = systemd(facts) {
        return Some(info);
    }
    container(facts)
}

fn docker_proxy(facts: &SupervisorFacts<'_>) -> Option<SupervisorInfo> {
    let base_comm = base_name(facts.comm);
    let base_arg = base_name(facts.args0);
    let base_exe = base_name(facts.exe);
    if base_comm != "docker-proxy" && base_arg != "docker-proxy" && base_exe != "docker-proxy" {
        return None;
    }
    let ip = extract_flag(facts.cmdline, "-container-ip");
    let port = extract_flag(facts.cmdline, "-container-port");
    let detail = match (ip.as_deref(), port.as_deref()) {
        (Some(ip), Some(port)) => format!("container {ip}:{port}"),
        (Some(ip), None) => format!("container {ip}"),
        _ => "docker userland proxy".to_string(),
    };
    Some(SupervisorInfo {
        kind: "docker-proxy".to_string(),
        name: ip.unwrap_or_else(|| "docker-proxy".to_string()),
        stop: "docker ps --format '{{.ID}} {{.Ports}}' && docker stop <id>".to_string(),
        detail,
        blocks_kill: true,
    })
}

fn extract_flag(cmdline: &str, flag: &str) -> Option<String> {
    let mut parts = cmdline.split_whitespace();
    while let Some(part) = parts.next() {
        if part == flag {
            return parts.next().map(|s| s.to_string());
        }
        if let Some(value) = part.strip_prefix(&format!("{flag}=")) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn compose(facts: &SupervisorFacts<'_>) -> Option<SupervisorInfo> {
    let project = env_get(facts.environ, "COMPOSE_PROJECT_NAME")?;
    let service = env_get(facts.environ, "COMPOSE_SERVICE");
    let remote = !same_cgroup(facts.cgroup, facts.self_cgroup);
    let stop = match &service {
        Some(service) => format!("docker compose -p {project} stop {service}"),
        None => format!("docker compose -p {project} stop"),
    };
    let detail = match &service {
        Some(service) => format!("compose project {project} service {service}"),
        None => format!("compose project {project}"),
    };
    Some(SupervisorInfo {
        kind: "compose".to_string(),
        name: service.unwrap_or(project.clone()),
        stop,
        detail,
        blocks_kill: remote,
    })
}

fn pm2(facts: &SupervisorFacts<'_>) -> Option<SupervisorInfo> {
    let home = env_get(facts.environ, "PM2_HOME");
    let named = is_pm2_name(facts.comm)
        || is_pm2_name(facts.args0)
        || is_pm2_name(facts.exe)
        || facts.ancestry_comms.iter().any(|c| is_pm2_name(c));
    if home.is_none() && !named {
        return None;
    }
    let name = base_name(facts.comm).to_string();
    Some(SupervisorInfo {
        kind: "pm2".to_string(),
        name: name.clone(),
        stop: format!("pm2 stop {name}"),
        detail: match home {
            Some(home) => format!("PM2_HOME={home}"),
            None => "pm2 process ancestry".to_string(),
        },
        blocks_kill: true,
    })
}

fn systemd(facts: &SupervisorFacts<'_>) -> Option<SupervisorInfo> {
    let unit = specific_service(facts.cgroup)?;
    let user = facts.cgroup.contains("/user.slice/") || facts.cgroup.contains("user@");
    let stop = if user {
        format!("systemctl --user stop {unit}")
    } else {
        format!("systemctl stop {unit}")
    };
    Some(SupervisorInfo {
        kind: "systemd".to_string(),
        name: unit.clone(),
        stop,
        detail: format!("cgroup unit {unit}"),
        blocks_kill: true,
    })
}

fn container(facts: &SupervisorFacts<'_>) -> Option<SupervisorInfo> {
    let lower = facts.cgroup.to_ascii_lowercase();
    let (kind, tool) = if lower.contains("libpod") || lower.contains("/podman") {
        ("podman", "podman")
    } else if lower.contains("containerd") {
        ("containerd", "docker")
    } else if lower.contains("docker") {
        ("docker", "docker")
    } else if lower.contains("kubepods") {
        ("kubernetes", "kubectl")
    } else {
        return None;
    };
    let remote = !same_cgroup(facts.cgroup, facts.self_cgroup);
    // Same cgroup as us means we are inside that container too. Show the
    // attribution, but do not block a kill of a sibling dev server.
    if !remote && kind != "kubernetes" {
        let id = hex_run(&lower).unwrap_or_default();
        let name = short_id(&id);
        return Some(SupervisorInfo {
            kind: kind.to_string(),
            name: name.clone(),
            stop: format!("{tool} stop {name}"),
            detail: "same cgroup as whose; kill is a local process signal".to_string(),
            blocks_kill: false,
        });
    }
    let id = hex_run(&lower).unwrap_or_default();
    let name = if id.is_empty() {
        kind.to_string()
    } else {
        short_id(&id)
    };
    let stop = match kind {
        "kubernetes" => format!("kubectl delete pod {name}"),
        "podman" => format!("podman stop {name}"),
        _ => format!("docker stop {name}"),
    };
    Some(SupervisorInfo {
        kind: kind.to_string(),
        name,
        stop,
        detail: "process cgroup is a different container than whose".to_string(),
        blocks_kill: true,
    })
}

fn specific_service(cgroup: &str) -> Option<String> {
    let mut units = Vec::new();
    for part in cgroup.split(['/', '\n', ':']) {
        if part.ends_with(".service") && !part.starts_with("user@") {
            units.push(part.to_string());
        }
    }
    units.pop()
}

fn same_cgroup(target: &str, ours: &str) -> bool {
    normalize_cgroup(target) == normalize_cgroup(ours)
}

fn normalize_cgroup(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn env_get(env: &[(String, String)], key: &str) -> Option<String> {
    env.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
}

fn is_pm2_name(value: &str) -> bool {
    base_name(value).eq_ignore_ascii_case("pm2")
}

fn base_name(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value).trim()
}

fn hex_run(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut best: Option<(usize, usize)> = None;
    while index < bytes.len() {
        if bytes[index].is_ascii_hexdigit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                index += 1;
            }
            if index - start >= 12 && best.map(|(s, e)| e - s < index - start).unwrap_or(true) {
                best = Some((start, index));
            }
        } else {
            index += 1;
        }
    }
    best.map(|(start, end)| text[start..end].to_string())
}

fn short_id(id: &str) -> String {
    if id.len() > 12 {
        id[..12].to_string()
    } else {
        id.to_string()
    }
}

/// Names that should not be signaled without an explicit `--yes`.
pub fn is_sensitive_daemon(comm: &str, args0: &str, exe: &str) -> bool {
    const NAMES: &[&str] = &[
        "postgres",
        "postmaster",
        "mysqld",
        "mariadbd",
        "mongod",
        "redis-server",
        "valkey-server",
        "memcached",
        "clickhouse-server",
        "influxd",
        "cockroach",
        "rabbitmq-server",
        "dockerd",
        "containerd",
        "containerd-shim",
        "kubelet",
        "sshd",
    ];
    [comm, args0, exe].into_iter().any(|value| {
        let base = base_name(value);
        NAMES.iter().any(|name| base.eq_ignore_ascii_case(name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(
        comm: &'a str,
        args0: &'a str,
        cgroup: &'a str,
        env: &'a [(String, String)],
        ancestry: &'a [String],
        self_cgroup: &'a str,
    ) -> SupervisorFacts<'a> {
        SupervisorFacts {
            comm,
            args0,
            exe: args0,
            cmdline: comm,
            cgroup,
            environ: env,
            ancestry_comms: ancestry,
            self_cgroup,
        }
    }

    #[test]
    fn redacts_allowlisted_secrets_and_database_url() {
        let env = vec![
            ("PORT".into(), "3000".into()),
            ("NODE_ENV".into(), "test".into()),
            ("VITE_API_KEY".into(), "super-secret-value".into()),
            ("NEXT_PUBLIC_URL".into(), "http://localhost".into()),
            (
                "DATABASE_URL".into(),
                "postgres://user:super-secret-value@localhost/db".into(),
            ),
            ("UNRELATED".into(), "super-secret-value".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "super-secret-value".into()),
            ("HOST".into(), "127.0.0.1".into()),
        ];
        let filtered = filter_env(&env, false);
        let blob = serde_json::to_string(&filtered).unwrap();
        assert!(!blob.contains("super-secret-value"));
        assert!(blob.contains("3000"));
        assert!(blob.contains("http://localhost"));
        assert!(blob.contains("<redacted>"));
        assert!(filtered
            .iter()
            .any(|e| e.key == "VITE_API_KEY" && e.redacted));
        assert!(filtered
            .iter()
            .any(|e| e.key == "DATABASE_URL" && e.redacted));
        assert!(!filtered.iter().any(|e| e.key == "UNRELATED"));
        assert!(!filtered.iter().any(|e| e.key == "AWS_SECRET_ACCESS_KEY"));

        let shown = filter_env(&env, true);
        let raw = serde_json::to_string(&shown).unwrap();
        assert!(raw.contains("super-secret-value"));
        assert!(shown.iter().any(|e| e.key == "DATABASE_URL" && !e.redacted));
    }

    #[test]
    fn docker_proxy_and_systemd_block_pm2_blocks_compose_same_cgroup_does_not() {
        let proxy = classify(&facts(
            "docker-proxy -proto tcp -host-port 3000 -container-ip 172.17.0.2 -container-port 3000",
            "docker-proxy",
            "0::/system.slice/docker.service",
            &[],
            &[],
            "0::/user.slice/session.scope",
        ))
        .unwrap();
        assert_eq!(proxy.kind, "docker-proxy");
        assert!(proxy.blocks_kill);
        assert!(proxy.detail.contains("172.17.0.2"));

        let unit = classify(&facts(
            "nginx",
            "nginx",
            "0::/system.slice/nginx.service",
            &[],
            &[],
            "0::/user.slice/user-1000.slice/session-3.scope",
        ))
        .unwrap();
        assert_eq!(unit.kind, "systemd");
        assert_eq!(unit.name, "nginx.service");
        assert!(unit.blocks_kill);
        assert!(unit.stop.contains("systemctl stop nginx.service"));

        let session = classify(&facts(
            "node",
            "node",
            "0::/user.slice/user-1000.slice/user@1000.service/session-3.scope",
            &[],
            &[],
            "0::/user.slice/user-1000.slice/user@1000.service/session-3.scope",
        ));
        assert!(session.is_none());

        let env = vec![
            ("COMPOSE_PROJECT_NAME".into(), "app".into()),
            ("COMPOSE_SERVICE".into(), "web".into()),
        ];
        let inside = classify(&facts(
            "node",
            "node",
            "0::/system.slice/docker-abc.scope",
            &env,
            &[],
            "0::/system.slice/docker-abc.scope",
        ))
        .unwrap();
        assert_eq!(inside.kind, "compose");
        assert!(!inside.blocks_kill);
        assert!(inside.stop.contains("docker compose -p app stop web"));

        let outside = classify(&facts(
            "node",
            "node",
            "0::/docker/0123456789abcdef0123456789abcdef",
            &env,
            &[],
            "0::/user.slice/session.scope",
        ))
        .unwrap();
        assert_eq!(outside.kind, "compose");
        assert!(outside.blocks_kill);

        let pm2_env = vec![("PM2_HOME".into(), "/home/dev/.pm2".into())];
        let pm2 = classify(&facts(
            "node",
            "node",
            "0::/user.slice/session.scope",
            &pm2_env,
            &[],
            "0::/user.slice/session.scope",
        ))
        .unwrap();
        assert_eq!(pm2.kind, "pm2");
        assert!(pm2.blocks_kill);
    }

    #[test]
    fn sensitive_daemons_match_exe_basename() {
        assert!(is_sensitive_daemon("postgres", "postgres", ""));
        assert!(is_sensitive_daemon(
            "postgres",
            "/usr/lib/postgresql/16/bin/postgres",
            ""
        ));
        assert!(!is_sensitive_daemon("node", "node", "/usr/bin/node"));
    }
}
