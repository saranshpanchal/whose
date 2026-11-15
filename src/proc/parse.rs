/// Fields we need from `/proc/<pid>/stat`. `comm` may contain spaces and parentheses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatFields {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub start_ticks: u64,
    pub rss_pages: u64,
}

pub fn parse_stat(text: &str) -> Option<StatFields> {
    let start = text.find('(')?;
    let end = text.rfind(')')?;
    if end <= start {
        return None;
    }
    let pid: u32 = text[..start].trim().parse().ok()?;
    let comm = text[start + 1..end].to_string();
    let rest: Vec<&str> = text[end + 1..].split_whitespace().collect();
    // state .. rss is 22 fields (indexes 0..=21).
    if rest.len() < 22 {
        return None;
    }
    let state = rest[0].chars().next()?;
    Some(StatFields {
        pid,
        comm,
        state,
        ppid: rest[1].parse().ok()?,
        pgrp: rest[2].parse().ok()?,
        session: rest[3].parse().ok()?,
        start_ticks: rest[19].parse().ok()?,
        rss_pages: rest[21].parse().ok()?,
    })
}

pub fn parse_uid(status: &str) -> Option<u32> {
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        return rest.split_whitespace().next()?.parse().ok();
    }
    None
}

pub fn parse_socket_inode(link: &str) -> Option<u64> {
    let rest = link.strip_prefix("socket:[")?.strip_suffix(']')?;
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

pub fn split_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

pub fn split_environ(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in bytes.split(|b| *b == 0) {
        if part.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(part);
        if let Some((key, value)) = text.split_once('=') {
            out.push((key.to_string(), value.to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rest_stat(
        comm: &str,
        ppid: &str,
        pgrp: &str,
        session: &str,
        start: &str,
        rss: &str,
    ) -> String {
        let fields = [
            "S", ppid, pgrp, session, "0", "-1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "20",
            "0", "1", "0", start, "0", rss,
        ];
        assert_eq!(fields.len(), 22);
        format!("42 ({comm}) {}", fields.join(" "))
    }

    #[test]
    fn stat_comm_with_parens_and_spaces() {
        let text = rest_stat("worker (renderer)", "7", "20", "20", "5000", "128");
        let stat = parse_stat(&text).unwrap();
        assert_eq!(stat.pid, 42);
        assert_eq!(stat.comm, "worker (renderer)");
        assert_eq!(stat.ppid, 7);
        assert_eq!(stat.pgrp, 20);
        assert_eq!(stat.session, 20);
        assert_eq!(stat.start_ticks, 5000);
        assert_eq!(stat.rss_pages, 128);
    }

    #[test]
    fn uid_and_socket_inode() {
        let status = "Name:\tnpm\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n";
        assert_eq!(parse_uid(status), Some(1000));
        assert_eq!(parse_socket_inode("socket:[99887]"), Some(99887));
        assert_eq!(parse_socket_inode("anon_inode:[eventfd]"), None);
    }

    #[test]
    fn cmdline_and_environ_are_nul_split() {
        let args = split_cmdline(b"node\0server.js\0");
        assert_eq!(args, vec!["node".to_string(), "server.js".to_string()]);
        let env = split_environ(b"PORT=3000\0EMPTY=\0NOEQ\0");
        assert_eq!(
            env,
            vec![
                ("PORT".to_string(), "3000".to_string()),
                ("EMPTY".to_string(), String::new())
            ]
        );
    }
}
