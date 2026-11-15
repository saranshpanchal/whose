use std::fs;
use std::path::{Component, Path, PathBuf};

use super::GitInfo;

/// Walk parents of `start` for a `.git` directory or a linked-worktree `.git` file.
pub fn find_git(start: &Path) -> Option<GitInfo> {
    let mut dir = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent()?.to_path_buf()
    };
    loop {
        let dot = dir.join(".git");
        if dot.exists() {
            return resolve(&dir, &dot);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn resolve(worktree: &Path, dot: &Path) -> Option<GitInfo> {
    let git_dir = if dot.is_dir() {
        dot.to_path_buf()
    } else {
        let text = fs::read_to_string(dot).ok()?;
        let line = text
            .lines()
            .find(|line| line.trim_start().starts_with("gitdir:"))?;
        let rel = line.trim().trim_start_matches("gitdir:").trim();
        if rel.is_empty() {
            return None;
        }
        let raw = PathBuf::from(rel);
        if raw.is_absolute() {
            raw
        } else {
            worktree.join(raw)
        }
    };
    let git_dir = normalize(&git_dir);
    let common = common_dir(&git_dir);
    let repo_root = if common.file_name().and_then(|n| n.to_str()) == Some(".git") {
        common.parent()?.to_path_buf()
    } else {
        common.clone()
    };
    let repo_root = normalize(&repo_root);
    let repo_name = repo_root.file_name()?.to_string_lossy().into_owned();
    let head_path = if git_dir.join("HEAD").is_file() {
        git_dir.join("HEAD")
    } else {
        common.join("HEAD")
    };
    let head = fs::read_to_string(head_path).ok()?;
    let head = head.trim();
    if head.is_empty() {
        return None;
    }
    let (branch, detached) = if let Some(rest) = head.strip_prefix("ref:") {
        let rest = rest.trim();
        let branch = rest.strip_prefix("refs/heads/").unwrap_or(rest);
        (branch.to_string(), false)
    } else {
        let short = if head.len() > 12 { &head[..12] } else { head };
        (short.to_string(), true)
    };
    Some(GitInfo {
        repo_name,
        repo_root: repo_root.to_string_lossy().into_owned(),
        worktree: normalize(worktree).to_string_lossy().into_owned(),
        branch,
        detached,
    })
}

fn common_dir(git_dir: &Path) -> PathBuf {
    let commondir = git_dir.join("commondir");
    if let Ok(text) = fs::read_to_string(commondir) {
        let rel = text.trim();
        if !rel.is_empty() {
            let raw = PathBuf::from(rel);
            let resolved = if raw.is_absolute() {
                raw
            } else {
                git_dir.join(raw)
            };
            return normalize(&resolved);
        }
    }
    if git_dir.file_name().and_then(|n| n.to_str()) == Some(".git") {
        return git_dir.to_path_buf();
    }
    if git_dir
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        == Some("worktrees")
    {
        if let Some(main) = git_dir.parent().and_then(|p| p.parent()) {
            return normalize(main);
        }
    }
    git_dir.to_path_buf()
}

fn normalize(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon;
    }
    clean(path)
}

fn clean(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn linked_worktree_branch_and_repo_name() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = Tmp(std::env::temp_dir().join(format!("whose-git-{nonce}")));
        let repo = root.0.join("repo");
        let git = repo.join(".git");
        let wt_git = git.join("worktrees").join("wt");
        let wt = root.0.join("wt");
        fs::create_dir_all(&wt_git).unwrap();
        fs::create_dir_all(wt.join("subdir")).unwrap();
        fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(wt_git.join("HEAD"), "ref: refs/heads/feature/one\n").unwrap();
        fs::write(wt_git.join("commondir"), "../..\n").unwrap();
        let gitdir = wt_git.display().to_string();
        fs::write(wt.join(".git"), format!("gitdir: {gitdir}\n")).unwrap();

        let main = find_git(&repo.join("src")).unwrap();
        assert_eq!(main.repo_name, "repo");
        assert_eq!(main.branch, "main");
        assert!(!main.detached);
        assert_eq!(main.worktree, main.repo_root);

        let linked = find_git(&wt.join("subdir")).unwrap();
        assert_eq!(linked.repo_name, "repo");
        assert_eq!(linked.branch, "feature/one");
        assert!(!linked.detached);
        assert_eq!(linked.repo_root, main.repo_root);
        assert_ne!(linked.worktree, linked.repo_root);
        assert!(linked.worktree.ends_with("wt") || linked.worktree.ends_with("wt/"));
    }
}
