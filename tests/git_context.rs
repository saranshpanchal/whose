#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use whose::{filter_env, find_git, load_process};

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn linked_worktree_and_secret_redaction() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Tmp(std::env::temp_dir().join(format!("whose-it-git-{nonce}")));
    let repo = root.0.join("repo");
    let git = repo.join(".git");
    let wt_git = git.join("worktrees").join("wt");
    let wt = root.0.join("wt");
    let sub = wt.join("subdir");
    fs::create_dir_all(&wt_git).unwrap();
    fs::create_dir_all(&sub).unwrap();
    fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(wt_git.join("HEAD"), "ref: refs/heads/feature\n").unwrap();
    fs::write(wt_git.join("commondir"), "../..\n").unwrap();
    fs::write(wt.join(".git"), format!("gitdir: {}\n", wt_git.display())).unwrap();

    let main = find_git(&repo).unwrap();
    assert_eq!(main.repo_name, "repo");
    assert_eq!(main.branch, "main");
    assert!(!main.detached);

    let linked = find_git(&sub).unwrap();
    assert_eq!(linked.repo_name, "repo");
    assert_eq!(linked.branch, "feature");
    assert_eq!(linked.repo_root, main.repo_root);
    assert_ne!(linked.worktree, linked.repo_root);

    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .current_dir(&sub)
        .env_clear()
        .env("PORT", "3000")
        .env("HOST", "127.0.0.1")
        .env("NODE_ENV", "test")
        .env("VITE_API_KEY", "super-secret-value")
        .env("NEXT_PUBLIC_URL", "http://localhost")
        .env(
            "DATABASE_URL",
            "postgres://user:super-secret-value@localhost/db",
        )
        .env("UNRELATED", "super-secret-value")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let proc = load_process(child.id()).unwrap();
    let cwd_git = find_git(std::path::Path::new(proc.cwd.as_deref().unwrap())).unwrap();
    assert_eq!(cwd_git.branch, "feature");
    assert_eq!(cwd_git.repo_name, "repo");
    let filtered = filter_env(&proc.environ, false);
    let blob = serde_json::to_string(&filtered).unwrap();
    assert!(blob.contains("3000"), "{blob}");
    assert!(blob.contains("http://localhost"), "{blob}");
    assert!(blob.contains("<redacted>"), "{blob}");
    assert!(!blob.contains("super-secret-value"), "{blob}");
    assert!(filtered
        .iter()
        .any(|item| item.key == "VITE_API_KEY" && item.redacted));
    assert!(filtered
        .iter()
        .any(|item| item.key == "DATABASE_URL" && item.redacted));
    assert!(!filtered.iter().any(|item| item.key == "UNRELATED"));
    let _ = child.kill();
    let _ = child.wait();
}
