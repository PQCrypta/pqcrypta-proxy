//! Records the commit a binary is built from, so `--version` names it.
//!
//! The benchmark exports took the commit as a typed argument, and one run was
//! published naming a binary-hash prefix that no repository had: the page's
//! "changes since" listing could not resolve it and read as "nothing changed".
//! The exports now read the commit from `--version` and refuse a mismatch.
//! "-dirty" marks a build whose tracked sources differ from that commit.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    // A build with no git checkout -- the Docker image, whose context has no
    // .git -- is given the commit instead (a build argument in CI).
    println!("cargo:rerun-if-env-changed=PQCRYPTA_GIT_COMMIT");
    if let Some(given) = std::env::var("PQCRYPTA_GIT_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
    {
        let short: String = given.chars().take(7).collect();
        println!("cargo:rustc-env=PQCRYPTA_GIT_COMMIT={short}");
        return;
    }
    let commit = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = git(&[
        "status",
        "--porcelain",
        "--untracked-files=no",
        "--",
        "src",
        "vendor",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
    ])
    .is_some_and(|s| !s.is_empty());
    println!(
        "cargo:rustc-env=PQCRYPTA_GIT_COMMIT={commit}{}",
        if dirty { "-dirty" } else { "" }
    );
    // Rerun when HEAD moves or a tracked source changes. The git directory is
    // a submodule's, so ask git where it is.
    if let Some(dir) = git(&["rev-parse", "--git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={dir}/index");
        if let Some(head) = git(&["symbolic-ref", "-q", "HEAD"]) {
            println!("cargo:rerun-if-changed={dir}/{head}");
        }
    }
    for path in ["src", "vendor", "Cargo.toml", "Cargo.lock", "build.rs"] {
        println!("cargo:rerun-if-changed={path}");
    }
}
