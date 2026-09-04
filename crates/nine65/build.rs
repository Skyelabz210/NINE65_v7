//! Captures the commit this crate was built from, for archival bootstrap
//! tuple fingerprints (`keys::bootstrap::BootstrapTupleFingerprint`, WR-5B /
//! issue #83 requirement 4).
//!
//! Falls back to `"unknown"` rather than failing the build when `git` is
//! unavailable at build time (e.g. a source tarball with no `.git`, or a
//! sandboxed build environment without the `git` binary). Never a build
//! failure: a missing commit SHA is a provenance gap to report, not a
//! reason a security-critical crate should fail to compile.

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=NINE65_COMMIT_SHA={sha}");
}
