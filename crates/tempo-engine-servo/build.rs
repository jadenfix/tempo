use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    println!("cargo:rustc-check-cfg=cfg(tempo_servo_fork_source)");
    println!("cargo:rustc-check-cfg=cfg(tempo_servo_fork_lock_checked)");

    let Ok(source) = fs::read_to_string("src/lib.rs") else {
        return;
    };
    let Some(expected_repo) = rust_str_const(&source, "TEMPO_SERVO_FORK_REPOSITORY") else {
        return;
    };
    let Some(expected_rev) = rust_str_const(&source, "TEMPO_SERVO_FORK_REVISION") else {
        return;
    };

    if env::var_os("CARGO_FEATURE_SERVO_TEMPO").is_some() {
        validate_servo_lock_source(&expected_repo, &expected_rev).unwrap_or_else(|error| {
            panic!("servo-tempo requires the pinned Tempo Servo fork patch: {error}");
        });
        println!("cargo:rustc-cfg=tempo_servo_fork_source");
        println!("cargo:rustc-cfg=tempo_servo_fork_lock_checked");
    }
}

fn rust_str_const(source: &str, name: &str) -> Option<String> {
    let prefix = format!("pub const {name}: &str = \"");
    source.lines().find_map(|line| {
        let value = line.trim().strip_prefix(&prefix)?;
        Some(value.strip_suffix("\";")?.to_string())
    })
}

fn validate_servo_lock_source(expected_repo: &str, expected_rev: &str) -> Result<(), String> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map_err(|error| format!("CARGO_MANIFEST_DIR is unavailable: {error}"))?;
    let lock_path = find_workspace_lock(&manifest_dir).ok_or_else(|| {
        "Cargo.lock was not found; run through Cargo with the fork patch".to_string()
    })?;
    let lock = fs::read_to_string(&lock_path)
        .map_err(|error| format!("failed to read {}: {error}", lock_path.display()))?;
    let source = servo_package_source(&lock).ok_or_else(|| {
        format!(
            "{} does not contain a resolved servo package source",
            lock_path.display()
        )
    })?;
    if !source.contains(expected_repo) {
        return Err(format!(
            "resolved servo source is {source:?}, expected repository {expected_repo:?}"
        ));
    }
    if !source.contains(expected_rev) {
        return Err(format!(
            "resolved servo source is {source:?}, expected revision {expected_rev:?}"
        ));
    }
    Ok(())
}

fn find_workspace_lock(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|path| path.join("Cargo.lock"))
        .find(|path| path.is_file())
}

fn servo_package_source(lock: &str) -> Option<String> {
    for package in lock.split("[[package]]").skip(1) {
        let mut is_servo = false;
        let mut source = None;
        for line in package.lines().map(str::trim) {
            if line == "name = \"servo\"" {
                is_servo = true;
            } else if let Some(value) = line.strip_prefix("source = \"") {
                source = value.strip_suffix('"').map(ToOwned::to_owned);
            }
        }
        if is_servo {
            return source;
        }
    }
    None
}
