//! Canonical verification of this workspace: `cargo verify [GATE ...]`.
//!
//! The gates are the authority for what a change must pass. The workspace
//! is a library and keeps no lock file, so every gate resolves the newest
//! compatible dependencies, as a consumer would. The bare-metal check covers
//! exactly the
//! workspace packages whose manifest declares `[package.metadata.verify]
//! no-std = true`, once without features and once with all features, so a
//! new `no_std` crate is verified by declaring it rather than by editing a
//! list here. A gate that cannot run on this machine is reported as
//! unavailable, with the reason, and fails the verification like a failed
//! gate.

use serde_json::Value;
use std::{
    env,
    error::Error,
    ffi::OsString,
    fmt, fs,
    path::PathBuf,
    process::{Command, ExitCode},
    time::{Duration, Instant},
};

/// Bare-metal target that has `core` and `alloc` but no `std`.
const NO_STD_TARGET: &str = "x86_64-unknown-none";

/// One verification gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    Format,
    Build,
    Test,
    Clippy,
    Doc,
    NoStd,
}

impl Gate {
    const ALL: [Self; 6] = [
        Self::Format,
        Self::Build,
        Self::Test,
        Self::Clippy,
        Self::Doc,
        Self::NoStd,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Format => "fmt",
            Self::Build => "build",
            Self::Test => "test",
            Self::Clippy => "clippy",
            Self::Doc => "doc",
            Self::NoStd => "no-std",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|gate| gate.name() == text)
    }

    /// The cargo invocations of the gate, given the declared `no_std`
    /// packages.
    fn invocations(self, no_std: &[String]) -> Vec<Vec<String>> {
        let words = |text: &str| text.split(' ').map(str::to_owned).collect::<Vec<_>>();
        match self {
            Self::Format => vec![words("fmt --all --check")],
            Self::Build => vec![words("build --workspace")],
            Self::Test => vec![words("test --workspace --all-features")],
            Self::Clippy => vec![words(
                "clippy --workspace --all-targets --all-features -- -D warnings",
            )],
            Self::Doc => vec![
                [
                    words("doc --workspace --no-deps --all-features --config"),
                    vec!["build.rustdocflags=['-Dwarnings']".to_owned()],
                ]
                .concat(),
            ],
            Self::NoStd => {
                let check = |features: &[&str]| {
                    let mut args = words("check --lib --target");
                    args.push(NO_STD_TARGET.to_owned());
                    args.extend(features.iter().map(|feature| (*feature).to_owned()));
                    for package in no_std {
                        args.push("-p".to_owned());
                        args.push(package.clone());
                    }
                    args
                };
                vec![check(&[]), check(&["--all-features"])]
            }
        }
    }
}

/// Result of one gate.
#[derive(Debug)]
enum Verdict {
    Passed,
    Failed(String),
    Unavailable(String),
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed => f.write_str("passed"),
            Self::Failed(reason) => write!(f, "FAILED: {reason}"),
            Self::Unavailable(reason) => write!(f, "NOT RUN: {reason}"),
        }
    }
}

fn cargo() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// Workspace packages that declare `[package.metadata.verify] no-std = true`.
fn no_std_packages() -> Result<Vec<String>, Box<dyn Error>> {
    let output = Command::new(cargo())
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("cargo metadata has no package list")?;
    let mut declared = Vec::new();
    for package in packages {
        let flag = package.pointer("/metadata/verify/no-std");
        if flag.is_none() {
            continue;
        }
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or("a package has no name")?;
        if flag != Some(&Value::Bool(true)) {
            return Err(format!("{name}: [package.metadata.verify] no-std must be true").into());
        }
        let has_lib = package
            .get("targets")
            .and_then(Value::as_array)
            .is_some_and(|targets| {
                targets.iter().any(|target| {
                    target
                        .get("kind")
                        .and_then(Value::as_array)
                        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "lib"))
                })
            });
        if !has_lib {
            return Err(format!("{name} declares no-std but has no library target").into());
        }
        declared.push(name.to_owned());
    }
    if declared.is_empty() {
        return Err("no package declares [package.metadata.verify] no-std = true".into());
    }
    Ok(declared)
}

/// Why the bare-metal target cannot be checked here, if it cannot.
fn no_std_target_missing() -> Option<String> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let libdir = Command::new(rustc)
        .args(["--print", "target-libdir", "--target", NO_STD_TARGET])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()));
    let installed = libdir
        .and_then(|libdir| fs::read_dir(libdir).ok())
        .is_some_and(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().starts_with("libcore-"))
        });
    (!installed).then(|| {
        format!("the {NO_STD_TARGET} standard library is not installed (rustup target add {NO_STD_TARGET})")
    })
}

fn run(gate: Gate, no_std: &[String]) -> Verdict {
    if gate == Gate::NoStd
        && let Some(reason) = no_std_target_missing()
    {
        return Verdict::Unavailable(reason);
    }
    for args in gate.invocations(no_std) {
        println!("verify: cargo {}", args.join(" "));
        match Command::new(cargo()).args(&args).status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                return Verdict::Failed(format!("cargo {} exited with {status}", args.join(" ")));
            }
            Err(error) => return Verdict::Unavailable(format!("cannot start cargo: {error}")),
        }
    }
    Verdict::Passed
}

fn usage() -> String {
    let names: Vec<_> = Gate::ALL.iter().map(|gate| gate.name()).collect();
    format!(
        "cargo verify [GATE ...]\nGATE: {}\nWithout gates, every gate runs in this order.",
        names.join(", ")
    )
}

fn main() -> ExitCode {
    let mut gates = Vec::new();
    for arg in env::args().skip(1) {
        match Gate::parse(&arg) {
            Some(gate) => gates.push(gate),
            None => {
                eprintln!("unknown gate {arg:?}\n{}", usage());
                return ExitCode::FAILURE;
            }
        }
    }
    if gates.is_empty() {
        gates = Gate::ALL.to_vec();
    }
    let no_std = if gates.contains(&Gate::NoStd) {
        match no_std_packages() {
            Ok(packages) => packages,
            Err(error) => {
                eprintln!("verify: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        Vec::new()
    };
    let mut results: Vec<(Gate, Verdict, Duration)> = Vec::new();
    for gate in gates {
        let started = Instant::now();
        let verdict = run(gate, &no_std);
        results.push((gate, verdict, started.elapsed()));
    }
    println!();
    for (gate, verdict, elapsed) in &results {
        println!(
            "verify: {:<7} {verdict} ({:.1} s)",
            gate.name(),
            elapsed.as_secs_f64()
        );
    }
    if results
        .iter()
        .all(|(_, verdict, _)| matches!(verdict, Verdict::Passed))
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
