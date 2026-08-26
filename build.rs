// Copyright (c) 2026 渟雲. All rights reserved.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn wdk_root_from_registry() -> Option<String> {
    let roots = [
        r"HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots",
    ];
    for root in roots {
        let out = Command::new("reg")
            .args(["query", root, "/v", "KitsRoot10"])
            .output()
            .ok()?;
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("KitsRoot10") {
                if let Some((_, val)) = line.split_once("REG_SZ") {
                    let p = val.trim().trim_end_matches('\\');
                    if !p.is_empty() {
                        return Some(p.to_string());
                    }
                }
            }
        }
    }
    None
}

fn latest_version(root: &Path) -> Option<String> {
    let inc = root.join("Include");
    let mut versions: Vec<String> = Vec::new();
    if let Ok(rd) = fs::read_dir(&inc) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("10.") && e.path().join("km").is_dir() {
                versions.push(n);
            }
        }
    }
    versions.sort();
    versions.pop()
}

fn main() {
    let wdk_root = PathBuf::from(wdk_root_from_registry().expect("failed to locate WDK"));

    let wdk_ver = latest_version(&wdk_root).expect("no 10.* SDK version dirs under WDK root");

    let km_lib = wdk_root.join("Lib").join(&wdk_ver).join("km").join("x64");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!("cargo:rustc-link-search=native={}", km_lib.display());
    println!("cargo:rustc-link-lib=ntoskrnl");
    println!("cargo:rustc-link-lib=libcntpr");

    println!("cargo:rustc-link-arg=/DRIVER");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB");
    println!("cargo:rustc-link-arg=/SUBSYSTEM:NATIVE");
    println!("cargo:rustc-link-arg=/ENTRY:usugumo_entry");
    println!("cargo:rustc-link-arg=/MACHINE:X64");
    println!("cargo:rustc-link-arg=/IGNORE:4257");
    println!("cargo:rustc-link-arg=/IGNORE:4216");
    println!("cargo:rustc-link-arg=/INCREMENTAL:NO");
    println!(
        "cargo:rustc-link-arg=/MAP:{}",
        manifest.join("target").join("usugumo.map").display()
    );
}
