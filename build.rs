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

    let km_inc = wdk_root.join("Include").join(&wdk_ver).join("km");
    let shared_inc = wdk_root.join("Include").join(&wdk_ver).join("shared");
    let um_inc = wdk_root.join("Include").join(&wdk_ver).join("um");
    let km_lib = wdk_root.join("Lib").join(&wdk_ver).join("km").join("x64");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let csrc = manifest.join("csrc");
    let includes = manifest.join("includes");

    println!("cargo:rerun-if-changed={}", csrc.display());
    println!("cargo:rerun-if-changed={}", includes.display());

    let mut c_srcs = Vec::new();
    let mut asm_srcs = Vec::new();
    for entry in fs::read_dir(&csrc).expect("csrc dir must exist") {
        let path = entry.expect("read_dir entry").path();
        match path.extension().and_then(|e| e.to_str()) {
            Some("c") => c_srcs.push(path),
            Some("asm") => asm_srcs.push(path),
            _ => {}
        }
    }
    c_srcs.sort();
    asm_srcs.sort();

    let mut c = cc::Build::new();
    c.include(&km_inc)
        .include(&shared_inc)
        .include(&um_inc)
        .include(&includes);
    c.define("_AMD64_", None);
    c.define("_KERNEL_MODE", None);
    c.define("DEPRECATE_DDK_FUNCTIONS", None);
    c.define("_WIN32_WINNT", Some("0x0A00"));
    c.flag("/std:c17").flag("/utf-8").flag("/GS-").flag("/O2");
    c.static_crt(true);
    c.files(&c_srcs);
    c.compile("usugumo_c");

    let mut asm = cc::Build::new();
    asm.include(&km_inc)
        .include(&shared_inc)
        .include(&um_inc)
        .include(&includes);
    asm.define("_AMD64_", None);
    asm.define("_KERNEL_MODE", None);
    asm.files(&asm_srcs);
    asm.compile("usugumo_asm");

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
}
