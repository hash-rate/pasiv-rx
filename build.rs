// Build tevador/RandomX (vendored, v1.2.1, BSD-3) as a static library.
fn main() {
    let mut cfg = cmake::Config::new("vendor/RandomX");
    // Generic build (RandomX's ARCH=default): runs on any x86-64 and picks
    // AES/AVX2/SSSE3 at runtime, so one signed binary serves every rig.
    cfg.profile("Release").build_target("randomx");
    // The cmake crate replaces CMAKE_<LANG>_FLAGS_RELEASE with cc's flags, which
    // on MSVC carry no optimisation level: RandomX's AES fill and Blake2 then
    // run unoptimised, measured at 52% of XMRig on the tower. Pin it.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // Match Rust's CRT: static (/MT) under +crt-static (.cargo/config.toml).
        let crt_static = std::env::var("CARGO_CFG_TARGET_FEATURE")
            .unwrap_or_default()
            .split(',')
            .any(|f| f == "crt-static");
        let rt = if crt_static { "/MT" } else { "/MD" };
        cfg.define(
            "CMAKE_MSVC_RUNTIME_LIBRARY",
            if crt_static { "MultiThreaded" } else { "MultiThreadedDLL" },
        );
        cfg.static_crt(crt_static);
        for lang in ["C", "CXX"] {
            cfg.define(format!("CMAKE_{lang}_FLAGS_RELEASE"), format!("{rt} /O2 /Ob2 /DNDEBUG"));
        }
    }
    let dst = cfg.build();
    let build = dst.join("build");
    println!("cargo:rustc-link-search=native={}", build.display());
    println!("cargo:rustc-link-search=native={}", build.join("Release").display());
    println!("cargo:rustc-link-lib=static=randomx");
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target == "macos" {
        println!("cargo:rustc-link-lib=c++");
    } else if env != "msvc" {
        println!("cargo:rustc-link-lib=stdc++");
    }
    if target == "windows" {
        println!("cargo:rustc-link-lib=advapi32");
    }
    println!("cargo:rerun-if-changed=vendor/RandomX/src");
}
