// Build tevador/RandomX (vendored, v1.2.1, BSD-3) as a static library.
fn main() {
    let mut cfg = cmake::Config::new("vendor/RandomX");
    cfg.define("ARCH", "native").profile("Release").build_target("randomx");
    // The cmake crate replaces CMAKE_<LANG>_FLAGS_RELEASE with cc's flags, which
    // on MSVC carry no optimisation level: RandomX's AES fill and Blake2 then
    // run unoptimised, measured at 52% of XMRig on the tower. Pin it.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        for lang in ["C", "CXX"] {
            cfg.define(format!("CMAKE_{lang}_FLAGS_RELEASE"), "/MD /O2 /Ob2 /DNDEBUG");
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
