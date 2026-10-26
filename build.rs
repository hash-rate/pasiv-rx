// Build tevador/RandomX (vendored, v1.2.1, BSD-3) as a static library.
fn main() {
    let dst = cmake::Config::new("vendor/RandomX")
        .define("ARCH", "native")
        .profile("Release")
        .build_target("randomx")
        .build();
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
