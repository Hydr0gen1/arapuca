fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "linux" && matches!(arch.as_str(), "x86_64" | "aarch64") {
        println!("cargo:rustc-cfg=seccomp_supported");
    }
}
