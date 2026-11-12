fn main() {
    // Embeds the exe icon (needs windres, which ships with the MinGW toolchain).
    let icon = format!("{}/icon.ico", std::env::var("CARGO_MANIFEST_DIR").unwrap().replace(std::path::MAIN_SEPARATOR, "/"));
    winres::WindowsResource::new().set_icon(&icon).compile().unwrap();
    // The GNU linker drops an object-less archive member, so link the resource object directly.
    println!("cargo:rustc-link-arg-bins={}/resource.o", std::env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=icon.ico");
}
