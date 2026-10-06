fn main() {
    // Tauri's Windows manifest declares one thing: Common Controls v6, which
    // TaskDialogIndirect and the rest of Tauri's window code need. tauri_build
    // embeds it in the app alone, so a unit test that reaches that code could
    // not even start (STATUS_ENTRYPOINT_NOT_FOUND). The same declaration goes
    // in through the linker instead, for every binary, tests included; this is
    // the route Tauri's WindowsAttributes::new_without_app_manifest is for.
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if msvc {
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        );
        let attrs = tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
        tauri_build::try_build(attrs).expect("tauri build");
    } else {
        tauri_build::build()
    }
}
