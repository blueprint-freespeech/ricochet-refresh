extern crate cbindgen;

use std::path::PathBuf;

fn main() {
    // set by cargo
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // set by cargo
    let profile = match std::env::var("PROFILE") {
        Ok(target) => target,
        Err(_) => panic!("PROFILE not set"),
    };
    // set by cmake; fall back to OUT_DIR's ancestor for standalone cargo builds
    let target_dir = match std::env::var("CARGO_TARGET_DIR") {
        Ok(target) => PathBuf::from(target).join(profile),
        Err(_) => {
            let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
            let mut path = PathBuf::from(out_dir);
            // OUT_DIR is target/<profile>/build/<crate>-<hash>/out — walk up to target/<profile>
            for _ in 0..3 {
                path.pop();
            }
            path
        }
    };

    let header_file_dir = target_dir.join("include").join("tego");
    std::fs::create_dir_all(header_file_dir.clone()).unwrap();

    let header_file_path = header_file_dir.join("tego.h");
    println!("cargo:rerun-if-changed={}", header_file_path.display());
    let temp_file_path = std::env::temp_dir().join("tego.h");

    // generate libgosling.h C header
    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => bindings.write_to_file(temp_file_path.clone().into_os_string()),
        Err(cbindgen::Error::ParseSyntaxError { .. }) => return, // ignore in favor of cargo's syntax check
        Err(err) => panic!("{:?}", err),
    };

    let prev_source = std::fs::read(header_file_path.as_path()).unwrap_or(Default::default());
    let new_source = std::fs::read(temp_file_path.as_path()).unwrap();

    if prev_source != new_source {
        // copy+remove instead of rename: temp dir may be on a different filesystem
        std::fs::copy(temp_file_path.as_path(), header_file_path.as_path()).unwrap();
    }
    let _ = std::fs::remove_file(temp_file_path.as_path());
}
