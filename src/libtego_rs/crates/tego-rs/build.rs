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
    // set by cmake
    let target_dir = match std::env::var("CARGO_TARGET_DIR") {
        Ok(target) => PathBuf::from(target).join(profile),
        Err(_) => panic!("CARGO_TARGET_DIR not set"),
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
        std::fs::rename(temp_file_path.as_path(), header_file_path.as_path()).unwrap();
    } else {
        std::fs::remove_file(temp_file_path.as_path()).unwrap();
    }
}
