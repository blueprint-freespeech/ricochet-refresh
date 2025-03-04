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

    let header_file_path = target_dir.join("include").join("tego").join("tego.h");
    println!("cargo:rerun-if-changed={}", header_file_path.display());

    // generate libgosling.h C header
    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => bindings.write_to_file(header_file_path.clone().into_os_string()),
        Err(cbindgen::Error::ParseSyntaxError { .. }) => return, // ignore in favor of cargo's syntax check
        Err(err) => panic!("{:?}", err),
    };
}