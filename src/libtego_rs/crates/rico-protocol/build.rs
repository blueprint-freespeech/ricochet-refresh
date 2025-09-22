extern crate protobuf_codegen;

fn main() {
    protobuf_codegen::Codegen::new()
        // use pure-rust parser to generate
        .pure()
        // All inputs and imports from the inputs must reside in `includes` directories.
        .includes(["src/v3/protos"])
        // Inputs must reside in some of include paths.
        .input("src/v3/protos/AuthHiddenService.proto")
        .input("src/v3/protos/ChatChannel.proto")
        .input("src/v3/protos/ContactRequestChannel.proto")
        .input("src/v3/protos/ControlChannel.proto")
        .input("src/v3/protos/FileChannel.proto")
        // Specify output directory relative to Cargo output directory.
        .out_dir("src/v3/protos")
        .run_from_script();
}