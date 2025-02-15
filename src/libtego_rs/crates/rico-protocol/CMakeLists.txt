set(rico_protocol_depends
    Cargo.toml
    build.rs
    src/lib.rs
    src/v3/mod.rs
    src/v3/protos/ChatChannel.proto
    src/v3/protos/ContactRequestChannel.proto
    src/v3/protos/AuthHiddenService.proto
    src/v3/protos/ControlChannel.proto
    src/v3/protos/FileChannel.proto)

set(rico_protocol_outputs
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/librico_protocol.d
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/librico_protocol.rlib)

#
# build target
#
add_custom_command(
    DEPENDS ${rico_protocol_depends}
    OUTPUT ${rico_protocol_outputs}
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(rico_protocol_target
    DEPENDS ${rico_protocol_outputs})
