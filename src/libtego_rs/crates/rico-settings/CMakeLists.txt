set(rico_settings_depends
    Cargo.toml
    src/common.rs
    src/lib.rs
    src/v3/mod.rs
    src/v3/settings.rs
    src/v4/mod.rs
    src/v4/settings.rs)

set(rico_settings_outputs
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/librico_settings.d
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/librico_settings.rlib)

#
# build target
#
add_custom_command(
    DEPENDS ${rico_settings_depends}
    OUTPUT ${rico_settings_outputs}
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(rico_settings_target
    DEPENDS ${rico_settings_outputs})

#
# cargo test target
#
if (ENABLE_TESTS)
    add_test(NAME rico_settings_cargo_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} -- --nocapture
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()
