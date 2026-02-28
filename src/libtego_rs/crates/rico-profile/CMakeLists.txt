set(rico_profile_depends
    Cargo.toml
    src/lib.rs
    src/v3/mod.rs
    src/v3/profile.rs)

set(rico_profile_outputs
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/librico_profile.d
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/librico_profile.rlib)

#
# build target
#
add_custom_command(
    DEPENDS ${rico_profile_depends}
    OUTPUT ${rico_profile_outputs}
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS} --features v3-profile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(rico_profile_target
    DEPENDS ${rico_profile_outputs})

#
# cargo test target
#
if (ENABLE_TESTS)
    add_test(NAME rico_profile_cargo_test
        COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} RUST_BACKTRACE=full cargo test ${CARGO_FLAGS} -- --nocapture
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()
