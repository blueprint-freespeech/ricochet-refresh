set(tego_rs_sources
    Cargo.toml
    src/lib.rs
)

set(TEGO_RS_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}tego-rs${CMAKE_STATIC_LIBRARY_SUFFIX}" CACHE STRING "tego-rs static library filename" FORCE
)
set(tego_rs_static ${CARGO_TARGET_DIR}/${CARGO_TARGET_TRIPLE}/${CARGO_PROFILE}/${tego_rs_static_filename})

set(tego_rs_outputs
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${TEGO_RS_STATIC}
)

#
# build tego-rs static lib
#

add_custom_command(
    DEPENDS ${tego_rs_sources}
    OUTPUT ${tego_rs_outputs}
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(tego_rs_target
    DEPENDS ${tego_rs_outputs}
)
