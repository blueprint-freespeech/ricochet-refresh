set(tego_rs_sources
    build.rs
    Cargo.toml
    cbindgen.toml
    src/command_queue.rs
    src/context.rs
    src/error.rs
    src/ffi.rs
    src/lib.rs
    src/macros.rs
    src/object_map.rs
    src/promise.rs
    src/user_id.rs
)

set(tego_rs_static_filename "${CMAKE_STATIC_LIBRARY_PREFIX}tego_rs${CMAKE_STATIC_LIBRARY_SUFFIX}" CACHE STRING "tego-rs static library filename" FORCE
)
set(tego_rs_static ${CARGO_TARGET_DIR}/${CARGO_TARGET_TRIPLE}/${CARGO_PROFILE}/${tego_rs_static_filename})
set(tego_rs_include_dir
    ${CARGO_TARGET_DIR}/${CARGO_PROFILE}/include
)

set(tego_rs_outputs
    ${tego_rs_static}
    ${tego_rs_include_dir}/tego.h
)

make_directory(${tego_rs_include_dir}/tego)

# hard-link our authord tego headers to tego-rs' include directory
file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/include/tego/tego.hpp ${tego_rs_include_dir}/tego/tego.hpp)
file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/include/tego/utilities.hpp ${tego_rs_include_dir}/tego/utilities.hpp)
file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/include/tego/logger.hpp ${tego_rs_include_dir}/tego/logger.hpp)

#
# build tego-rs static lib
#

add_custom_command(
    DEPENDS ${tego_rs_sources}
    OUTPUT ${tego_rs_outputs}
    COMMAND ${CMAKE_COMMAND} -E touch build.rs
    COMMAND env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo build ${CARGO_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(tego_rs_target
    DEPENDS ${tego_rs_outputs}
)

#
# create static library target for consumers
#

add_library(tego_rs STATIC IMPORTED GLOBAL)
add_dependencies(tego_rs tego_rs_target)
set_target_properties(tego_rs PROPERTIES
    IMPORTED_LOCATION ${tego_rs_static})
target_include_directories(tego_rs INTERFACE ${tego_rs_include_dir})

# Windows
if (WIN32)
    target_link_libraries(tego_rs INTERFACE ws2_32)
    target_link_libraries(tego_rs INTERFACE userenv)
    target_link_libraries(tego_rs INTERFACE bcrypt)
    target_link_libraries(tego_rs INTERFACE ntdll)
endif()
