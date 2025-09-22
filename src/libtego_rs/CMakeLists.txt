# translate our cmake build type to a cargo profile and build flags
if(CMAKE_BUILD_TYPE)
    string(REPLACE " " ";" CARGO_FLAGS "${CARGO_FLAGS}")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CARGO_PROFILE debug)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS "--release;${CARGO_FLAGS}")
        set(RUSTFLAGS "-C strip=symbols")
    elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS "--release;${CARGO_FLAGS}")
        set(RUSTFLAGS "-g")
    elseif(CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
        set(CARGO_PROFILE release)
        set(CARGO_FLAGS "--release;${CARGO_FLAGS}")
        set(RUSTFLAGS "-C opt-level=z -C strip=symbols")
    else()
        message(FATAL_ERROR "CMAKE_BUILD_TYPE not defined")
    endif()
else()
    message(FATAL_ERROR "CMAKE_BUILD_TYPE not defined")
endif()

# extract the cargo target triple if it exists
list(FIND CARGO_FLAGS "--target" TARGET_ARG_INDEX)
if(NOT TARGET_ARG_INDEX EQUAL -1)
    math(EXPR TRIPLE_ARG_INDEX "${TARGET_ARG_INDEX} + 1")
    list(GET CARGO_FLAGS ${TRIPLE_ARG_INDEX} CARGO_TARGET_TRIPLE)
endif()

set(CARGO_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR})

# ensure we have required Rust components
find_program(RUSTC_EXECUTABLE NAMES rustc)
find_program(CARGO_EXECUTABLE NAMES cargo)

if (NOT RUSTC_EXECUTABLE)
    message(FATAL_ERROR "rustc not found; required to build libtego_rs")
elseif (NOT CARGO_EXECUTABLE)
    message(FATAL_ERROR "cargo not found; required to build libtego_rs")
endif()

add_subdirectory(crates)

if (ENABLE_LINTING)
    #
    # Run crate linting
    #
    add_custom_target(cargo_clippy_target
        COMMAND CARGO_TARGET_DIR=${CARGO_TARGET_DIR} RUSTFLAGS=${RUSTFLAGS} cargo clippy
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_dependencies(linting cargo_clippy_target)
endif()

if (ENABLE_FORMATTING)
    #
    # Run rust formatting
    #
    add_custom_target(cargo_fmt_target
        COMMAND cargo fmt
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_dependencies(format cargo_fmt_target)
endif()

