# Ricochet Refresh - https://ricochetrefresh.net/
# Copyright (C) 2021, Blueprint For Free Speech <ricochet@blueprintforfreespeech.net>
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
# 
#    * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following disclaimer
#      in the documentation and/or other materials provided with the
#      distribution.
# 
#    * Neither the names of the copyright owners nor the names of its
#      contributors may be used to endorse or promote products derived from
#      this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.18)

project(ricochet-refresh)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

# ctest targets
option(ENABLE_TESTS "Enable running tests" ON)
if (ENABLE_TESTS)
    enable_testing()
endif ()

# Run Rust's clippy for Rust targets and cppcheck for C++ targets
option(ENABLE_LINTING "Enable lint make target" OFF)
if (ENABLE_LINTING)
    find_program(CARGO_CLIPPY_EXECUTABLE NAMES cargo-clippy)
    find_program(CPPCHECK_EXECUTABLE NAMES cppcheck)

    if(NOT CARGO_CLIPPY_EXECUTABLE)
        message(FATAL_ERROR "cargo-clippy not found; required for linting Rust")
    else()
        message(STATUS "Found cargo-clippy: ${CARGO_CLIPPY_EXECUTABLE}")
    endif()

    if(NOT CPPCHECK_EXECUTABLE)
        message(FATAL_ERROR "cppcheck not found; required for linting C/C++")
    else()
        message(STATUS "Found cppcheck: ${CPPCHECK_EXECUTABLE}")
    endif()

    add_custom_target(linting)

    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    add_custom_target(cppcheck_target
        DEPENDS
            ${CMAKE_BINARY_DIR}/compile_commands.json
        COMMAND cppcheck --enable=all --error-exitcode=1 --inline-suppr --suppressions-list="${CMAKE_CURRENT_SOURCE_DIR}/cppcheck-suppress" --project="${CMAKE_BINARY_DIR}/compile_commands.json"
    )
    add_dependencies(linting cppcheck_target)

endif()

option(ENABLE_FORMATTING "Enable format make target" OFF)
if (ENABLE_FORMATTING)
    find_program(CARGO_FMT_EXECUTABLE NAMES cargo-fmt)
    find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format)

    if (NOT CARGO_FMT_EXECUTABLE)
        message(FATAL_ERROR "cargo-fmt not found; required to run format make target")
    else()
        message(STATUS "Found cargo-fmt: ${CARGO_FMT_EXECUTABLE}")
    endif()

    if (NOT CLANG_FORMAT_EXECUTABLE)
        message(FATAL_ERROR "clang-format not found; required to run format make target")
    else()
        message(STATUS "Found clang-format: ${CLANG_FORMAT_EXECUTABLE}")
    endif()

    function(add_clang_format_target target_name)
        get_target_property(target_sources ${target_name} SOURCES)
        add_custom_target(${target_name}_clang-format_target
            COMMAND ${CLANG_FORMAT_EXECUTABLE} -style=file:${CMAKE_SOURCE_DIR}/clang-format -i ${target_sources}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
        add_dependencies(format ${target_name}_clang-format_target)
    endfunction()

    add_custom_target(format)

endif()


add_subdirectory(libtego_rs)

if (BUILD_QT_FRONTEND)
    add_subdirectory(ricochet-refresh-qt)
endif()
