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

project(tego)


if (ENABLE_TESTS)
    # this needs to go in the root source folder because CTest expects the
    # config in the root build folder
    enable_testing()
endif ()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

# Run Rust's clippy for Rust targets and cppcheck for C++ targets
option(ENABLE_LINTING "Enable lint make target" OFF)
if (ENABLE_LINTING)
    # todo: add C++ support once we move off of the Qt frontend
    add_custom_target(linting)
endif()

option(ENABLE_FORMATTING "Enable format make target" OFF)
if (ENABLE_FORMATTING)
    # todo: add C++ support once we ove off of the Qt frontend
    add_custom_target(format)

    find_program(CARGO_FMT_EXECUTABLE NAMES cargo-fmt)
    if (NOT CARGO_FMT_EXECUTABLE)
        message(FATAL_ERROR "cargo-fmt not found; required to run format make target")
    else()
        message(STATUS "Found cargo-fmt: ${CARGO_FMT_EXECUTABLE}")
    endif()
endif()

# qt configuration
set(STATIC_QT OFF CACHE BOOL "Enable if using a static build of QT" )
set(STATIC_QT_ROOT_DIR "" CACHE STRING "Path to static build of QT (ignored if STATIC_QT is set to OFF)")

add_subdirectory(libtego_rs)
add_subdirectory(ricochet-refresh)
