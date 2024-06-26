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

cmake_minimum_required(VERSION 3.16)

project(tego_ui LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (FORCE_QT5)
    find_package(
        QT
        NAMES
        Qt5
        COMPONENTS Core
                Gui
                Network
                Quick
                Widgets
        REQUIRED)
else ()
    find_package(
        QT
        NAMES
        Qt6
        Qt5
        COMPONENTS Core
                Gui
                Network
                Quick
                Widgets
        REQUIRED)
endif ()

find_package(
    Qt${QT_VERSION_MAJOR}
    COMPONENTS Core
               Gui
               Network
               Quick
               Widgets
    REQUIRED)

# Require Qt >5.15
if (${QT_VERSION_MAJOR} EQUAL 5)
    if (${QT_VERSION_MINOR} LESS 15)
        message(FATAL_ERROR "Qt >5.15 is required to build this project!")
    endif ()
endif ()

if (APPLE)
    find_package(
        Qt${QT_VERSION_MAJOR}
        COMPONENTS MacExtras
        REQUIRED)
endif ()

add_library(
    tego_ui STATIC
    ui/LanguagesModel.h
    ui/ContactsModel.h
    ui/Clipboard.cpp
    ui/Clipboard.h
    ui/ContactsModel.cpp
    ui/LanguagesModel.cpp
    ui/MainWindow.cpp
    ui/MainWindow.h
    utils/Useful.h
    utils/Settings.cpp
    utils/Settings.h
    libtego_callbacks.cpp
    shims/UserIdentity.h
    shims/ContactsManager.cpp
    shims/TorCommand.h
    shims/UserIdentity.cpp
    shims/ContactUser.h
    shims/ContactsManager.h
    shims/OutgoingContactRequest.h
    shims/ContactIDValidator.h
    shims/TorControl.h
    shims/TorManager.h
    shims/TorCommand.cpp
    shims/TorControl.cpp
    shims/IncomingContactRequest.h
    shims/OutgoingContactRequest.cpp
    shims/ConversationModel.cpp
    shims/ContactIDValidator.cpp
    shims/IncomingContactRequest.cpp
    shims/ContactUser.cpp
    shims/ConversationModel.h
    shims/TorManager.cpp
    libtego_callbacks.hpp)
target_precompile_headers(tego_ui PRIVATE precomp.hpp)

include(lto)
include(compiler_opts)
# enables compiler specific warnings/sanitizers if requested
setup_compiler(tego_ui)

target_compile_features(tego_ui PRIVATE cxx_std_20)

# Since ricochet-refresh includes libtego_callbacks.hpp as a system header file, we export the include directory twice,
# once as local, once as system TODO: perhaps there's a cleaner way to go about this
target_include_directories(tego_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(tego_ui SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(tego_ui PUBLIC tego)

if (NOT USE_SUBMODULE_FMT)
    find_package(fmt REQUIRED)
endif ()
target_link_libraries(tego_ui PRIVATE fmt::fmt-header-only)

# QT
target_link_libraries(
    tego_ui
    PRIVATE Qt${QT_VERSION_MAJOR}::Core
            Qt${QT_VERSION_MAJOR}::Widgets
            Qt${QT_VERSION_MAJOR}::Network
            Qt${QT_VERSION_MAJOR}::Qml
            Qt${QT_VERSION_MAJOR}::Quick)
if (APPLE)
    target_link_libraries(tego_ui PRIVATE Qt${QT_VERSION_MAJOR}::MacExtras)
endif ()

if ("${CMAKE_BUILD_TYPE}" MATCHES "Rel.*" OR "${CMAKE_BUILD_TYPE}" STREQUAL "MinSizeRel")
    target_compile_definitions(tego_ui PRIVATE QT_NO_DEBUG_OUTPUT QT_NO_WARNING_OUTPUT)
endif ()
