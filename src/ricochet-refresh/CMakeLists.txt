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

# qt configuration
set(STATIC_QT OFF CACHE BOOL "Enable if using a static build of QT" )
set(STATIC_QT_ROOT_DIR "" CACHE STRING "Path to static build of QT (ignored if STATIC_QT is set to OFF)")

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
                LinguistTools
                QmlWorkerScript
                Multimedia
                MultimediaQuick
                QuickControls2
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
                LinguistTools
                QmlWorkerScript
                Multimedia
                MultimediaQuick
                QuickControls2
        REQUIRED)
endif ()

find_package(
    Qt${QT_VERSION_MAJOR}
    COMPONENTS Core
               Gui
               Network
               Quick
               Widgets
               LinguistTools
               QmlWorkerScript
               Multimedia
               MultimediaQuick
               QuickControls2
    REQUIRED)

find_program(LUPDATE_EXECUTABLE NAMES lupdate)
if (NOT LUPDATE_EXECUTABLE)
    message(FATAL_ERROR "lupdate not found; required to update *.ts translation files")
endif()


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

if (WIN32)
    add_executable(ricochet-refresh-qt WIN32)

    # Add the icon
    target_sources(ricochet-refresh-qt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/resources/windows/resources.rc)
else()
    add_executable(ricochet-refresh-qt)
endif()
set_target_properties(ricochet-refresh-qt PROPERTIES OUTPUT_NAME "ricochet-refresh")

option(ENABLE_PLUGGABLE_TRANSPORTS "Enable integrating pluggable-transports from the tor-expert-bundle" OFF)

if(ENABLE_PLUGGABLE_TRANSPORTS)
    # Download tor-expert-bundle based on requested target if not
    # provided at configure time
    if (NOT TOR_EXPERT_BUNDLE)
        if(NOT TOR_EXPERT_BUNDLE_TARGET)
            message(FATAL_ERROR "TOR_EXPERT_BUNDLE_TARGET must be defined (e.g. windows-x86_64, linux-i686, macos-aarch64, etc)")
        endif()
        if (NOT TOR_EXPERT_BUNDLE_VERSION)
            set(TOR_EXPERT_BUNDLE_VERSION "15.0")
        endif()

        set(TOR_EXPERT_BUNDLE_FILENAME "tor-expert-bundle-${TOR_EXPERT_BUNDLE_TARGET}-${TOR_EXPERT_BUNDLE_VERSION}.tar.gz")

        set(TOR_EXPERT_BUNDLE_URL "https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_EXPERT_BUNDLE_VERSION}/${TOR_EXPERT_BUNDLE_FILENAME}")
        set(TOR_EXPERT_BUNDLE "${CMAKE_CURRENT_BINARY_DIR}/${TOR_EXPERT_BUNDLE_FILENAME}")

        if (NOT EXISTS ${TOR_EXPERT_BUNDLE})
            message(STATUS "Downloading ${TOR_EXPERT_BUNDLE_URL}")
            file(DOWNLOAD "${TOR_EXPERT_BUNDLE_URL}" "${TOR_EXPERT_BUNDLE}" SHOW_PROGRESS STATUS TOR_EXPERT_BUNDLE_DOWNLOADED)
            if (NOT TOR_EXPERT_BUNDLE_DOWNLOADED EQUAL 0)
                file (REMOVE "${TOR_EXPERT_BUNDLE}")
                message(FATAL_ERROR "Failed to download: ${TOR_EXPERT_BUNDLE_URL}")
            endif()
        endif()
    endif()

    # custom directory for a particular tor-expert-bundle to avoid overwrites/collisions
    file(SHA256 ${TOR_EXPERT_BUNDLE} TOR_EXPERT_BUNDLE_HASH)
    string(SUBSTRING ${TOR_EXPERT_BUNDLE_HASH} 0 8 TOR_EXPERT_BUNDLE_HASH)
    set(TOR_EXPERT_BUNDLE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tor-expert-bundle-${TOR_EXPERT_BUNDLE_HASH}")
    file(MAKE_DIRECTORY ${TOR_EXPERT_BUNDLE_DIRECTORY})

    set(PT_CONFIG_JSON "${TOR_EXPERT_BUNDLE_DIRECTORY}/tor/pluggable_transports/pt_config.json")

    # create a subdirectory for our deployed pluggable transport binaries
    set(PLUGGABLE_TRANSPORTS_DEST "${CMAKE_CURRENT_BINARY_DIR}/pluggable_transports")
    file(MAKE_DIRECTORY ${PLUGGABLE_TRANSPORTS_DEST})

    # extract tor-expert-bundle and deploy binaries
    add_custom_command(
        DEPENDS ${TOR_EXPERT_BUNDLE}
        OUTPUT ${PT_CONFIG_JSON}
        # extract tor expert bundle
        COMMAND ${CMAKE_COMMAND} -E chdir ${TOR_EXPERT_BUNDLE_DIRECTORY} ${CMAKE_COMMAND} -E tar xvf ${TOR_EXPERT_BUNDLE}
        # pt_config.json has a timestamp older than our archive, so we
        # need to touch the contents so that this rule is not repeatedly
        # rebuilt
        COMMAND ${CMAKE_COMMAND} -E touch ${PT_CONFIG_JSON}
        # deploy pluggable-transport binaries
        COMMAND ${CMAKE_COMMAND} -E copy "${TOR_EXPERT_BUNDLE_DIRECTORY}/tor/pluggable_transports/*" "${PLUGGABLE_TRANSPORTS_DEST}/."
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    install(DIRECTORY "${PLUGGABLE_TRANSPORTS_DEST}" TYPE BIN USE_SOURCE_PERMISSIONS)
endif()

# Generate pluggables.hpp file
set(RICOCHET_PLUGGABLES_SOURCE
    build_pluggables.rs
    Cargo.toml
    ${PT_CONFIG_JSON}
)

add_custom_command(
    DEPENDS ${RICOCHET_PLUGGABLES_SOURCE}
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/pluggables.hpp
    # generate pluggables.hpp header
    COMMAND env CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUST_BACKTRACE=full cargo run --bin build_pluggables ${CMAKE_CURRENT_SOURCE_DIR}/pluggables.hpp ${PT_CONFIG_JSON}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
add_custom_target(pluggables-hpp
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/pluggables.hpp)
add_dependencies(ricochet-refresh-qt pluggables-hpp)

set(RICOCHET_SOURCE
    shims/ContactIDValidator.cpp
    shims/ContactIDValidator.h
    shims/ContactsManager.cpp
    shims/ContactsManager.h
    shims/ContactUser.cpp
    shims/ContactUser.h
    shims/ConversationModel.cpp
    shims/ConversationModel.h
    shims/IncomingContactRequest.cpp
    shims/IncomingContactRequest.h
    shims/OutgoingContactRequest.cpp
    shims/OutgoingContactRequest.h
    shims/TorControl.cpp
    shims/TorControl.h
    shims/TorManager.cpp
    shims/TorManager.h
    shims/UserIdentity.cpp
    shims/UserIdentity.h
    ui/Clipboard.cpp
    ui/Clipboard.h
    ui/ContactsModel.cpp
    ui/ContactsModel.h
    ui/LanguagesModel.cpp
    ui/LanguagesModel.h
    ui/MainWindow.cpp
    ui/MainWindow.h
    utils/Settings.cpp
    utils/Settings.h
    utils/Useful.h
    libtego_callbacks.cpp
    libtego_callbacks.hpp
    main.cpp
)

set(RICOCHET_SOURCE_QML
    ui/ChatWindow.qml
    ui/ContactActions.qml
    ui/dummy.qml
    ui/MainToolBar.qml
    ui/ContactRequestFields.qml
    ui/GeneralPreferences.qml
    ui/TorPreferences.qml
    ui/TorBootstrapStatus.qml
    ui/AudioNotifications.qml
    ui/ChatPage.qml
    ui/ContactIDField.qml
    ui/AddContactDialog.qml
    ui/ContactRequestDialog.qml
    ui/UnreadCountBadge.qml
    ui/AboutPreferences.qml
    ui/PresenceIcon.qml
    ui/Bubble.qml
    ui/ContactList.qml
    ui/ContactListDelegate.qml
    ui/ContactPreferences.qml
    ui/PreferencesDialog.qml
    ui/TorLogDisplay.qml
    ui/MessageDialogWrapper.qml
    ui/MainWindow.qml
    ui/ChatMessageArea.qml
    ui/PageView.qml
    ui/MessageDelegate.qml
    ui/NetworkSetupWizard.qml
    ui/main.qml
    ui/TorConfigurationPage.qml
)

set (RICOCHET_TS
    translation/ricochet_bg.ts
    translation/ricochet_cs.ts
    translation/ricochet_da.ts
    translation/ricochet_de.ts
    translation/ricochet_en.ts
    translation/ricochet_es.ts
    translation/ricochet_et_EE.ts
    translation/ricochet_fi.ts
    translation/ricochet_fil_PH.ts
    translation/ricochet_fr.ts
    translation/ricochet_he.ts
    translation/ricochet_it.ts
    translation/ricochet_it_IT.ts
    translation/ricochet_ja.ts
    translation/ricochet_nb.ts
    translation/ricochet_nl_NL.ts
    translation/ricochet_pl.ts
    translation/ricochet_pt_BR.ts
    translation/ricochet_pt_PT.ts
    translation/ricochet_ru.ts
    translation/ricochet_sl.ts
    translation/ricochet_sq.ts
    translation/ricochet_sv.ts
    translation/ricochet_tr.ts
    translation/ricochet_uk.ts
    translation/ricochet_zh.ts
    translation/ricochet_zh_HK.ts
)

add_custom_command(
    OUTPUT ${RICOCHET_TS}
    COMMAND ${LUPDATE_EXECUTABLE} -no-obsolete ${RICOCHET_SOURCE} ${RICOCHET_SOURCE_QML} -ts ${RICOCHET_TS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(ricochet-refresh-qt-translations
     DEPENDS ${RICOCHET_TS})
add_dependencies(ricochet-refresh-qt ricochet-refresh-qt-translations)

# Add the translations
qt_add_translation(RICOCHET_QM_RES
    ${RICOCHET_TS}
)
# The QM files are generated in the build dir, but the qrc file expects the
# QM files to be relative paths. Work around this by copying the qrc file to
# the build dir
configure_file(translation/embedded.qrc ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

qt_add_resources(
    RICOCHET_QML_RES
    ${CMAKE_CURRENT_BINARY_DIR}/embedded.qrc
    sounds/sounds.qrc
    icons/icons.qrc
    ui/qml.qrc)

target_precompile_headers(ricochet-refresh-qt PRIVATE precomp.hpp)
target_sources(ricochet-refresh-qt PRIVATE ${RICOCHET_SOURCE} ${RICOCHET_QM_RES} ${RICOCHET_QML_RES})

if (DEFINED ENV{RICOCHET_REFRESH_VERSION})
    add_compile_definitions(TEGO_VERSION=$ENV{RICOCHET_REFRESH_VERSION})
endif ()

if (STATIC_QT)
    include(qmake_static)
    target_generate_static_qml_plugins(ricochet-refresh-qt)
    target_generate_static_qt_plugins(ricochet-refresh-qt)
endif ()


include(lto)
include(compiler_opts)
# enables compiler specific warnings/sanitizers if requested
setup_compiler(ricochet-refresh-qt)

target_compile_features(ricochet-refresh-qt PRIVATE cxx_std_20)

target_link_libraries(ricochet-refresh-qt PUBLIC tego_rs)
target_link_libraries(
    ricochet-refresh-qt
    PRIVATE Qt${QT_VERSION_MAJOR}::Core
            Qt${QT_VERSION_MAJOR}::Widgets
            Qt${QT_VERSION_MAJOR}::Network
            Qt${QT_VERSION_MAJOR}::Qml
            Qt${QT_VERSION_MAJOR}::Quick
            Qt${QT_VERSION_MAJOR}::QmlWorkerScript
            Qt${QT_VERSION_MAJOR}::Multimedia
            Qt${QT_VERSION_MAJOR}::MultimediaQuick
            Qt${QT_VERSION_MAJOR}::QuickControls2)
if (APPLE)
    target_link_libraries(ricochet-refresh-qt PRIVATE Qt${QT_VERSION_MAJOR}::MacExtras)
endif ()

if ("${CMAKE_BUILD_TYPE}" MATCHES "Rel.*" OR "${CMAKE_BUILD_TYPE}" STREQUAL "MinSizeRel")
    target_compile_definitions(ricochet-refresh-qt PRIVATE QT_NO_DEBUG_OUTPUT QT_NO_WARNING_OUTPUT)
endif ()

#
# Install
#
install(TARGETS ricochet-refresh-qt)

# Linux
if (UNIX AND NOT WIN32)
    option (RICOCHET_REFRESH_INSTALL_DESKTOP "Install desktop integration files + icons" OFF)
    if (RICOCHET_REFRESH_INSTALL_DESKTOP)
        install(FILES resources/linux/ricochet-refresh.desktop DESTINATION share/applications)
        install(FILES resources/linux/icons/48x48/ricochet-refresh.png DESTINATION share/icons/hicolor/48x48/apps/)
        install(FILES resources/linux/icons/scalable/ricochet-refresh.svg DESTINATION share/icons/hicolor/scalable/apps/)
    endif ()
endif ()
