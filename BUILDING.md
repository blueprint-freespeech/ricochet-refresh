# Building Ricochet Refresh

These instructions are intended for people who wish to build or modify Ricochet
Refresh from source.

## Getting the source code

Clone the Ricochet Refresh git repository with `--recurse-submodules`:
```sh
git clone --recurse-submodules https://github.com/blueprint-freespeech/ricochet-refresh.git
```

In the event that you cloned the repo without fetching the submodules, you can
still get them with:
```sh
git submodule --init --update
```

Later, you should update your local repository with:
```sh
git pull --recurse-submodules
```

## GNU/Linux

### Dependencies

You will need:
 * Qt5 (Qt Base, Qt Declarative, Qt Quick)
 * Tor
 * OpenSSL (libcrypto)
 * Protocol Buffers (libprotobuf, protoc)
 * {fmt}
 * CMake

#### Fedora
```sh
yum install cmake tor gcc-c++ protobuf-devel protobuf-compiler openssl-devel fmt-devel \
            qt5-qtbase-devel qt5-qtquickcontrols qt5-qtdeclarative-devel
```

#### Debian & Ubuntu
```sh
apt install cmake tor build-essential libprotobuf-dev protobuf-compiler libssl-dev \
            libfmt-dev qtbase5-dev qtdeclarative5-dev qml-module-qtquick-layouts \
            qml-module-qtquick-controls qml-module-qtquick-dialogs
```

If the `qml-module-qtquick` packages aren't available, try `qtdeclarative5-controls-plugin` instead.

### Arch
```sh
pacman -S cmake tor qt5-base qt5-declarative qt5-quickcontrols openssl fmt \
          protobuf
```

### Building
```sh
mkdir build
cmake -S ./src -B ./build -G"Unix Makefiles" -DCMAKE_BUILD_TYPE=MinSizeRel -DRICOCHET_REFRESH_INSTALL_DESKTOP=ON
cmake --build ./build -j$(nproc)
```

### Installing
For a system-wide installation run as root:
```sh
cmake --build ./build --target install
```

By default Ricochet Refresh will load and save configuration files to
`~/.config/ricochet-refresh/`. First argument to command-line overrides this and
allows you to specify the config directory.

## OS X

Not tested. A build may be possible by installing the dependencies listed for
GNU/Linux with brew, as well as Xcode (for the toolchain).

Qt5 can alternatively be installed via the [Qt SDK](https://www.qt.io/download/).

You will need a `tor` binary in $PATH or inside the build's
`ricochet refresh.app/Contents/MacOS` folder. The easiest solution is to use
`brew install tor`. If you copy the `tor` binary, you will need to keep it up to
date.

By default, configuration will be stored at
`~/Library/Application Support/ricochet-refresh/` folder. This can be overridden
by supplying a directory as first argument to the command-line.

## Windows

Not tested. A build may be possible by installing the dependencies listed for
GNU/Linux as well as Visual Studio C++ or MinGW (for the toolchain).

Qt5 can be installed via the [Qt SDK](https://www.qt.io/download/).

Libraries such as OpenSSL and protobuf should be build and installed before
Ricochet Refresh according to their own instructions.

You will need a `tor.exe` binary, placed in the same folder as
`ricochet-refresh.exe`.
