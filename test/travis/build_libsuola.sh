#!/bin/bash

set -e
set -v
cd "$TRAVIS_BUILD_DIR"
mkdir build
cd build

(
    set -v
    set -e

    if [ "$LIBSODIUM_VERSION" != "native" ]; then
        export PKG_CONFIG_PATH="$LIBSODIUM_ROOT/lib/pkgconfig"
    fi
    cmake ${OSSL_ROOT:+-DOPENSSL_ROOT_DIR="$OSSL_ROOT"} ..
)

make
