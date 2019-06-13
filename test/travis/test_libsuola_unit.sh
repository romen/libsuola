#!/bin/bash

set -e
set -v

if [ "$LIBSODIUM_VERSION" != "native" ]; then
    export LD_LIBRARY_PATH="${LIBSODIUM_ROOT}/lib:${LD_LIBRARY_PATH}"
fi
if [ "$OPENSSL_VERSION" != "native" ]; then
    export LD_LIBRARY_PATH="${OSSL_ROOT}/lib:${LD_LIBRARY_PATH}"
    export PATH="$OSSL_ROOT/bin:$PATH"
fi

cd "$TRAVIS_BUILD_DIR/build"

export CTEST_OUTPUT_ON_FAILURE=1
make test
