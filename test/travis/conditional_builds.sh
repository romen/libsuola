#!/bin/bash

if git log -1 $TRAVIS_COMMIT_RANGE | grep -q '\[quick tests\]' ; then
    echo "Detected [quick tests] in commit messages" >&2
    export SKIP_BUILD_DEPS=1
fi

if [[ ! -z "$SKIP_BUILD_DEPS" ]]; then
    for var in "${OPENSSL_VERSION}" "${LIBSODIUM_VERSION}"; do
        case "${var}" in
            native|packages) : ;;
            *)
                export SKIP_BUILD=1
                export SKIP_TESTS=1
                ;;
        esac
    done
    unset var
fi
