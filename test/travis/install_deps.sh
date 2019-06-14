#!/bin/bash

set -e

function install_openssl_from_git() {
    set -v
    set -e
    VERSION="$1"
    if [ -e "$OSSL_ROOT" ]; then
        rm -rf "$OSSL_ROOT"
    fi

    mkdir -p "$HOME/src"
    cd "$HOME/src"
    test -d openssl && rm -rf openssl || :
    git clone --depth=5 https://github.com/openssl/openssl.git --branch "$VERSION"

    cd openssl
    ./config -d shared --prefix="$OSSL_ROOT" --openssldir="$OSSL_ROOT/ssl" -Wl,-rpath="$OSSL_ROOT/lib"
    make update

    make -s -j2
    make install_sw
    make install_ssldirs || :
}

function install_openssl() {
    set -v
    set -e
    VERSION="$1"
    case "$VERSION" in
        native|packages)
            return 0
            ;;
        *)
            if [ ! -z "${SKIP_BUILD_DEPS}" ]; then
                echo "SKIPPING DEPENDENCIES BUILD" >&2
                return 0
            fi

            install_openssl_from_git $VERSION
            ;;
    esac
}

install_libsodium_from_git() {
    set -v
    set -e

    VERSION=$1
    if [ -e "$LIBSODIUM_ROOT" ]; then
        rm -rf "$LIBSODIUM_ROOT"
    fi
    mkdir -p "$HOME/src"
    cd "$HOME/src"
    test -d libsodium && rm -rf libsodium || :
    git clone --depth=5 https://github.com/jedisct1/libsodium --branch "$VERSION"

    cd libsodium
    ./configure --prefix="$LIBSODIUM_ROOT"

    make -s -j2
    make install
}

function install_libsodium() {
    set -v
    set -e

    VERSION="$1"
    case "$VERSION" in
        native|packages)
            return 0
            ;;
        *)
            if [ ! -z "${SKIP_BUILD_DEPS}" ]; then
                echo "SKIPPING DEPENDENCIES BUILD" >&2
                return 0
            fi

            install_libsodium_from_git $VERSION
            ;;
    esac
}

function install_deps_packages() {
    set -e
    set -v

    local prefix=$1; shift
    local urls=$@

    local tmpdir="$(mktemp -d)"
    local u=""
    local p=""

    cd $tmpdir
    mkdir -p data

    for u in ${urls}; do
        p="${u##*/}"

        curl -s -o"$p" "$u"
        dpkg -x "$p" "$PWD/data"
    done

    # remove multilib prefixes
    for a in x86_64-linux-gnu; do
        for s in data/usr/lib data/usr/include; do
            cp -a $s/$a/* $s/ || :
            rm -rf $s/$a
            ln -s . $s/$a
        done
    done

    [ -e "${prefix}" ] && rm -rf "${prefix}" || :
    mkdir -p "${prefix}"
    mv data/usr/* "${prefix}/"

    # Edit pkg-config files
    cd "${prefix}"
    for pc in lib/pkgconfig/*.pc; do
        sed -i -e "s,^prefix=/usr,prefix=${prefix}," $pc
    done

    (set -x; tree "${prefix}" >&2 )
}

set -v

if [ ! -z "${DEPS_PACKAGES_URLS}" ]; then
    install_deps_packages "${DPACKAGES_PREFIX}" ${DEPS_PACKAGES_URLS}
fi
install_openssl "$OPENSSL_VERSION"
install_libsodium "$LIBSODIUM_VERSION"
