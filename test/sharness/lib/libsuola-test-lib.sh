#!/bin/sh

test "$TEST_VERBOSE" = 1 && verbose=t
test "$TEST_IMMEDIATE" = 1 && immediate=t


OPENSSL=${OPENSSL:-$(which openssl)}
LIBSUOLA_DIR="$(readlink -f '../../build')"
($OPENSSL version | grep "^OpenSSL 1.0.") && LIBSUOLA_PATH="$LIBSUOLA_DIR/liblibsuola.so" || LIBSUOLA_PATH="$LIBSUOLA_DIR/libsuola.so"
export LIBSUOLA_PATH
# OSSL_ENV=''
#OSSL_ENCRYPT_OPT="-aes256"

WOPENSSL="OPENSSL_CONF='$PWD/openssl.cnf' $OPENSSL"
