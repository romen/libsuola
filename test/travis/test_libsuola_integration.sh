set -e
set -v
export LD_LIBRARY_PATH="$HOME/cache/openssl/$OPENSSL_VERSION/lib:$HOME/cache/libsodium/stable/lib"
export PATH="$HOME/cache/openssl/$OPENSSL_VERSION/bin:$PATH"

cd "$TRAVIS_BUILD_DIR/build"
TEST_VERBOSE=1 make integration-test
