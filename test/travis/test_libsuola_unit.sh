set -e
set -v
export LD_LIBRARY_PATH="$OSSL_ROOT/lib:$HOME/cache/libsodium/stable/lib"
export PATH="$OSSL_ROOT/bin:$PATH"

cd "$TRAVIS_BUILD_DIR/build"
make test
