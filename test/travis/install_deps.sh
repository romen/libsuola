set -e

install_openssl() {
	set -v
	set -e
	VERSION="$1"
	export OSSL_ROOT="$HOME/cache/openssl/$VERSION"
	if [ -e "$OSSL_ROOT" ]
	then
		return 0
	fi
	
	mkdir -p "$HOME/src"
	cd "$HOME/src"
	test -d openssl && rm -rf openssl || :
	git clone --depth=5 https://github.com/openssl/openssl.git --branch "$VERSION"
	cd openssl
	
# 	cd openssl
# 	git checkout "$VERSION"
	./config -d shared --prefix="$OSSL_ROOT" --openssldir="$OSSL_ROOT/ssl" -Wl,-rpath="$OSSL_ROOT/lib"
	make -j2
	make install
}

install_libsodium() {
	set -v
	set -e
# 	VERSION="$1"
	
	VERSION=stable
	LIB_ROOT="$HOME/cache/libsodium/$VERSION"
	if [ -e "$LIB_ROOT" ]
	then
		return 0
	fi
	mkdir -p "$HOME/src"
	cd "$HOME/src"
	test -d libsodium && rm -rf libsodium || :
	git clone --depth=5 https://github.com/jedisct1/libsodium --branch stable
	cd libsodium
# 	git checkout "$VERSION"
	./configure --prefix="$LIB_ROOT"
	make -j2
	make install
}

set -v

install_openssl "$OPENSSL_VERSION"
install_libsodium stable
