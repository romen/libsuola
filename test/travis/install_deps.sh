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
	
	if [ "$VERSION" = native ]
	then
		mkdir -p "$HOME/cache/openssl"
		ln -s /usr "$OSSL_ROOT"
		return 0
	fi
	
	if [ "$DEBIAN_PACKAGES" ]
	then
		TMP="$(mktemp -d)"
		cd "$TMP"
		for package in $DEBIAN_PACKAGES
		do
			wget "$package" -O package.deb
			ar x package.deb data.tar.xz
			mkdir -p data
			(cd data && tar xf ../data.tar.xz)
			
		done
		
		# remove multilib prefixes
		cp -r data/usr/lib/x86_64-linux-gnu/* data/usr/lib/ || :
		cp -r data/usr/include/x86_64-linux-gnu/* data/usr/include/ || :
		rm -rf data/usr/include/x86_64-linux-gnu  data/usr/lib/x86_64-linux-gnu
		mkdir -p "$HOME/cache/openssl"
		mv data/usr "$OSSL_ROOT"
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

if [ "$DEBIAN_PACKAGES" ]
then
	# Download the debian packages from link and gut it
	# dark magic to extract only the checksum
	DIGEST="$(echo -n "$DEBIAN_PACKAGES" | md5sum | cut -d ' ' -f 1)"
	export OPENSSL_VERSION="$DIGEST"
fi

install_openssl "$OPENSSL_VERSION"
install_libsodium stable
