# libsuola OpenSSL Engine [![Build Status](https://travis-ci.com/romen/libsuola.svg?branch=master)](https://travis-ci.com/romen/libsuola)

This project aims at developing an OpenSSL engine rigging cryptosystem implementations derived from [NaCl](https://nacl.cr.yp.to/) into OpenSSL.

The project currently supports three alternative back-end providers:

-   [libsodium](https://github.com/jedisct1/libsodium)
-   [HACL\*](https://github.com/mitls/hacl-star)
-   [donna](https://github.com/floodyberry/ed25519-donna.git)

More details are available in [this paper](https://eprint.iacr.org/2018/354.pdf).

<!-- toc -->

- [Project structure](#project-structure)
- [Installation](#installation)
  * [Binary distributions of OpenSSL and libsodium](#binary-distributions-of-openssl-and-libsodium)
  * [Installing prerequisites from source](#installing-prerequisites-from-source)
    + [OpenSSL](#openssl)
    + [Back-end provider](#back-end-provider)
      - [libsodium](#libsodium)
      - [HACL](#hacl)
  * [libsuola](#libsuola)
  * [Uninstall](#uninstall)
- [Usage](#usage)
  * [List algorithms](#list-algorithms)
  * [Generate private key](#generate-private-key)
  * [Generate public key](#generate-public-key)
  * [Examine a key](#examine-a-key)
  * [Sign data](#sign-data)
  * [Verify data](#verify-data)
  * [Generate cert](#generate-cert)
  * [Generate new key and cert](#generate-new-key-and-cert)
  * [Examine a cert](#examine-a-cert)
  * [ENV variables](#env-variables)
- [License](#license)
- [OID crud](#oid-crud)
  * [Ed25519](#ed25519)
- [Acknowledgments](#acknowledgments)

<!-- tocstop -->

## Project structure

The source code of the project is organized hierarchically.

```
.
├── cmake
├── debug
├── meths
├── ossl
├── providers
│   ├── _dummy
│   ├── api
│   ├── donna
│   ├── hacl
│   ├── libsodium
│   └── ossl
├── test
└── suola.c
```

- `suola.c` contains the main entry point for loading of the `ENGINE`;
- `meths` contains the implementation of the OpenSSL method structures defining
  the implemented cryptosystems;
- `ossl` contains code to integrate error codes, messages, NIDs, and
  OIDs in the OpenSSL abstractions;
- `providers` contains the code to map the primitives referenced in the
  `meths` structures to the actual cryptographic implementation provider:
  * `api` describes the API that a valid provider module needs to implement;
  * `libsodium`, `hacl` and `donna` map the cryptographic functionality
    to the corresponding backend implementation;
  * `_dummy` includes boilerplate code for additional functions (e.g.\
    an empty `suola_implementation_init()` that can be used when the
    backend provider does not require any initialization before being
    used);
  * `ossl` includes boilerplate code for additional functions that are
    implemented reusing OpenSSL methods rather than a backend
    implementation (e.g.\ implement `suola_randombytes_buf()` using
    OpenSSL `RAND` module rather then the backend PRNG);
- `test` contains code used to automate testing of the `ENGINE`;
- `debug` contains definitions used to implement the debug messaging
  system;
- `cmake` contains helpers for the build system.

## Installation

To build `libsuola` from source you will need:
- `git` to clone the latest source version from this repository and
  other dependencies you plan to build from source;
- `cmake`, `pkg-config`, `make`, `gcc`/`clang` and the required
  development headers specific for your system, to ensure a working
  build system.

In Debian-like distributions the following should suffice:

```
apt-get install git pkg-config cmake build-essential
```

Other flavours of UNIX will use a different package manager (replacing
`apt-get install` with something similar) and use slightly different
package names.

### Binary distributions of OpenSSL and libsodium

If you have already installed OpenSSL,
[libsodium](https://github.com/jedisct1/libsodium), etc., the
corresponding installation steps are optional for you.


To use OpenSSL or libsodium as provided by your Linux distribution, you
need to make sure the development headers are also installed.

In Debian/Ubuntu this means to install the corresponding `*-dev`
packages:

```
apt-get install libssl-dev libsodium-dev
```

**Note**: the above step is not required if installing OpenSSL or
libsodium from source.

Other flavours of UNIX will use a different package manager (replacing
`apt-get install` with something similar) and use slightly different
package names.

### Installing prerequisites from source

#### OpenSSL

```
git clone https://github.com/openssl/openssl.git openssl-master
cd openssl-master/
export OPENSSL_ROOT_DIR=/usr/local/ssl
./config -d shared --prefix=$OPENSSL_ROOT_DIR --openssldir=$OPENSSL_ROOT_DIR -Wl,-rpath=$OPENSSL_ROOT_DIR/lib
make -j4
make test
sudo checkinstall --strip=no --stripso=no --pkgname=openssl-master-debug --provides=openssl-master-debug --pkgversion=1.1.1 --default make install_sw
alias openssl=$OPENSSL_ROOT_DIR/bin/openssl
```

#### Back-end provider

##### libsodium

```
git clone https://github.com/jedisct1/libsodium --branch stable
cd libsodium/
LIBSODIUM_PREFIX=/usr/local
./configure --enable-debug --prefix=${LIBSODIUM_PREFIX}
make
make check
sudo checkinstall --strip=no --stripso=no --pkgname=libsodium-debug --provides=libsodium-debug --default
export PKG_CONFIG_PATH="$LIBSODIUM_PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"
```

##### HACL

```
git clone https://github.com/mitls/hacl-star
cd hacl-star
make build
cd build
sudo checkinstall --strip=no --stripso=no --pkgname=libhacl-debug --provides=libhacl-debug --default
sudo ldconfig
```

### libsuola

```
git clone https://github.com/romen/libsuola
cd libsuola
mkdir build
cd build
# -DUSE_DONNA=<ON|OFF> enables/disables the DONNA implementation as the provider backend, which by default is libsodium
# -DUSE_HACL=<ON|OFF> enables/disables HACL as the provider backend, which by default is libsodium
# -DHACL_PREFIX=<path> allows to specify the installation prefix for HACL, by default /usr/local
cmake -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR} -DUSE_HACL=ON ..
make
make test
#ctest --output-on-failure
#ctest --verbose
sudo checkinstall --strip=no --stripso=no --pkgname=libsuola-debug --provides=libsuola-debug --default
# or build a proper package with git-buildpackage
gbp buildpackage --git-upstream-tree=SLOPPY --git-debian-branch=master -ibuild\|.git --git-ignore-new --no-sign
```

### Uninstall

```
sudo dpkg -r libsuola-debug
sudo dpkg -r libhacl-debug        # if installed from source
sudo dpkg -r libsodium-debug      # if installed from source
sudo dpkg -r openssl-master-debug # if installed from source
```

## Usage

### List algorithms

`openssl engine -c libsuola`

### Generate private key

`openssl genpkey -engine libsuola -algorithm Ed25519 -out priv.pem`

### Generate public key

`openssl pkey -engine libsuola -in priv.pem -pubout -out pub.pem`

### Examine a key

`openssl pkey -engine libsuola -in priv.pem -text`

### Sign data

`openssl dgst -engine libsuola -sign priv.pem -out lsb-release.sig /etc/lsb-release`

### Verify data

`openssl dgst -engine libsuola -verify pub.pem -signature lsb-release.sig /etc/lsb-release`

### Generate cert

`openssl req -engine libsuola -x509 -config /path/to/openssl.cnf -new -key priv.pem -out cert.pem`

### Generate new key and cert

`openssl req -engine libsuola -x509 -config /usr/lib/ssl/openssl.cnf -nodes -newkey Ed25519 -keyout priv.pem -out cert.pem`

### Examine a cert

`openssl asn1parse -in cert.pem`

### ENV variables

The verbosity level of libsuola logging output is controlled by the
`SUOLA_DEBUG` environment variable, which can be set to an integer value as
detailed in this list:

-   1 (LOG_FATAL)
-   2 (LOG_ERR)
-   3 (LOG_WARN) **default**
-   4 (LOG_INFO)
-   5 (LOG_DBG)
-   6 (LOG_VRB)
-   10 (LOG_EXTRM)

*Example*: `export SUOLA_DEBUG=5` will setup libsuola to print messages with
priority `LOG_DBG` or higher (highest priority is `LOG_FATAL`).

Environment variables relevant to the project include those affecting OpenSSL,
specifically the following ones:

-   `OPENSSL_ENGINES` sets the directory from which engines are loaded (the
	default value can be obtained by `openssl version -e`
-   `OPENSSL_CONF` sets a custom configuration file (the default value is
	`$OPENSSLDIR/openssl.cnf`, `openssl version -d`)

## License

libsuola is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

libsuola is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

The full text of the license is contained in the files `COPYING` and
`COPYING.LESSER`.

## OID crud

* [Database](http://www.alvestrand.no/objectid/)

### Ed25519

* https://tools.ietf.org/html/rfc8032
* https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04
* https://tools.ietf.org/html/draft-josefsson-tls-ed25519-00
* https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
* [IETF curdle mailing list archive](https://mailarchive.ietf.org/arch/search/?email_list=curdle)
* https://www.gnu.org/prep/standards/html_node/OID-Allocations.html
* [OpenPGP](https://gitorious.org/gnupg/mainline/commit/59207a86e5f40c77fed296b642bf76692e8eef65?p=gnupg:mainline.git;a=commitdiff;h=59207a86e5f40c77fed296b642bf76692e8eef65;hp=159d42ee6ab21d97f40ee129445f37209b875739)
* https://github.com/str4d/ed25519-java/pull/20

## Acknowledgments

- Supported in part by Academy of Finland grant 303814.
- This article is based in part upon work from COST Action IC1403 CRYPTACUS, supported by COST (European Cooperation in Science and Technology).

