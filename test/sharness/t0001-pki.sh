#!/bin/bash

test_description="test PKI infrastructure"

. ./lib/libsuola-test-lib.sh
. ./lib/sharness/sharness.sh

# Directory for Root certificate files
export format=pem
export subjectAltName="email:example@example.com"
export cadir="$PWD/ca"
export icdir="$PWD/ic"
export ic8dir="$PWD/ic8"
export crlDP=
export default_crl_days=30
export ocspIAI=
export sn=8


set -e
mkdir "$cadir"
cd "$cadir"
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
touch serial
countryName="/C=TS"
stateOrProvinceName="/ST=TST"
localityName="/L=TestTown"
organizationName="/O=TestCorp"
organizationalUnitName="/OU=TestLab"
commonName="/CN=Test Root CA"
DN="$countryName$stateOrProvinceName$localityName"
DN="$DN$organizationName$organizationalUnitName$commonName"
cat >"$cadir/openssl-root.cnf" <<-'EOF'
	# OpenSSL root CA configuration file.
	# Copy to `$dir/openssl-root.cnf`.

	openssl_conf = openssl_init
	
	[openssl_init]
	engines = engine_section
	
	[engine_section]
	libsuola = libsuola_section

	[libsuola_section]
	dynamic_path = $ENV::LIBSUOLA_PATH
	default_algorithms = ALL
	init = 1
	
	[ ca ]
	# `man ca`
	default_ca = CA_default

	[ CA_default ]
	# Directory and file locations.
	cadir             = $ENV::cadir
	format            = $ENV::format

	certs             = $cadir/certs
	crl_dir           = $cadir/crl
	new_certs_dir     = $cadir/newcerts
	database          = $cadir/index.txt
	serial            = $cadir/serial
	RANDFILE          = $cadir/private/.rand

	# The root key and root certificate.
	private_key       = $cadir/private/ca.key.$format
	certificate       = $cadir/certs/ca.cert.$format

	# For certificate revocation lists.
	crlnumber         = $cadir/crlnumber
	crl               = $cadir/crl/ca.crl.pem
	crl_extensions    = crl_ext
	default_crl_days  = 30

	# SHA-1 is deprecated, so use SHA-2 instead.
	#default_md        = sha256

	name_opt          = ca_default
	cert_opt          = ca_default
	default_days      = 375
	preserve          = no
	policy            = policy_strict
	copy_extensions   = copy

	[ policy_strict ]
	# The root CA should only sign intermediate certificates that match.
	# See the POLICY FORMAT section of `man ca`.
	countryName             = match
	stateOrProvinceName     = match
	organizationName        = match
	organizationalUnitName  = optional
	commonName              = optional

	[ policy_loose ]
	# Allow the intermediate CA to sign a more
	#   diverse range of certificates.
	# See the POLICY FORMAT section of the `ca` man page.
	countryName             = optional
	stateOrProvinceName     = optional
	localityName            = optional
	organizationName        = optional
	organizationalUnitName  = optional
	commonName              = optional

	[ req ]
	# Options for the `req` tool (`man req`).
	default_bits        = 2048
	distinguished_name  = req_distinguished_name
	string_mask         = utf8only
	req_extensions      = req_ext

	# SHA-1 is deprecated, so use SHA-2 instead.
	#default_md          = sha256

	# Extension to add when the -x509 option is used.
	x509_extensions     = v3_ca

	[ req_distinguished_name ]
	# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
	countryName                     = Country Name (2 letter code)
	stateOrProvinceName             = State or Province Name
	localityName                    = Locality Name
	0.organizationName              = Organization Name
	organizationalUnitName          = Organizational Unit Name
	commonName                      = Common Name

	[ req_ext ]
	subjectAltName = $ENV::subjectAltName

	[ v3_ca ]
	# Extensions for a typical CA (`man x509v3_config`).
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid:always,issuer
	basicConstraints = critical, CA:true
	# keyUsage = critical, digitalSignature, cRLSign, keyCertSign
	keyUsage = critical, cRLSign, keyCertSign
	subjectAltName = $ENV::subjectAltName

	[ v3_intermediate_ca ]
	# Extensions for a typical intermediate CA (`man x509v3_config`).
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid:always,issuer
	basicConstraints = critical, CA:true, pathlen:0
	# keyUsage = critical, digitalSignature, cRLSign, keyCertSign
	keyUsage = critical, cRLSign, keyCertSign

	[ crl_ext ]
	# Extension for CRLs (`man x509v3_config`).
	authorityKeyIdentifier=keyid:always

	[ ocsp ]
	# Extension for OCSP signing certificates (`man ocsp`).
	basicConstraints = CA:FALSE
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid,issuer
	keyUsage = critical, digitalSignature
	extendedKeyUsage = critical, OCSPSigning
EOF
cd ..
set +e

# Macro to redirect output to file and scan it for errors
# Because OpenSSL would still return 0 if failed to load engine
ASSERT_NOERROR="2>&1 | tee err && ! grep -Pq '^\d+:error:' err"

test_expect_success "Ensure engine works" "
	$WOPENSSL engine -c libsuola
"

test_expect_success "Generate CA keypair" "
	$WOPENSSL genpkey ${OSSL_ENCRYPT_OPT} \
		-outform '$format' -out '$cadir/private/ca.key.$format' \
		-algorithm Ed25519 \
		$ASSERT_NOERROR &&
	chmod 400 '$cadir/private/ca.key.$format'
"

test_expect_success "Generate CA root certificate" "
	$OPENSSL req -config '$cadir/openssl-root.cnf' \
		-set_serial 0x$($OPENSSL rand -hex $sn) \
		-keyform '$format' -outform '$format' \
		-key '$cadir/private/ca.key.$format' -subj '$DN' \
		-new -x509 -days 7300 -extensions v3_ca \
		-out '$cadir/certs/ca.cert.$format' \
		$ASSERT_NOERROR
"

set -e
mkdir "$icdir"
cd "$icdir"
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
sn=8 # hex 8 is minimum, 19 is maximum
echo 1000 > crlnumber

crl=intermediate.crl.pem
crlurl=localhost/pki/$crl
export crlDP="URI:http://$crlurl"
ocspurl=localhost
export ocspIAI="OCSP;URI:http://$ocspurl"
commonName="/CN=Test Signing CA"
DN="$countryName$stateOrProvinceName$localityName$organizationName"
DN="$DN$organizationalUnitName$commonName"

# Create the file, $dir/openssl-intermediate.cnf from the contents in Appendix A.2.
# Remove the crlDistributionPoints to drop CRL support and authorityInfoAccess to drop OCSP support.
cat >openssl-intermediate.cnf <<-'EOF'
	# OpenSSL intermediate CA configuration file.
	# Copy to `$dir/intermediate/openssl.cnf`.

	openssl_conf = openssl_init
	
	[openssl_init]
	engines = engine_section
	
	[engine_section]
	libsuola = libsuola_section

	[libsuola_section]
	dynamic_path = $ENV::LIBSUOLA_PATH
	default_algorithms = ALL
	init = 1
	
	[ ca ]
	# `man ca`
	default_ca = CA_default

	[ CA_default ]
	# Directory and file locations.
	icdir             = $ENV::icdir
	format            = $ENV::format

	certs             = $icdir/certs
	crl_dir           = $icdir/crl
	new_certs_dir     = $icdir/newcerts
	database          = $icdir/index.txt
	serial            = $icdir/serial
	RANDFILE          = $icdir/private/.rand

	# The Intermediate key and Intermediate certificate.
	private_key       = $icdir/private/intermediate.key.$format
	certificate       = $icdir/certs/intermediate.cert.$format

	# For certificate revocation lists.
	crlnumber         = $icdir/crlnumber
	crl               = $icdir/crl/intermediate.crl.pem
	crl_extensions    = crl_ext
	default_crl_days  = $ENV::default_crl_days

	# SHA-1 is deprecated, so use SHA-2 instead.
	#default_md        = sha256

	name_opt          = ca_default
	cert_opt          = ca_default
	default_days      = 375
	preserve          = no
	policy            = policy_loose
	copy_extensions   = copy

	[ policy_strict ]
	# The root CA should only sign intermediate certificates that match.
	# See the POLICY FORMAT section of `man ca`.
	countryName             = match
	stateOrProvinceName     = match
	organizationName        = match
	organizationalUnitName  = optional
	commonName              = optional

	[ policy_loose ]
	# Allow the intermediate CA to sign a more
	#  diverse range of certificates.
	# See the POLICY FORMAT section of the `ca` man page.
	countryName             = optional
	stateOrProvinceName     = optional
	localityName            = optional
	organizationName        = optional
	organizationalUnitName  = optional
	commonName              = optional
	UID                     = optional

	[ req ]
	# Options for the `req` tool (`man req`).
	default_bits        = 2048
	distinguished_name  = req_distinguished_name
	string_mask         = utf8only
	req_extensions      = req_ext

	# SHA-1 is deprecated, so use SHA-2 instead.
	#default_md          = sha256

	# Extension to add when the -x509 option is used.
	x509_extensions     = v3_ca

	[ req_distinguished_name ]
	# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
	countryName                     = Country Name (2 letter code)
	stateOrProvinceName             = State or Province Name
	localityName                    = Locality Name
	0.organizationName              = Organization Name
	organizationalUnitName          = Organizational Unit Name
	commonName                      = Common Name
	UID                             = User ID

	[ req_ext ]
	subjectAltName = $ENV::subjectAltName

	[ v3_ca ]
	# Extensions for a typical CA (`man x509v3_config`).
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid:always,issuer
	basicConstraints = critical, CA:true
	# keyUsage = critical, digitalSignature, cRLSign, keyCertSign
	keyUsage = critical, cRLSign, keyCertSign

	[ v3_intermediate_ca ]
	# Extensions for a typical intermediate CA (`man x509v3_config`).
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid:always,issuer
	basicConstraints = critical, CA:true, pathlen:0
	# keyUsage = critical, digitalSignature, cRLSign, keyCertSign
	keyUsage = critical, cRLSign, keyCertSign

	[ usr_cert ]
	# Extensions for client certificates (`man x509v3_config`).
	basicConstraints = CA:FALSE
	nsCertType = client, email
	nsComment = "OpenSSL Generated Client Certificate"
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid,issuer
	keyUsage = critical,nonRepudiation,digitalSignature,keyEncipherment
	extendedKeyUsage = clientAuth, emailProtection
	crlDistributionPoints = $ENV::crlDP
	authorityInfoAccess = $ENV::ocspIAI

	[ server_cert ]
	# Extensions for server certificates (`man x509v3_config`).
	basicConstraints = CA:FALSE
	nsCertType = server
	nsComment = "OpenSSL Generated Server Certificate"
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid,issuer:always
	keyUsage = critical, digitalSignature, keyEncipherment
	extendedKeyUsage = serverAuth
	crlDistributionPoints = $ENV::crlDP
	authorityInfoAccess = $ENV::ocspIAI

	[ crl_ext ]
	# Extension for CRLs (`man x509v3_config`).
	authorityKeyIdentifier=keyid:always

	[ ocsp ]
	# Extension for OCSP signing certificates (`man ocsp`).
	basicConstraints = CA:FALSE
	subjectKeyIdentifier = hash
	authorityKeyIdentifier = keyid,issuer
	keyUsage = critical, digitalSignature
	extendedKeyUsage = critical, OCSPSigning
EOF
cd ..
set +e

test_expect_success "Generate IC keypair" "
	$WOPENSSL genpkey ${OSSL_ENCRYPT_OPT} \
		-outform '$format' -out '$icdir/private/intermediate.key.$format' \
		-algorithm Ed25519 \
		$ASSERT_NOERROR &&
	chmod 400 '$icdir/private/intermediate.key.$format'
"

test_expect_success "Generate IC CSR" "
	$OPENSSL req -config '$icdir/openssl-intermediate.cnf' \
		-key '$icdir/private/intermediate.key.$format' \
		-keyform '$format' -outform '$format' -subj '$DN' -new \
		-out '$icdir/csr/intermediate.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Verify IC CSR" "
	$WOPENSSL req -text -noout -verify -inform '$format' \
	-in '$icdir/csr/intermediate.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Sign IC certificate file" "
	$OPENSSL rand -hex $sn > '$cadir/serial' # hex 8 is minimum, 19 is maximum &&
	# To prevent openssl complaining about missing file
	echo 'unique_subject = yes' > '$cadir/index.txt.attr' && 
	$OPENSSL ca -batch -config '$cadir/openssl-root.cnf' -days 3650\
		-extensions v3_intermediate_ca -notext -md default \
		-in '$icdir/csr/intermediate.csr.$format' \
		-out '$icdir/certs/intermediate.cert.pem' \
		$ASSERT_NOERROR
"
test_expect_success "Create IC certificate chain" "
	chmod 444 '$icdir/certs/intermediate.cert.$format' &&
	cat '$icdir/certs/intermediate.cert.$format' \
		'$cadir/certs/ca.cert.$format' \
		> '$icdir/certs/ca-chain.cert.$format' &&
	chmod 444 '$icdir/certs/ca-chain.cert.$format'
"

export commonName=
DN="$countryName$stateOrProvinceName$localityName"
export DN="$DN$organizationName$organizationalUnitName$commonName"
export serverfqdn=www.example.com
export emailaddr="postmaster@example.com"
export subjectAltName="DNS:$serverfqdn, email:$emailaddr"

test_expect_success "Create a server EE keypair" "
	$WOPENSSL genpkey ${OSSL_ENCRYPT_OPT} \
		-out '$icdir/private/$serverfqdn.key.$format' \
		-algorithm Ed25519 \
		$ASSERT_NOERROR &&
	chmod 400 '$icdir/private/$serverfqdn.key.$format'
"

test_expect_success "Create a server EE CSR" "
	$OPENSSL req -config '$icdir/openssl-intermediate.cnf' \
		-key '$icdir/private/$serverfqdn.key.$format' \
		-subj '$DN' -new -out '$icdir/csr/$serverfqdn.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Verify server EE CSR" "
	$WOPENSSL req -noout -verify -in '$icdir/csr/$serverfqdn.csr.$format' $ASSERT_NOERROR
"

test_expect_success "Sign server EE CSR" "
	$OPENSSL rand -hex '$sn' > '$icdir/serial' && # hex 8 is minimum, 19 is maximum
	# To prevent openssl complaining about missing file
	echo 'unique_subject = yes' > '$icdir/index.txt.attr' && 
	$OPENSSL ca -batch -config '$icdir/openssl-intermediate.cnf' -days 375 \
		-extensions server_cert -notext -md default \
		-in '$icdir/csr/$serverfqdn.csr.$format' \
		-out '$icdir/certs/$serverfqdn.cert.$format' \
		$ASSERT_NOERROR &&
	chmod 444 '$icdir/certs/$serverfqdn.cert.$format'
"

test_expect_success "Verify server EE certificate" "
	$WOPENSSL verify -CAfile '$icdir/certs/ca-chain.cert.$format' \
		'$icdir/certs/$serverfqdn.cert.$format' \
		$ASSERT_NOERROR
"


export commonName=
export UserID="/UID=MClient"
DN="$countryName$stateOrProvinceName$localityName"
export DN="$DN$organizationName$organizationalUnitName$commonName$UserID"
export clientemail="client@example.com"
export subjectAltName="email:$clientemail"

test_expect_success "Generate client EE keypair" "
	$WOPENSSL genpkey ${OSSL_ENCRYPT_OPT} \
		-out '$icdir/private/$clientemail.key.$format' \
		-algorithm Ed25519 \
		$ASSERT_NOERROR &&
	chmod 400 '$icdir/private/$clientemail.key.$format'
"

test_expect_success "Create client EE CSR" "
	$OPENSSL req -config '$icdir/openssl-intermediate.cnf' \
		-key '$icdir/private/$clientemail.key.$format' \
		-subj '$DN' -new -out '$icdir/csr/$clientemail.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Verify client EE CSR" "
	$WOPENSSL req -noout -verify \
		-in '$icdir/csr/$clientemail.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Sign client EE certificate" "
	$OPENSSL rand -hex '$sn' > '$icdir/serial' && # hex 8 is minimum, 19 is maximum
	$OPENSSL ca -batch \
		-config '$icdir/openssl-intermediate.cnf' -days 375 \
		-extensions usr_cert -notext -md default \
		-in '$icdir/csr/$clientemail.csr.$format' \
		-out '$icdir/certs/$clientemail.cert.$format' \
	$ASSERT_NOERROR &&
	chmod 444 '$icdir/certs/$clientemail.cert.$format'
"

test_expect_success "Verify client EE certificate" "
	$WOPENSSL verify -CAfile '$icdir/certs/ca-chain.cert.$format' \
		'$icdir/certs/$clientemail.cert.$format' \
		$ASSERT_NOERROR
"


set -e
mkdir "$ic8dir"
cd "$ic8dir"
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
sn=8 # hex 8 is minimum, 19 is maximum
echo 1000 > "$ic8dir/crlnumber"

export default_crl_days=30

export crlDP=
# For CRL support use uncomment these:
crl=8021ARintermediate.crl.pem
crlurl=localhost/pki/$crl
export crlDP="URI:http://$crlurl"
export default_crl_days=30
export ocspIAI=
# For OCSP support use uncomment these:
ocspurl=localhost
export ocspIAI="OCSP;URI:http://$ocspurl"

countryName="/C=TS"
stateOrProvinceName="/ST=TST"
localityName="/L=TestTown"
organizationName="/O=TestCorp"
organizationalUnitName="/OU=TestLab"
commonName="/CN=Test Root CA"
DN="$countryName$stateOrProvinceName$localityName$organizationName"
DN="$DN$organizationalUnitName$commonName"
export subjectAltName=email:postmaster@example.com


cat >openssl-8021ARintermediate.cnf <<-'EOF'

openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
libsuola = libsuola_section

[libsuola_section]
dynamic_path = $ENV::LIBSUOLA_PATH
default_algorithms = ALL
init = 1

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
ic8dir               = $ENV::ic8dir
cadir             = $ENV::cadir
format            = $ENV::format

certs             = $ic8dir/certs
crl_dir           = $ic8dir/crl
new_certs_dir     = $ic8dir/newcerts
database          = $ic8dir/index.txt
serial            = $ic8dir/serial
RANDFILE          = $ic8dir/private/.rand

# The root key and root certificate.
private_key       = $ic8dir/private/8021ARintermediate.key.$format
certificate       = $ic8dir/certs/8021ARintermediate.cert.$format

# For certificate revocation lists.
crlnumber         = $ic8dir/crlnumber
crl               = $ic8dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = $ENV::default_crl_days

name_opt          = ca_default
cert_opt          = ca_default
default_enddate   = 99991231235959Z # per IEEE 802.1AR
preserve          = no
policy            = policy_loose
copy_extensions   = copy

[ policy_strict ]
# The root CA should only sign 8021ARintermediate
#   certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = optional

[ policy_loose ]
# Allow the 8021ARintermediate CA to sign
#   a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.


countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
serialNumber            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
req_extensions      = req_ext

# SHA-1 is deprecated, so use SHA-2 instead.

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
serialNumber                    = Device Serial Number

[ req_ext ]
subjectAltName = $ENV::subjectAltName

[ hmodname ]
hwType = OID:$ENV::hwType
hwSerialNum = FORMAT:HEX,OCT:$ENV::hwSerialNum

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign


[ v3_8021ARintermediate_ca ]
# Extensions for a typical
#   8021ARintermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
# keyUsage = critical, digitalSignature, cRLSign, keyCertSign
keyUsage = critical, cRLSign, keyCertSign

[ 8021ar_idevid ]
# Extensions for IEEE 802.1AR iDevID
#   certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
crlDistributionPoints = $ENV::crlDP
authorityInfoAccess = $ENV::ocspIAI

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning

EOF
cd ..
set +e

test_expect_success "Create 802.1AR Intermediate keypair" "
	$WOPENSSL genpkey ${OSSL_ENCRYPT_OPT} \
		-algorithm Ed25519 \
		-outform '$format' \
		-out '$ic8dir/private/8021ARintermediate.key.$format' \
		$ASSERT_NOERROR &&
   chmod 400 '$ic8dir/private/8021ARintermediate.key.$format'
"

test_expect_success "Create 802.1AR Intermediate CSR" "
	$OPENSSL req -config '$cadir/openssl-root.cnf' \
		-key '$ic8dir/private/8021ARintermediate.key.$format' \
		-keyform '$format' -outform '$format' -subj '$DN' -new \
		-out '$ic8dir/csr/8021ARintermediate.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Verify 802.1AR Intermediate CSR" "
	$WOPENSSL req -noout -verify \
		-in '$ic8dir/csr/8021ARintermediate.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Sign 802.1AR Intermediate CSR" "
	$OPENSSL rand -hex '$sn' > '$ic8dir/serial' &&
	$OPENSSL ca -batch -config '$cadir/openssl-root.cnf' -days 3650 \
		-extensions v3_intermediate_ca -notext -md default \
		-in '$ic8dir/csr/8021ARintermediate.csr.$format' \
		-out '$ic8dir/certs/8021ARintermediate.cert.pem' \
		$ASSERT_NOERROR &&
	chmod 444 '$ic8dir/certs/8021ARintermediate.cert.$format'
"

test_expect_success "Verify 802.1AR Intermediate certificate" "
	$WOPENSSL verify -CAfile '$cadir/certs/ca.cert.$format' \
        '$ic8dir/certs/8021ARintermediate.cert.$format'
"

test_expect_success "Create 802.1AR Intermediate certificate chain" "
	 cat '$ic8dir/certs/8021ARintermediate.cert.$format' \
      '$cadir/certs/ca.cert.$format' > '$ic8dir/certs/ca-chain.cert.$format' &&
   chmod 444 '$ic8dir/certs/ca-chain.cert.$format'"

set -e
export DevID=Wt1234
countryName="/C=TS"
stateOrProvinceName="/ST=TST"
localityName="/L=TestTown"
organizationName="/O=TestCorp"
organizationalUnitName="/OU=TestLab"
serialNumber="/serialNumber=$DevID"
commonName="/CN=Test Root CA"
DN="$countryName$stateOrProvinceName$localityName"
DN="$DN$organizationName$organizationalUnitName$commonName"
export DN="$DN$serialNumber"
# hwType is OID for HTT Consulting, devices, sensor widgets
export hwType=1.3.6.1.4.1.6715.10.1
export hwSerialNum=01b20fa4 # Some hex 
export subjectAltName="otherName:1.3.6.1.5.5.7.8.4;SEQ:hmodname"
set +e

test_expect_success "Create 802.1AR iDevID keypair" "
	$WOPENSSL genpkey ${OSSL_ENCRYPT_OPT} \
		-algorithm Ed25519 \
		-out '$ic8dir/private/$DevID.key.$format' \
		$ASSERT_NOERROR &&
   chmod 400 '$ic8dir/private/$DevID.key.$format'
"

test_expect_success "Create 802.1AR iDevID CSR" "
	$OPENSSL req -config '$ic8dir/openssl-8021ARintermediate.cnf' \
		-key '$ic8dir/private/$DevID.key.$format' \
		-outform '$format' \
		-subj '$DN' -new -out '$ic8dir/csr/$DevID.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Verify 802.1AR iDevID CSR" "
	$WOPENSSL req -noout -verify \
       -in '$ic8dir/csr/$DevID.csr.$format' \
       $ASSERT_NOERROR
"

test_expect_success "Sign 802.1AR iDevID CSR" "
	$OPENSSL rand -hex '$sn' > '$ic8dir/serial' &&
	# To prevent openssl complaining about missing file
	echo 'unique_subject = yes' > '$ic8dir/index.txt.attr' && 
	$OPENSSL ca -batch -config '$ic8dir/openssl-8021ARintermediate.cnf' -days 375 \
		-extensions 8021ar_idevid -notext -md default \
		-in '$ic8dir/csr/$DevID.csr.$format' \
		-out '$ic8dir/certs/$DevID.cert.$format' \
		$ASSERT_NOERROR &&
   chmod 444 '$ic8dir/certs/$DevID.cert.$format'
"

test_expect_success "Verify 802.1AR iDevID certificate" "
	$WOPENSSL verify -CAfile '$ic8dir/certs/ca-chain.cert.$format' \
		'$ic8dir/certs/$DevID.cert.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Create CRLs" "
	# Create CRL file for intermediate
	$OPENSSL ca -config '$icdir/openssl-intermediate.cnf' \
		-gencrl -out '$icdir/crl/intermediate.crl.pem' -md default \
		$ASSERT_NOERROR &&
	chmod 644 '$icdir/crl/intermediate.crl.pem'
	
	# Create CRL file for 802.1AR intermediate
	$OPENSSL ca -config '$ic8dir/openssl-8021ARintermediate.cnf' \
		-gencrl -out '$ic8dir/crl/8021ARintermediate.crl.pem' -md default \
		$ASSERT_NOERROR &&
	chmod 644 '$ic8dir/crl/8021ARintermediate.crl.pem'
"

test_expect_success "Revoke client EE certificate & recreate CRL" "
	$OPENSSL ca -config '$icdir/openssl-intermediate.cnf' \
		-revoke '$icdir/certs/$clientemail.cert.$format' -md default \
		$ASSERT_NOERROR &&
	$OPENSSL ca -config '$icdir/openssl-intermediate.cnf' \
		-gencrl -out '$icdir/crl/intermediate.crl.pem' -md default \
		$ASSERT_NOERROR &&
	chmod 644 '$icdir/crl/intermediate.crl.pem'
"

test_expect_success "Create OCSP keypair" "
	$WOPENSSL genpkey ${OSSL_ENCRYPT_OPT} \
		-algorithm Ed25519 \
		-out '$icdir/private/$ocspurl.key.$format' \
		$ASSERT_NOERROR &&
	chmod 400 '$icdir/private/$ocspurl.key.$format'
"

commonName="mOCSP"
DN="$countryName$stateOrProvinceName$localityName"
DN="$DN$organizationName$organizationalUnitName$commonName"
emailaddr="example@example.com"
export subjectAltName="DNS:$ocspurl, email:$emailaddr"

test_expect_success "Create OCSP CSR" "
	$OPENSSL req -config '$icdir/openssl-intermediate.cnf' \
		-key '$icdir/private/$ocspurl.key.$format' \
		-subj '$DN' -new -out '$icdir/csr/$ocspurl.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Verify OCSP CSR" "
	$WOPENSSL req -noout -verify \
		-in '$icdir/csr/$ocspurl.csr.$format' \
		$ASSERT_NOERROR
"

test_expect_success "Sign OCSP CSR" "
	$OPENSSL rand -hex '$sn' > '$icdir/serial' && # hex 8 is minimum, 19 is maximum
	$OPENSSL ca -batch -config '$icdir/openssl-intermediate.cnf' -days 375 \
		-extensions ocsp -notext -md default \
		-in '$icdir/csr/$ocspurl.csr.$format' \
		-out '$icdir/certs/$ocspurl.cert.$format' \
		$ASSERT_NOERROR &&
	chmod 444 '$icdir/certs/$ocspurl.cert.$format'
"

test_expect_success "Verify OCSP certificate" "
	$WOPENSSL verify -CAfile '$icdir/certs/ca-chain.cert.$format' \
		'$icdir/certs/$ocspurl.cert.$format' \
		$ASSERT_NOERROR
"

# Disabled because OCSP does not work with engines
# Launch OCSP daemon
sh -c "$WOPENSSL ocsp -port 2560 \
		-index '$icdir/index.txt' \
		-CA '$icdir/certs/ca-chain.cert.pem' \
		-rkey '$icdir/private/$ocspurl.key.pem' \
		-rsigner '$icdir/certs/$ocspurl.cert.pem' \
		-nrequest 1" &
OCSP_PID=$!
# give ocsp some time
sleep 0.5

test_expect_success "Query OCSP for certificate revocation" "
	$WOPENSSL ocsp -CAfile '$icdir/certs/ca-chain.cert.pem' \
		-url http://localhost:2560 -resp_text -sha256\
		-issuer '$icdir/certs/intermediate.cert.pem' \
		-cert '$icdir/certs/$clientemail.cert.pem' | grep '$icdir/certs/$clientemail.cert.pem: revoked'
"

# Kill OCSP daemon in case it's still alive
(kill $OCSP_PID && wait $OCSP_PID) 2> /dev/null

test_done

# vi: set ft=sh :
