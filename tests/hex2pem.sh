#!/bin/bash

function usage() {
    echo "usage: $0 <ed25519|x25519> <priv|pub> HEX"
    exit 1
}

OID_ED25519="1.3.101.112"
OID_X25519="1.3.101.110"

function genconf_preamble() {
	cat <<- EOF
	asn1 = SEQUENCE:keywrap

	[x25519_oid]
	field1 = OID:${OID_X25519}

	[ed25519_oid]
	field1 = OID:${OID_ED25519}

	[keywrap]
	EOF
}

function genconf_priv() {
	local HEX=${1}

	genconf_preamble
	cat <<- EOF
	field1 = INTEGER:0
	field2 = SEQUENCE:${OID}
	field3 = OCTWRAP,FORMAT:HEX,OCTETSTRING:${HEX}
	EOF
}

function genconf_pub() {
	local HEX=${1}

	genconf_preamble
	cat <<- EOF
	field1 = SEQUENCE:${OID}
	field2 = FORMAT:HEX,BITSTRING:${HEX}
	EOF
}

function pem_writer() {
	local TYPE=${1}
	local GENCONF=${2}

	local BODY=$(openssl asn1parse -genconf <(echo "${GENCONF}") -noout -out >(base64) )

	cat <<-EOF
	-----BEGIN ${TYPE} KEY-----
	${BODY}
	-----END ${TYPE} KEY-----
	EOF
}

function pem_priv() {
	local HEX=${1}

	local GENCONF=$(genconf_priv ${HEX})

	pem_writer "PRIVATE" "${GENCONF}"
}

function pem_pub() {
	local HEX=${1}

	local GENCONF=$(genconf_pub ${HEX})

	pem_writer "PUBLIC" "${GENCONF}"
}

if [ "$#" -ne 3 ] || ( [ $2 != "priv" ] && [ $2 != "pub" ]); then
	usage
	exit 1
fi

OID="ed25519_oid"
if ( [ $1 == "ed25519" ] ); then
	OID="ed25519_oid"
	shift
elif ( [ $1 == "x25519" ] ); then
	OID="x25519_oid"
	shift
else
	usage
	exit 1
fi

OP=$1
HEX=$2

if [ $OP == "priv" ]; then
	pem_priv ${HEX}
elif [ $OP == "pub" ]; then
	pem_pub ${HEX}
fi

