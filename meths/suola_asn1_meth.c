/*
 *  libsuola - An engine gluing together OpenSSL and NaCl-derived crypto.
 *  Copyright (C) 2018 TTY Foundation sr
 *
 *  This file is part of libsuola.
 *
 *  libsuola is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU Lesser General Public License as published by the
 *  Free Software Foundation, either version 3 of the License, or (at your
 *  option) any later version.
 *
 *  libsuola is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "meths/suola_asn1_meth.h"

#include "suola_keypair.h"

#include "ossl/suola_objects.h"
#include <openssl/err.h>
#include "ossl/suola_err.h"
#include <openssl/ec.h>
#include <openssl/x509.h>

#include "ossl/ossl_compat.h"

#include <string.h>

#include "debug/debug.h"

#ifndef OPENSSL_V102_COMPAT
#define RC_CONST const
#else
#define RC_CONST
#endif

#define SUOLA_EVP_PKEY_ASN1_FLAGS 0

// ----- ACTUAL STATIC IMPLEMENTATIONS --- {{{

// ----- GENERIC FUNCTIONS             --- {{{

// ----- GENERIC PRINT FUNCTIONS --- {{{
typedef enum {
    SUOLA_PUBLIC,
    SUOLA_PRIVATE
} suola_key_op_t;

static int suola_key_print( BIO *bp, const EVP_PKEY *pkey,
                            int indent, ASN1_PCTX *ctx, suola_key_op_t op)
{
    if (!pkey)
        return 0;

    const SUOLA_KEYPAIR *kpair = EVP_PKEY_get0(pkey);
    const struct suola_nid_data_st *nid_data = NULL;

    if (op == SUOLA_PRIVATE) {
        if (suola_keypair_is_invalid_private(kpair)) {
            if (BIO_printf(bp, "%*s<INVALID PRIVATE KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        nid_data = suola_get_nid_data(kpair->nid);
        if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", nid_data->name) <= 0)
            return 0;
        if (BIO_printf(bp, "%*spriv:\n", indent, "") <= 0)
            return 0;
        if (ASN1_buf_print(bp, kpair->key.privk, nid_data->privk_bytes, indent + 4) == 0)
            return 0;
    } else {
        if (suola_keypair_is_invalid(kpair)) {
            if (BIO_printf(bp, "%*s<INVALID PUBLIC KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        nid_data = suola_get_nid_data(kpair->nid);
        if (BIO_printf(bp, "%*s%s Public-Key:\n", indent, "", nid_data->name) <= 0)
            return 0;
    }
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0)
        return 0;
    if (ASN1_buf_print(bp, kpair->key.pubk.value, nid_data->pubk_bytes,
                       indent + 4) == 0)
        return 0;
    return 1;
}

static int suola_gen_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)
{
    return suola_key_print(bp, pkey, indent, ctx, SUOLA_PRIVATE);
}

static int suola_gen_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)
{
    return suola_key_print(bp, pkey, indent, ctx, SUOLA_PUBLIC);
}

// }}} ----- ABSTRACT PRINT FUNCTIONS

// ----- GENERIC UTILITY FUNCTIONS --- {{{
static int suola_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const SUOLA_KEYPAIR *akey = EVP_PKEY_get0(a);
    const SUOLA_KEYPAIR *bkey = EVP_PKEY_get0(b);

    const struct suola_nid_data_st *adata = NULL; // *bdata = NULL;

    if (suola_keypair_is_invalid(akey) || suola_keypair_is_invalid(bkey) )
        return -2;
    if (akey->nid != bkey->nid)
        return -2;
    adata = suola_get_nid_data(akey->nid);
    return !CRYPTO_memcmp(akey->key.pubk.value, bkey->key.pubk.value,
                          adata->pubk_bytes);
}

/* EVP_PKEY_size returns the maximum size, in bytes, of a signature signed by
 * pkey. For an RSA key, this returns the number of bytes needed to represent
 * the modulus. For an EC key, this returns the maximum size of a DER-encoded
 * ECDSA signature.
 */
static int suola_ed25519_size(const EVP_PKEY *pkey)
{
    return Ed25519_SIGN_LENGTH;
}

/* EVP_PKEY_bits returns the "size", in bits, of pkey. For an RSA key, this
 * returns the bit length of the modulus. For an EC key, this returns the bit
 * length of the group order.
 */
static int suola_curve25519_bits(const EVP_PKEY *pkey)
{
    return CURVE25519_BITS;
}

static int suola_curve25519_security_bits(const EVP_PKEY *pkey)
{
    return CURVE25519_SECURITY_BITS;
}

static void suola_free(EVP_PKEY *pkey)
{
    SUOLA_KEYPAIR *kp = EVP_PKEY_get0(pkey);

    _suola_keypair_free(kp);
}

/* TODO: "parameters" are always equal ? */
static int suola_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    return 1;
}
// }}} ----- GENERIC UTILITY FUNCTIONS

// ----- GENERIC ABSTRACT DECODE/ENCODE/CTRL FUNCTIONS --- {{{

static int suola_gen_ctrl(int nid, EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    SUOLA_KEYPAIR *kp = NULL;
    const unsigned char *p = NULL;
    const struct suola_nid_data_st *nid_data = suola_get_nid_data(nid);
    int pklen = 0;

    switch (op) {

#ifndef OPENSSL_V102_COMPAT
    // FIXME: check if/how this control signals should be handled in 1.0.2
    case ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
        debug("nid: %d, op: ASN1_PKEY_CTRL_SET1_TLS_ENCPT, pklen: %ld\n", nid, arg1);
        p = arg2;
        pklen = arg1;

        if (p == NULL || pklen != nid_data->pubk_bytes ) {
            SUOLAerr(SUOLA_F_ASN1_GENERIC_CTRL, SUOLA_R_WRONG_LENGTH);
            return 0;
        }

        kp = _suola_keypair_new(nid, NO_PRIV_KEY);
        if (suola_keypair_is_invalid(kp)) {
            return 0;
        }

        memcpy(kp->key.pubk.value, p, pklen);

        EVP_PKEY_assign(pkey, nid, kp);
        return 1;


    case ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
        debug("nid: %d, op: ASN1_PKEY_CTRL_GET1_TLS_ENCPT\n", nid);
        kp = EVP_PKEY_get0(pkey);
        if (!suola_keypair_is_invalid(kp) && nid == kp->nid) {
            unsigned char **ppt = arg2;
            *ppt = OPENSSL_memdup(kp->key.pubk.value, nid_data->pubk_bytes);
            if (*ppt != NULL)
                return nid_data->pubk_bytes;
        }
        return 0;
#endif
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        debug("nid: %d, op: ASN1_PKEY_CTRL_DEFAULT_MD_NID, ret: %s\n",
                nid, OBJ_nid2sn(nid_data->default_md_nid) );
        *(int *)arg2 = nid_data->default_md_nid;
        return 2;

    default:
        return -2;

    }
}


static int suola_gen_priv_encode(int nid, PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    const SUOLA_KEYPAIR *kp = EVP_PKEY_get0(pkey);
    ASN1_OCTET_STRING oct;
    unsigned char *penc = NULL;
    int penclen;
    const struct suola_nid_data_st *nid_data = suola_get_nid_data(nid);
    char *tmp_buf = NULL;
    int ret = 0;

    if (nid_data == NULL) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, SUOLA_R_MISSING_NID_DATA);
        return 0;
    }

    if (suola_keypair_is_invalid(kp) || kp->nid != nid) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, SUOLA_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    tmp_buf = OPENSSL_secure_malloc(nid_data->privk_bytes);
    if (NULL == tmp_buf) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    oct.data = memcpy(tmp_buf, kp->key.privk, nid_data->privk_bytes);
    oct.length = nid_data->privk_bytes;
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        ret = 0;
        goto err;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(nid), 0,
                         V_ASN1_UNDEF, NULL, penc, penclen)) {
        OPENSSL_clear_free(penc, penclen);
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        ret = 0;
        goto err;
    }

    ret = 1;
err:
    if (tmp_buf)
        OPENSSL_secure_free(tmp_buf);
    return ret;
}

static int suola_gen_priv_decode(int nid, EVP_PKEY *pkey, RC_CONST PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    RC_CONST X509_ALGOR *palg;
    SUOLA_KEYPAIR *kp = NULL;

    const struct suola_nid_data_st *nid_data = suola_get_nid_data(nid);
    if (nid_data == NULL) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_DECODE, SUOLA_R_MISSING_NID_DATA);
        return 0;
    }

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8))
        return 0;

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    if (palg != NULL) {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF) {
            SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_DECODE, SUOLA_R_INVALID_ENCODING);
            return 0;
        }
    }

    if (p == NULL || plen != nid_data->privk_bytes) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_DECODE, SUOLA_R_WRONG_LENGTH);
        return 0;
    }

    kp = _suola_keypair_new(nid, NO_FLAG);
    if (suola_keypair_is_invalid_private(kp)){
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_DECODE, SUOLA_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    memcpy(kp->key.privk, p, nid_data->privk_bytes);

    ASN1_OCTET_STRING_free(oct);
    oct = NULL;
    p = NULL;
    plen = 0;

    // Generate corresponding public key
    if ( 1 != (nid_data->sk_to_pk)(kp->key.pubk.value, kp->key.privk) ) {
        _suola_keypair_free(kp);
        return 0;
    }

    EVP_PKEY_assign(pkey, nid, kp);

    return 1;
}

static int suola_gen_pub_encode(int nid, X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    const SUOLA_KEYPAIR *kp = EVP_PKEY_get0(pkey);
    unsigned char *penc;
    const struct suola_nid_data_st *nid_data = suola_get_nid_data(nid);

    if (suola_keypair_is_invalid(kp) || kp->nid != nid) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PUB_ENCODE, SUOLA_R_INVALID_KEY);
        return 0;
    }

    if (nid_data == NULL) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PUB_ENCODE, SUOLA_R_MISSING_NID_DATA);
        return 0;
    }

    penc = OPENSSL_memdup(kp->key.pubk.value, nid_data->pubk_bytes);
    if (penc == NULL) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (!X509_PUBKEY_set0_param(pk, OBJ_nid2obj(nid), V_ASN1_UNDEF,
                                NULL, penc, nid_data->pubk_bytes)) {
        OPENSSL_free(penc);
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PUB_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

static int suola_gen_pub_decode(int nid, EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *palg;
    SUOLA_KEYPAIR *kp = NULL;
    const struct suola_nid_data_st *nid_data = suola_get_nid_data(nid);

    if (nid_data == NULL) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PUB_DECODE, SUOLA_R_MISSING_NID_DATA);
        return 0;
    }

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey))
        return 0;

    if (palg != NULL) {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF) {
            SUOLAerr(SUOLA_F_ASN1_GENERIC_PUB_DECODE, SUOLA_R_INVALID_ENCODING);
            return 0;
        }
    }

    if (p == NULL || pklen != nid_data->pubk_bytes) {
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PUB_DECODE, SUOLA_R_WRONG_LENGTH);
        return 0;
    }

    kp = _suola_keypair_new(nid, NO_PRIV_KEY);
    if ( suola_keypair_is_invalid(kp) ){
        SUOLAerr(SUOLA_F_ASN1_GENERIC_PUB_DECODE, SUOLA_R_INVALID_KEY);
        return 0;
    }

    memcpy(kp->key.pubk.value, p, pklen);

    EVP_PKEY_assign(pkey, nid, kp);
    return 1;
}


// }}} ----- GENERIC ABSTRACT DECODE/ENCODE/CTRL FUNCTIONS

// }}} ----- GENERIC FUNCTIONS

// --------- CONCRETE DECODE/ENCODE/CTRL/PRINT FUNCTIONS --- {{{

#define ___debug_concrete(___NAME,___NID,___STRING) \
    verbose("CALLED:\tNID(%d/%s)\t-> \"%s\"\n", ___NID, OBJ_nid2sn(___NID), ___STRING);

#define DECLARE_SUOLA_CONCRETE_FUNCTIONS(___NAME,___NID,___STRING) \
	static int suola_##___NAME##_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)			{ ___debug_concrete(___NAME,___NID,___STRING);return suola_gen_ctrl(___NID,pkey,op,arg1,arg2); }; \
	static int suola_##___NAME##_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)	{ ___debug_concrete(___NAME,___NID,___STRING);return suola_gen_priv_encode(___NID,p8,pkey); };    \
	static int suola_##___NAME##_priv_decode(EVP_PKEY *pkey, RC_CONST PKCS8_PRIV_KEY_INFO *p8)	{ ___debug_concrete(___NAME,___NID,___STRING);return suola_gen_priv_decode(___NID,pkey,p8); };    \
	static int suola_##___NAME##_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx) { ___debug_concrete(___NAME,___NID,___STRING);return suola_gen_priv_print(bp,pkey,indent,ctx); }; \
	static int suola_##___NAME##_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)			{ ___debug_concrete(___NAME,___NID,___STRING);return suola_gen_pub_encode(___NID,pk,pkey); };		\
	static int suola_##___NAME##_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)				{ ___debug_concrete(___NAME,___NID,___STRING);return suola_gen_pub_decode(___NID,pkey,pubkey); }; \
	static int suola_##___NAME##_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx) { ___debug_concrete(___NAME,___NID,___STRING);return suola_gen_pub_print(bp,pkey,indent,ctx); };


DECLARE_SUOLA_CONCRETE_FUNCTIONS(X25519, NID_X25519, (OBJ_nid2sn(NID_X25519)) );
DECLARE_SUOLA_CONCRETE_FUNCTIONS(ed25519, NID_ED25519, (OBJ_nid2sn(NID_ED25519)) );


// }}} ----- CONCRETE DECODE/ENCODE/CTRL/PRINT FUNCTIONS

static int suola_ed25519_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                           X509_ALGOR *sigalg, ASN1_BIT_STRING *str,
                           EVP_PKEY *pkey)
{
    verbose("CALLED\n");
    const ASN1_OBJECT *obj;
    int ptype;

    X509_ALGOR_get0(&obj, &ptype, NULL, sigalg);
    /* Sanity check: make sure it is ED25519 with absent parameters */
    if (OBJ_obj2nid(obj) != NID_ED25519 || ptype != V_ASN1_UNDEF) {
        SUOLAerr(SUOLA_F_ASN1_ED25519_ITEM_VERIFY, SUOLA_R_INVALID_ENCODING);
        return 0;
    }

    if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey))
        return 0;

    return 2;
}

static int suola_ed25519_item_sign(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *str)
{
    verbose("CALLED\n");
    /* Set algorithms identifiers */
    X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_ED25519), V_ASN1_UNDEF, NULL);
    if (alg2)
        X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_ED25519), V_ASN1_UNDEF, NULL);
    /* Algorithm idetifiers set: just sign */
    return 3;
}

// }}} ----- ACTUAL STATIC IMPLEMENTATIONS


/* Called from suola.c:suola_register_ameth():
 * suola_register_asn1_meth(  NID_ED25519,
 *                            &ameth,
 *                            "ED25519",
 *                            "Ed25519 through libsodium");
 *
 * ameth is guaranteed to be non-NULL and unsupported nid are already filtered
 * out.
 */
int suola_register_asn1_meth(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char *pem_str, const char *info)
{
    debug("REGISTER AMETH NID(%d/%s):%s:%s\n",nid,OBJ_nid2sn(nid),pem_str,info);

    *ameth = EVP_PKEY_asn1_new(nid, SUOLA_EVP_PKEY_ASN1_FLAGS, pem_str, info);
    if (!*ameth)
        return 0;


    if (nid == NID_X25519) {
        debug("USING suola_X25519_* functions\n");
        EVP_PKEY_asn1_set_public(*ameth, suola_X25519_pub_decode, suola_X25519_pub_encode, suola_pub_cmp, suola_X25519_pub_print, NULL, suola_curve25519_bits);
        EVP_PKEY_asn1_set_private(*ameth, suola_X25519_priv_decode, suola_X25519_priv_encode, suola_X25519_priv_print);
        EVP_PKEY_asn1_set_ctrl(*ameth, suola_X25519_ctrl);
    } else if (nid == NID_ED25519) {
        debug("USING suola_ed25519_* functions\n");
        EVP_PKEY_asn1_set_public(*ameth, suola_ed25519_pub_decode, suola_ed25519_pub_encode, suola_pub_cmp, suola_ed25519_pub_print, suola_ed25519_size, suola_curve25519_bits);
        EVP_PKEY_asn1_set_private(*ameth, suola_ed25519_priv_decode, suola_ed25519_priv_encode, suola_ed25519_priv_print);
        EVP_PKEY_asn1_set_ctrl(*ameth, suola_ed25519_ctrl);

        EVP_PKEY_asn1_set_item(*ameth, suola_ed25519_item_verify, suola_ed25519_item_sign);
    }

    EVP_PKEY_asn1_set_param(*ameth, 0, 0, 0, 0, suola_cmp_parameters, 0);
#ifndef OPENSSL_V102_COMPAT
    EVP_PKEY_asn1_set_security_bits(*ameth, suola_curve25519_security_bits);
#endif /* OPENSSL_V102_COMPAT */
    EVP_PKEY_asn1_set_free(*ameth, suola_free);

    return 1;
}


/* vim: set ts=4 sw=4 tw=78 et : */
