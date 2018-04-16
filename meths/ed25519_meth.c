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

#include "meths/ed25519_meth.h"
#include "debug/debug.h"

#include "providers/api/rng.h"
#include "providers/api/ed25519.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>

#include "ossl/suola_err.h"

#include "suola_keypair.h"
#include "ossl/suola_objects.h"
#include "meths/suola_md_identity_meth.h"

#include <string.h> /* memcpy() */

#include "ossl/ossl_compat.h"

typedef SUOLA_KEYPAIR Ed25519_KEYPAIR;

#define ed25519_keypair_new(nid, flags) \
    _suola_keypair_new((nid), (flags))
#define ed25519_keypair_free(kpair) \
    _suola_keypair_free((kpair))

int ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
{
    int rt = 0;

    /* buffer for the expanded private key */
    unsigned char tmp_sk[Ed25519_EXP_PRIVKEYLEN];

    if ( 0 == suola_sign_ed25519_seed_keypair(pk, tmp_sk, sk))
        rt = 1;
    else
        SUOLAerr(SUOLA_F_ED25519_SK_TO_PK, SUOLA_R_IMPLEMENTATION_BACKEND_UNEXPECTED_RETURN);

    OPENSSL_cleanse(tmp_sk, sizeof(tmp_sk));

    return rt;
}

static int ed25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    Ed25519_KEYPAIR *kpair = NULL;
    // TODO: get nid as param to distinguish between Ed25519{,ph,ctx}
    int nid = NID_ED25519;

    kpair = ed25519_keypair_new(nid, NO_FLAG);
    if (suola_keypair_is_invalid_private(kpair)) {
        SUOLAerr(SUOLA_F_ED25519_KEYGEN, SUOLA_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    suola_randombytes_buf(kpair->key.privk, Ed25519_PRIVKEYLEN);

    if(!ed25519_sk_to_pk(kpair->key.pubk.value, kpair->key.privk)) {
        SUOLAerr(SUOLA_F_ED25519_KEYGEN, SUOLA_R_CANNOT_DERIVE_PK);
        goto err;
    }

    EVP_PKEY_assign(pkey, nid, kpair);
    return 1;
err:
    if (kpair)
        ed25519_keypair_free(kpair);
    return 0;
}

static int ed25519_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    int md_nid;
    const char *type_str = "";
    switch(type) {
        case EVP_PKEY_CTRL_MD:
            type_str = "EVP_PKEY_CTRL_MD";
            debug("%s (EVP_MD_type: %d)\n", type_str,
                    EVP_MD_type((const EVP_MD *)p2));

            md_nid = EVP_MD_nid(p2);
            if ( md_nid == NID_identity_md || md_nid == NID_sha512 ) {
                return 1;
            }
            errorf("%s: unsupported message digest '%s'\n", type_str, OBJ_nid2ln(md_nid));
            return 0;

        case EVP_PKEY_CTRL_DIGESTINIT:
            type_str = "EVP_PKEY_CTRL_DIGESTINIT";
            debug("%s\n", type_str);
            break;;

        default:
            warn("UNSUPPORTED operation (type=%d).\n", type);
            return -2;
    }
    verbose("STUB (type=%s).\n", type_str);
    return 1;
}

static int ed25519_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                         size_t *siglen, const unsigned char *tbs,
                         size_t tbslen)
{
    unsigned long long _siglen;
    const EVP_PKEY *_pkey = NULL;
    const Ed25519_KEYPAIR *kpair = NULL;
    debug("TBSLEN %lu\n", tbslen);

    _pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (_pkey == NULL) {
        SUOLAerr(SUOLA_F_ED25519_SIGN, SUOLA_R_KEYS_NOT_SET);
        return -1;
    }
    kpair = EVP_PKEY_get0(_pkey);
    if (suola_keypair_is_invalid(kpair)) {
        SUOLAerr(SUOLA_F_ED25519_SIGN, SUOLA_R_INVALID_PRIVATE_KEY);
        return -1;
    }
    if (kpair->has_private != 1) {
        SUOLAerr(SUOLA_F_ED25519_SIGN, SUOLA_R_MISSING_PRIVATE_KEY);
        return -1;
    }

    *siglen = Ed25519_SIGN_LENGTH;

    if (sig == NULL) {          // return signature length
        return 1;
    }

    if ( 0 !=  suola_sign_ed25519_detached( sig,
                                            &_siglen,
                                            tbs,
                                            tbslen,
                                            kpair->key.privk,
                                            kpair->key.pubk.value ) ) {
        SUOLAerr(SUOLA_F_ED25519_SIGN, SUOLA_R_IMPLEMENTATION_BACKEND_UNEXPECTED_RETURN);
        goto err;
    }

    *siglen = _siglen;

#if DEBUG_BASE64_SGNVRF
    debug_b64(LOG_EXTRM, sig, *siglen, "");
    debug_b64(LOG_EXTRM, tbs, tbslen, "");
    debug_b64(LOG_EXTRM, kpair->key.privk, Ed25519_PRIVKEYLEN, "");
    debug_b64(LOG_EXTRM, kpair->key.pubk.value, Ed25519_PUBKEYLEN, "");
#endif

    return 1;
err:
    return -1;
}

static int ed25519_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                           size_t siglen, const unsigned char *tbv,
                           size_t tbvlen)
{
    const EVP_PKEY *_pkey = NULL;
    const Ed25519_KEYPAIR *kpair = NULL;
    int valid = 0;

    _pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (_pkey == NULL) {
        SUOLAerr(SUOLA_F_ED25519_VERIFY, SUOLA_R_KEYS_NOT_SET);
        return -1;
    }
    kpair = EVP_PKEY_get0(_pkey);
    if (suola_keypair_is_invalid(kpair)) {
        SUOLAerr(SUOLA_F_ED25519_VERIFY, SUOLA_R_INVALID_KEY);
        return -1;
    }

#if DEBUG_BASE64_SGNVRF
    debug_b64(LOG_EXTRM, sig, siglen, "");
    debug_b64(LOG_EXTRM, tbv, tbvlen, "");
    debug_b64(LOG_EXTRM, kpair->key.pubk.value, Ed25519_PUBKEYLEN, "");
#endif

    if (siglen != Ed25519_SIGN_LENGTH || sig == NULL) {
        SUOLAerr(SUOLA_F_ED25519_VERIFY, SUOLA_R_BAD_SIGNATURE);
        return -1;
    }

    valid = ( 0 ==  suola_sign_ed25519_verify_detached( sig,
                                                        tbv,
                                                        tbvlen,
                                                        kpair->key.pubk.value) );
    if (valid == 1)
        return 1;

    return 0;
}

#include <string.h> /* memcpy */

int EVP_PKEY_CTX_ed25519_set_private(EVP_PKEY_CTX *ctx, const unsigned char sk[Ed25519_PRIVKEYLEN])
{
    EVP_PKEY *_pkey = NULL;

    _pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (_pkey == NULL) {
        SUOLAerr(SUOLA_F_EVP_PKEY_CTX_ED25519_SET_PRIVATE, SUOLA_R_KEYS_NOT_SET);
        return -1;
    }

    return EVP_PKEY_ed25519_set_private(_pkey, sk);
}

int EVP_PKEY_ed25519_set_private(EVP_PKEY *pkey, const unsigned char sk[Ed25519_PRIVKEYLEN])
{
    Ed25519_KEYPAIR *oldkpair = NULL, *newkpair = NULL;
    int nid = NID_undef;

    oldkpair = EVP_PKEY_get0(pkey);
    /* don't use _is_invalid_private to test later for missing
     * private key */
    if (suola_keypair_is_invalid(oldkpair)) {
        SUOLAerr(SUOLA_F_EVP_PKEY_ED25519_SET_PRIVATE, SUOLA_R_INVALID_PRIVATE_KEY);
        goto err;
    }

    nid = oldkpair->nid;

    newkpair = ed25519_keypair_new(nid, NO_FLAG);
    if (suola_keypair_is_invalid_private(newkpair)) {
        SUOLAerr(SUOLA_F_EVP_PKEY_ED25519_SET_PRIVATE, SUOLA_R_INVALID_PRIVATE_KEY);
        goto err;
    }

    memcpy(newkpair->key.privk, sk, Ed25519_PRIVKEYLEN);

    if(!ed25519_sk_to_pk(newkpair->key.pubk.value, newkpair->key.privk)) {
        SUOLAerr(SUOLA_F_EVP_PKEY_ED25519_SET_PRIVATE, SUOLA_R_CANNOT_DERIVE_PK);
        goto err;
    }

    EVP_PKEY_assign(pkey, nid, newkpair);
    oldkpair = NULL; // free called by EVP_PKEY_assign
    return 1;
err:
    if (newkpair)
        ed25519_keypair_free(newkpair);
    return 0;
}

static int ed25519_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                    size_t *siglen, EVP_MD_CTX *mctx)
{
    verbose("CALLED\n");
    int md_nid = EVP_MD_CTX_type(mctx);

    if (md_nid == NID_identity_md ) {
        MD_IDENTITY_DATA *md_data = (MD_IDENTITY_DATA*)EVP_MD_CTX_md_data(mctx);
        if ( md_data == NULL) {
            errorf("md_data should never be NULL\n");
            return 0;
        }
        return ed25519_sign(ctx, sig, siglen, md_data->m, md_data->offset);
    } else {
        // FIXME: add support for NID_sha512 (prehash Ed25519)
        errorf("Unsupported MD: '%s'\n", OBJ_nid2ln(md_nid));
        return 0;
    }
}

static int ed25519_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                      int siglen, EVP_MD_CTX *mctx)
{
    verbose("CALLED\n");
    int md_nid = EVP_MD_CTX_type(mctx);

    if (md_nid == NID_identity_md ) {
        MD_IDENTITY_DATA *md_data = (MD_IDENTITY_DATA*)EVP_MD_CTX_md_data(mctx);
        if ( md_data == NULL) {
            errorf("md_data should never be NULL\n");
            return 0;
        }
        return ed25519_verify(ctx, sig, siglen, md_data->m, md_data->offset);
    } else {
        // FIXME: add support for NID_sha512 (prehash Ed25519)
        errorf("Unsupported MD: '%s'\n", OBJ_nid2ln(md_nid));
        return 0;
    }
}

static int ed25519_ctx_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    debug("STUB\n");
    return 1;
}

void suola_register_Ed25519(EVP_PKEY_METHOD *pmeth)
{
    EVP_PKEY_meth_set_keygen(pmeth, NULL, ed25519_keygen);
    EVP_PKEY_meth_set_sign(pmeth, NULL, ed25519_sign);
    EVP_PKEY_meth_set_verify(pmeth, NULL, ed25519_verify);
    EVP_PKEY_meth_set_ctrl(pmeth, ed25519_ctrl, NULL); // TODO: ed25519_ctrl_str

    EVP_PKEY_meth_set_signctx(pmeth, NULL, ed25519_signctx);
    EVP_PKEY_meth_set_verifyctx(pmeth, NULL, ed25519_verifyctx);


    EVP_PKEY_meth_set_copy(pmeth, ed25519_ctx_copy);

}

/* vim: set ts=4 sw=4 tw=78 et : */
