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

#include "meths/X25519_meth.h"
#include "debug/debug.h"

#include "providers/api/rng.h"
#include "providers/api/curve25519.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "ossl/suola_err.h"
#include <openssl/ec.h>

#include "ossl/suola_objects.h"
#include "suola_keypair.h"

#define X25519_SHAREDLEN X25519_PUBKEYLEN

typedef SUOLA_KEYPAIR X25519_KEYPAIR;

#define X25519_keypair_new(flags) \
    _suola_keypair_new(NID_X25519, (flags))
#define X25519_keypair_free(kpair) \
    _suola_keypair_free((kpair))

static int X25519_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) 
{
    /* adapted from pkey_ecx_derive@openssl/crypto/ec/ecx_meth.c */
    EVP_PKEY *_pkey, *_peerkey;
    const X25519_KEYPAIR *pkey, *peerkey;

    _pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    _peerkey = EVP_PKEY_CTX_get0_peerkey(ctx);

    if (_pkey == NULL || _peerkey == NULL) {
        SUOLAerr(SUOLA_F_X25519_DERIVE, SUOLA_R_KEYS_NOT_SET);
        return 0;
    }
    pkey = EVP_PKEY_get0(_pkey);
    peerkey = EVP_PKEY_get0(_peerkey);
    if (suola_keypair_is_invalid_private(pkey)) {
        SUOLAerr(SUOLA_F_X25519_DERIVE, SUOLA_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    if (suola_keypair_is_invalid(peerkey)) {
        SUOLAerr(SUOLA_F_X25519_DERIVE, SUOLA_R_INVALID_PEER_KEY);
        return 0;
    }
    *keylen = X25519_SHAREDLEN;

    // suola_scalarmult success: 0, fail, nz
    if (key != NULL &&
            suola_scalarmult_curve25519(key, pkey->key.privk,
                                        peerkey->key.pubk.value))
        return 0;

    return 1;
}

int X25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
{
    if ( 0 != suola_scalarmult_curve25519_base(pk, sk)) {
        SUOLAerr(SUOLA_F_X25519_SK_TO_PK, SUOLA_R_IMPLEMENTATION_BACKEND_UNEXPECTED_RETURN);
        return 0;
    }
    return 1;
}

static int X25519_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    X25519_KEYPAIR *kpair = NULL;

    kpair = X25519_keypair_new(NO_FLAG);
    if (suola_keypair_is_invalid_private(kpair)) {
        SUOLAerr(SUOLA_F_X25519_KEYGEN, SUOLA_R_INVALID_PRIVATE_KEY);
        return 0;
    }

    suola_randombytes_buf(kpair->key.privk, X25519_PRIVKEYLEN);

    if (!X25519_sk_to_pk(kpair->key.pubk.value, kpair->key.privk)) {
        SUOLAerr(SUOLA_F_X25519_KEYGEN, SUOLA_R_RANDOM_NUMBER_GENERATION_FAILED);
        goto err;
    }

    EVP_PKEY_assign(pkey, NID_X25519, kpair);
    return 1;
err:
    if (kpair)
        X25519_keypair_free(kpair);
    return 0;
}

static int X25519_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    /* from pkey_ecx_ctrl@openssl/crypto/ec/ecx_meth.c */
    /* Only need to handle peer key for derivation */
    if (type == EVP_PKEY_CTRL_PEER_KEY)
        return 1;
    return -2;
}

void suola_register_X25519(EVP_PKEY_METHOD *pmeth)
{
    EVP_PKEY_meth_set_derive(pmeth, NULL, X25519_derive);
    EVP_PKEY_meth_set_keygen(pmeth, NULL, X25519_keygen);
    EVP_PKEY_meth_set_ctrl(pmeth, X25519_ctrl, NULL);
}

/* vim: set ts=4 sw=4 tw=78 et : */
