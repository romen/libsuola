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

#include "suola_keypair.h"
#include "ossl/suola_objects.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "ossl/suola_err.h"
#include "ossl/ossl_compat.h"

extern int X25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);
extern int ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);

struct suola_nid_data_st _suola_nid_data[] = {
    { "X25519",
        X25519_PRIVKEYLEN, X25519_PUBKEYLEN, X25519_sk_to_pk, NID_undef },
    { "ED25519",
        Ed25519_PRIVKEYLEN, Ed25519_PUBKEYLEN, ed25519_sk_to_pk, NID_undef /* NID_identity_md */},
};

inline const struct suola_nid_data_st *suola_get_nid_data(int nid)
{
    if (nid == NID_X25519) {
        return &_suola_nid_data[0];
    } else if (nid == NID_ED25519) {
        _suola_nid_data[1].default_md_nid = NID_identity_md;
        return &_suola_nid_data[1];
    }
    return NULL;
}


SUOLA_KEYPAIR *_suola_keypair_new(int nid,
                                  suola_keypair_flags_t flags)
{
    SUOLA_KEYPAIR *kpair = NULL;

    const struct suola_nid_data_st *nid_data = suola_get_nid_data(nid);
    if (nid_data == NULL)
        goto err;

    kpair = OPENSSL_secure_malloc(sizeof(*kpair));
    if (kpair == NULL) {
        SUOLAerr(SUOLA_F_KEYPAIR_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    kpair->nid = nid;
    kpair->has_private = 0;

    if (0 == (flags & NO_PRIV_KEY) ){
        kpair->has_private = 1;
    }

    return kpair;
err:
    if (kpair)
        OPENSSL_secure_free(kpair);

    return NULL;
}

int _suola_keypair_free(SUOLA_KEYPAIR *keypair)
{
    if (!keypair)
        return 0;

    OPENSSL_secure_free(keypair);

    return 1;
}

/* vim: set ts=4 sw=4 tw=78 et : */
