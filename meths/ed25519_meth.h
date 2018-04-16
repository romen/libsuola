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

#ifndef _Ed25519_METH_H
#define _Ed25519_METH_H

#include <openssl/evp.h>

typedef struct {
    unsigned char *m;
    unsigned long long offset;
    unsigned long long len;
} ED25519_PKEY_CTX;

void suola_register_Ed25519(EVP_PKEY_METHOD *pmeth);

#include "suola_keypair.h"
int ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);
int EVP_PKEY_CTX_ed25519_set_private(EVP_PKEY_CTX *ctx, const unsigned char sk[Ed25519_PRIVKEYLEN]);
int EVP_PKEY_ed25519_set_private(EVP_PKEY *pkey, const unsigned char sk[Ed25519_PRIVKEYLEN]);

#endif /* _Ed25519_METH_H */

/* vim: set ts=4 sw=4 tw=78 et : */
