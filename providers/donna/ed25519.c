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

#include "providers/api/ed25519.h"
#include "ed25519-donna/ed25519.h"
#include "debug/debug.h"

#include "suola_keypair.h"
#include <string.h> /* memset() */

int suola_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                    const unsigned char *seed)
{
    ed25519_publickey(seed, pk);
    return 0;
}

int suola_sign_ed25519_detached(unsigned char *sig,
                                unsigned long long *siglen_p,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *sk,
                                const unsigned char *pk)
{
    memset(sig, 0, Ed25519_SIGN_LENGTH);
    ed25519_sign(m, mlen, sk, pk, sig);
    *siglen_p = Ed25519_SIGN_LENGTH;

    return 0;
}

int suola_sign_ed25519_verify_detached(const unsigned char *sig,
                                       const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *pk)
{
    return ed25519_sign_open(m, mlen, pk, sig);
}

/* vim: set ts=4 sw=4 tw=78 et : */


