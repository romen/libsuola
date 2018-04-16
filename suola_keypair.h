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

#ifndef SUOLA_KEYPAIR_H
#define SUOLA_KEYPAIR_H

#include <openssl/obj_mac.h>

#define CURVE25519_BITS 253
#define CURVE25519_SECURITY_BITS 128

#define X25519_PUBKEYLEN        32U         // crypto_scalarmult_curve25519_BYTES
#define X25519_PRIVKEYLEN       32U         // crypto_scalarmult_curve25519_BYTES

#define Ed25519_PUBKEYLEN       32U         // crypto_sign_ed25519_PUBLICKEYBYTES
#define Ed25519_PRIVKEYLEN      32U         // crypto_sign_ed25519_SEEDBYTES
#define Ed25519_EXP_PRIVKEYLEN  (32U + 32U) // crypto_sign_ed25519_SECRETKEYBYTES
#define Ed25519_SIGN_LENGTH     64U         // crypto_sign_ed25519_BYTES


#include <stdint.h> /* uint8_t */
#include <stddef.h> /* size_t */

typedef struct {
    union {
        uint8_t privk[64];
        struct {
            /* Shift the location of the public key to the last 32B */
            uint8_t pad[32];
            uint8_t value[32];
        } pubk;
    } key;
    int nid;
    char has_private;
} SUOLA_KEYPAIR;

typedef enum {
    NO_FLAG=0,
    NO_PRIV_KEY=1,
} suola_keypair_flags_t;

SUOLA_KEYPAIR *_suola_keypair_new(int nid,
                                  suola_keypair_flags_t flags);

int _suola_keypair_free(SUOLA_KEYPAIR *keypair);

struct suola_nid_data_st {
    const char *name;
    size_t privk_bytes;
    size_t pubk_bytes;
    int (*sk_to_pk)(unsigned char *pk, const unsigned char *sk);
    int default_md_nid;
};

const struct suola_nid_data_st *suola_get_nid_data(int nid);

#define _suola_keypair_is_invalid(kp, contains_private) \
    ( (kp) == NULL || ( (contains_private) && (1 != (kp)->has_private) ) || \
      NULL == suola_get_nid_data( (kp)->nid) )

#define suola_keypair_is_invalid(kp) \
    _suola_keypair_is_invalid((kp), 0)
#define suola_keypair_is_invalid_private(kp) \
    _suola_keypair_is_invalid((kp), 1)

#endif /* SUOLA_KEYPAIR_H */

/* vim: set ts=4 sw=4 tw=78 et : */
