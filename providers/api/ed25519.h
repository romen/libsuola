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

#ifndef LIBSUOLA_ED25519_API_H
#define LIBSUOLA_ED25519_API_H

/* Deterministically generate a secret key and a corresponding public key.
 *
 * Arguments:
 *  pk:     where to put the public key (Ed25519_PUBKEYLEN bytes)
 *  sk:     where to put the secret key (Ed25519_EXP_PRIVKEYLEN bytes)
 *  seed:   the random seed to be used (Ed25519_PRIVKEYLEN bytes)
 *
 * Return:
 *  0 on success, non-0 otherwise.
 */
extern int suola_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);

/* Signs a message using a secret key in detached mode.
 *
 * In detached mode, the signature is stored without attaching a copy of the
 * original message to it.
 *
 * Arguments:
 *  sig:        where to put the signature (up to Ed25519_SIGN_LENGT bytes)
 *  siglen_p:   where to store the effective signature length (if not NULL)
 *              (if not NULL! it is safe to ignore siglen, the returned sig
 *              buffer is padded with zeros if necessary)
 *  m:          the message to be signed
 *  mlen:       lenght of the message m
 *  sk:         secret key to be used to generate the signature
 *  pk:         corresponding public key
 *
 * Returns 0 on success, non-0 otherwise.
 */
extern int suola_sign_ed25519_detached(unsigned char *sig,
                                       unsigned long long *siglen_p,
                                       const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *sk,
                                       const unsigned char *pk);

/* Verifies the detached signature on a message under a public key.
 *
 * In detached mode, the signature is stored without attaching a copy of the
 * original message to it.
 *
 * Arguments:
 *  sig:        the signature to be verified
 *  m:          the message associated to the signature
 *  mlen:       lenght of the message m
 *  pk:         signer's public key
 *
 * Returns 0 on success, -1 if the signature fails verification.
 */
extern int suola_sign_ed25519_verify_detached(const unsigned char *sig,
                                              const unsigned char *m,
                                              unsigned long long mlen,
                                              const unsigned char *pk)
       __attribute__ ((warn_unused_result));

#endif /* ! defined( LIBSUOLA_ED25519_API_H) */

/* vim: set ts=4 sw=4 tw=78 et : */
