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

#ifndef _SCALARMULT_FROM_SUPERCOP_H
#define _SCALARMULT_FROM_SUPERCOP_H

#ifdef _SCALARMULT_CURVE25519_NEON2
#define crypto_scalarmult_curve25519 crypto_scalarmult_curve25519_neon2
int crypto_scalarmult_curve25519_neon2(unsigned char *mypublic,
                                       const unsigned char *secret,
                                       const unsigned char *basepoint);
#endif /* defined(_SCALARMULT_CURVE25519_NEON2) */

#ifndef crypto_scalarmult_curve25519
#define crypto_scalarmult_curve25519 crypto_scalarmult
int crypto_scalarmult(unsigned char *mypublic,
                      const unsigned char *secret,
                      const unsigned char *basepoint);
#endif /* !defined(crypto_scalarmult_curve25519) */

#endif /* !defined(_SCALARMULT_FROM_SUPERCOP_H) */

/* vim: set ts=4 sw=4 tw=78 et : */
