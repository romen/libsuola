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

#include "providers/api/curve25519.h"
#include <hacl/Hacl_Curve25519.h>
#include "debug/debug.h"

int suola_scalarmult_curve25519(unsigned char *Q, const unsigned char *n, const unsigned char *P)
{
    Hacl_EC_crypto_scalarmult(Q, n, P);
    return 0;
}

static const uint8_t curve25519_bp[32] = {9};

int suola_scalarmult_curve25519_base(unsigned char *Q, const unsigned char *n)
{
    Hacl_EC_crypto_scalarmult(Q, n, curve25519_bp);
    return 0;
}

/* vim: set ts=4 sw=4 tw=78 et : */


