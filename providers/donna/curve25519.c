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
#include "debug/debug.h"

#include "supercop_scalarmult.h"
#include "ed25519-donna/ed25519.h"

int suola_scalarmult_curve25519(unsigned char *Q, const unsigned char *n, const unsigned char *P)
{
    return crypto_scalarmult_curve25519(Q, n, P);
}

int suola_scalarmult_curve25519_base(unsigned char *Q, const unsigned char *n)
{
    curved25519_scalarmult_basepoint(Q, n);
    return 0;
}

/* vim: set ts=4 sw=4 tw=78 et : */


