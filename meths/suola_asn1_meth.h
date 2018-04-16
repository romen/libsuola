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

#ifndef _SUOLA_ASN1_METH_H
#define _SUOLA_ASN1_METH_H

#include <openssl/evp.h>


/* Example call:
 * suola_register_asn1_meth(  NID_ED25519,
 *                            &ameth,
 *                            "ED25519",
 *                            "Ed25519 through libsodium");
 */
int suola_register_asn1_meth(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char *pem_str, const char *info);

#endif /* _SUOLA_ASN1_METH_H */

/* vim: set ts=4 sw=4 tw=78 et : */
