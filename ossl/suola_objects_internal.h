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

#ifndef SUOLA_OBJECTS_INTERNAL_H
#define SUOLA_OBJECTS_INTERNAL_H

#define suola_OID_identity_md "1.3.6.1.4.1.50263.0.1.1.1"
#define suola_SN_identity_md "identity_md"
#define suola_LN_identity_md "Libsuola identity message digest"

#define suola_OID_X25519   "1.3.101.110"
#define suola_SN_X25519    "X25519"
#define suola_LN_X25519    "EC DH X25519 through libsodium"

#define suola_OID_ED25519  "1.3.101.112"
#define suola_SN_ED25519   "ED25519"
#define suola_LN_ED25519   "Ed25519 through libsodium"

#endif /* SUOLA_OBJECTS_INTERNAL_H */
