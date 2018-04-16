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

#ifndef SUOLA_MD_IDENTITY_MD_H
#define SUOLA_MD_IDENTITY_MD_H

#include <openssl/evp.h>

typedef struct {
    unsigned char *m;
    unsigned long long offset;
    unsigned long long len;
} MD_IDENTITY_DATA;

void suola_register_md_identity(EVP_MD * md);

#endif /* SUOLA_MD_IDENTITY_MD_H */

/* vim: set ts=4 sw=4 tw=78 et : */
