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

#include "suola_objects.h"
#include "debug/debug.h"

#include "suola_objects_internal.h"

int NID_identity_md;
int NID_X25519;
int NID_ED25519;


static int _suola_register_nid(const char *oid_str, const char *sn, const char *ln) {
    int new_nid = NID_undef;

    if (NID_undef != (new_nid = OBJ_sn2nid(sn)) ) {
        debug("'%s' is already registered with NID %d\n", sn, new_nid);
        return new_nid;
    }

    new_nid = OBJ_create(oid_str, sn, ln);

    if (new_nid == NID_undef) {
        fatalf("Failed to register NID for '%s'\n", ln);
        return 0;
    }
    debug("Registered '%s' with NID %d\n", sn, new_nid);

    ASN1_OBJECT *obj = OBJ_nid2obj(new_nid);
    if ( !obj ) {
        fatalf("Failed to retrieve ASN1_OBJECT for dinamically registered NID\n");
        return 0;
    }

    return new_nid;
}

#define SUOLA_REGISTER_NID(___BASENAME) \
    if ( NID_undef == (NID_##___BASENAME = _suola_register_nid(  suola_OID_##___BASENAME, \
                                                                 suola_SN_##___BASENAME , \
                                                                 suola_LN_##___BASENAME ))\
       ) { \
        errorf("Failed to register NID for '%s'\n", suola_SN_##___BASENAME ); \
        return 0; \
    }


int suola_register_nids()
{
    SUOLA_REGISTER_NID(identity_md);

    SUOLA_REGISTER_NID(X25519);

    SUOLA_REGISTER_NID(ED25519);

    return 1;
}


/* vim: set ts=4 sw=4 tw=78 et : */
