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

#include <string.h> /* memcpy() */
#include <openssl/engine.h>
#include <openssl/obj_mac.h>

#include "ossl/ossl_compat.h"

#include "meths/X25519_meth.h"
#include "meths/ed25519_meth.h"

#include "meths/suola_asn1_meth.h"
#include "ossl/suola_objects.h"
#include "meths/suola_md_identity_meth.h"

#include "ossl/suola_err.h"

#include "debug/debug.h"

#include "providers/api/base.h"

#define SUOLA_DEBUG_ENVVAR "SUOLA_DEBUG"
#define SUOLA_DEBUG_DEFAULT_LEVEL LOG_WARN

#ifndef SUOLA_ENGINE_ID
#define SUOLA_ENGINE_ID "libsuola"
#endif /* !defined(SUOLA_ENGINE_ID) */

#ifndef SUOLA_ENGINE_NAME
#define SUOLA_ENGINE_NAME "An engine gluing together OpenSSL and libsodium"
#endif /* !defined(SUOLA_ENGINE_NAME) */

static const char *engine_id = SUOLA_ENGINE_ID;
static const char *engine_name = SUOLA_ENGINE_NAME ".";

static int suola_register_methods();

/* --------------- PKEY methods ---------------- */
static int suola_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);

static int suola_pkey_meth_nids[] = {
    0 /* NID_X25519 */,
    0 /* NID_ED25519 */,
    0
};

static void suola_pkey_meth_nids_init()
{
    suola_pkey_meth_nids[0] = NID_X25519;
    suola_pkey_meth_nids[1] = NID_ED25519;
}

static EVP_PKEY_METHOD *pmeth_X25519 = NULL;
static EVP_PKEY_METHOD *pmeth_Ed25519 = NULL;

/* --------------- ASN1 methods ---------------- */

static int suola_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid);
static int suola_register_ameth(int id, EVP_PKEY_ASN1_METHOD **ameth, int flags);

static int suola_pkey_asn1_meth_nids[] = {
    0 /* NID_X25519 */,
    0 /* NID_ED25519 */,
    0
};

static void suola_pkey_asn1_meth_nids_init()
{
    suola_pkey_asn1_meth_nids[0] = NID_X25519;
    suola_pkey_asn1_meth_nids[1] = NID_ED25519;
}

static EVP_PKEY_ASN1_METHOD *ameth_X25519 = NULL;
static EVP_PKEY_ASN1_METHOD *ameth_Ed25519 = NULL;

/* --------------- MD methods ---------------- */
static int suola_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);

static int suola_digests_nids[] = {
    0 /* NID_identity_md */,
    0
};

static int suola_digests_nids_init()
{
    suola_digests_nids[0] = NID_identity_md;
}

static EVP_MD *md_identity = NULL;

static int suola_e_init(ENGINE *e)
{
    verbose("STUB\n");
    return 1;
}

static int suola_e_destroy(ENGINE *e)
{
    verbose("CALLED\n");

    debug_logging_finish();
    ERR_unload_SUOLA_strings();
    OBJ_cleanup();

#ifdef OPENSSL_V102_COMPAT
    if (md_identity != NULL) {
        OPENSSL_free(md_identity);
        md_identity = NULL;
    }
#endif /* OPENSSL_V102_COMPAT */

    return 1;
}

static int suola_e_finish(ENGINE *e)
{
    verbose("STUB\n");
    return 1;
}

static int suola_bind(ENGINE *e, const char *id)
{
    debug_logging_init(SUOLA_DEBUG_DEFAULT_LEVEL, SUOLA_DEBUG_ENVVAR);

    verbose("CALLED\n");
    int ret = 0;
    if (!ENGINE_set_id(e, engine_id)) {
        errorf("ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        errorf("ENGINE_set_name failed\n");
        goto end;
    }

    if(!ENGINE_set_init_function(e, suola_e_init)) {
        errorf("ENGINE_set_init_function failed\n");
        goto end;
    }
    if(!ENGINE_set_destroy_function(e, suola_e_destroy)) {
        errorf("ENGINE_set_destroy_function failed\n");
        goto end;
    }
    if(!ENGINE_set_finish_function(e, suola_e_finish)) {
        errorf("ENGINE_set_finish_function failed\n");
        goto end;
    }

    if (!ERR_load_SUOLA_strings()) {
        errorf("ERR_load_SUOLA_strings failed\n");
        goto end;
    }

    if (!suola_register_nids()) {
        errorf("Failure registering NIDs\n");
        goto end;
    } else {
        suola_pkey_meth_nids_init();
        suola_pkey_asn1_meth_nids_init();
        suola_digests_nids_init();
    }

    if (!suola_register_methods()) {
        errorf("Failure registering methods\n");
        goto end;
    }

    if (!ENGINE_set_digests(e, suola_digests)) {
        errorf("ENGINE_set_digests failed\n");
        goto end;
    }

    if (!ENGINE_set_pkey_asn1_meths(e, suola_pkey_asn1_meths)) {
        errorf("ENGINE_set_pkey_asn1_meths failed\n");
        goto end;
    }


    if (!ENGINE_set_pkey_meths(e, suola_pkey_meths)) {
        errorf("ENGINE_set_pkey_meths failed\n");
        goto end;
    }

    if (suola_implementation_init() != 0) {
        errorf("suola_implementation_init failed\n");
        goto end;
    }

    ret = 1;
end:
    return ret;
}

#define sizeof_static_array(a) \
    ( (sizeof((a))) / sizeof((a)[0]) )

static int suola_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
    if(!pmeth) {
        debug("GET LIST\n");
        *nids = suola_pkey_meth_nids;
        return sizeof_static_array(suola_pkey_meth_nids) - 1;
    }
    debug("NID(%d/%s) ->", nid, OBJ_nid2sn(nid));

    if (nid == NID_X25519) {
        *pmeth = pmeth_X25519;
        debug_sl("pmeth_X25519\n");
        return 1;
    } else if (nid == NID_ED25519) {
        *pmeth = pmeth_Ed25519;
        debug_sl("pmeth_Ed25519\n");
        return 1;
    }

    debug_sl("NOT FOUND\n");
    *pmeth = NULL;
    return 0;
}

/* Register a new EVP_PKEY_METHOD for alg id under given flags */
static int suola_register_pmeth(int id, EVP_PKEY_METHOD **pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(id, flags);

    if (*pmeth == NULL)
        return 0;

    if (id == NID_X25519) {
        suola_register_X25519(*pmeth);
    } else if (id == NID_ED25519) {
        suola_register_Ed25519(*pmeth);
    } else {
        /* Unsupported method */
        return 0;
    }

    return 1;
}

static int suola_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid)
{
    if(!ameth) {
        debug("GET LIST\n");
        *nids = suola_pkey_asn1_meth_nids;
        return sizeof_static_array(suola_pkey_asn1_meth_nids) - 1;
    }
    debug("NID(%d/%s) ->", nid, OBJ_nid2sn(nid));

    if (nid == NID_X25519) {
        *ameth = ameth_X25519;
        debug_sl("ameth_X25519\n");
        return 1;
    } else if (nid == NID_ED25519) {
        *ameth = ameth_Ed25519;
        debug_sl("ameth_Ed25519\n");
        return 1;
    }

    debug_sl("NOT FOUND\n");
    *ameth = NULL;
    return 0;
}

/* Register a new EVP_PKEY_ASN1_METHOD for alg id under given flags */
static int suola_register_ameth(int id, EVP_PKEY_ASN1_METHOD **ameth, int flags)
{
    const char *pem_str = NULL;
    const char *info = NULL;

    if (!ameth)
        return 0;

    if (id == NID_X25519) {
        pem_str = OBJ_nid2sn(id);
        info = "EC DH X25519 through libsodium";
    } else if (id == NID_ED25519) {
        pem_str = OBJ_nid2sn(id);
        info = "Ed25519 through libsodium";
    } else {
        /* Unsupported method */
        return 0;
    }

    return suola_register_asn1_meth(id, ameth, pem_str, info);
}

static int suola_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    if (!digest) {
        debug("GET LIST\n");
        *nids = suola_digests_nids;
        return sizeof_static_array(suola_digests_nids) - 1;
    }
    debug("NID(%d/%s) ->", nid, OBJ_nid2sn(nid));

    if ( nid == NID_identity_md && nid != NID_undef ) {
        *digest = md_identity;
        debug_sl("md_identity\n");
        return 1;
    }

    debug_sl("NOT FOUND\n");
    *digest = NULL;
    return 0;
}


/* Register a new EVP_MD for alg md_id under given flags */
static int suola_register_md(int md_id, int pkey_type, EVP_MD **md, int flags)
{
    int ret = 0;
    debug("registering md method for '%s' with md_id=%d, pkey_type=%d, flags=%08x\n",
            OBJ_nid2ln(md_id), md_id, pkey_type, flags);

    *md = EVP_MD_meth_new(md_id, pkey_type);

    if (*md == NULL)
        return 0;

    if ( md_id == NID_identity_md ) {
        suola_register_md_identity(*md);
        ret = 1;
    }

    if (ret == 1) {
        ret = EVP_add_digest(*md);
        return ret;
    }

    /* Unsupported md type */
    return 0;
}


static int suola_register_methods()
{
    /* AMETHS ----- {{{ */
    if (!suola_register_ameth(NID_X25519, &ameth_X25519, 0)) {
        return 0;
    }
    if (!suola_register_ameth(NID_ED25519, &ameth_Ed25519, 0)) {
        return 0;
    }
    /* }}} ----- AMETHS */

    /* PMETHS ----- {{{ */
    if (!suola_register_pmeth(NID_X25519, &pmeth_X25519, 0)) {
        return 0;
    }
    if (!suola_register_pmeth(NID_ED25519, &pmeth_Ed25519, 0)) {
        return 0;
    }
    /* }}} ----- PMETHS */

    /* MD ----- {{{ */
    if (!suola_register_md(NID_identity_md , NID_ED25519, &md_identity, 0)) {
        return 0;
    }
    /* }}} ----- MD */

    return 1;
}




IMPLEMENT_DYNAMIC_BIND_FN(suola_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()

/* vim: set ts=4 sw=4 tw=78 et : */
