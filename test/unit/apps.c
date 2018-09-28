#include "apps.h"

#include "ossl_compat.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/conf.h>

#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

BIO *bio_err = NULL;

void apps_init(void)
{
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

#ifndef OPENSSL_V102_COMPAT
    OPENSSL_init_crypto(
            OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_DYNAMIC,
            NULL);
#else
    if(!ERR_load_EXTRA_strings()) {
        fprintf(stderr, "ERR_load_EXTRA_strings failed\n");
        return;
    }

    OPENSSL_config(NULL);
#endif
}

#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}
#endif

ENGINE *setup_engine(const char *engine, int debug)
{
    ENGINE *e = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (strcmp(engine, "auto") == 0) {
            BIO_printf(bio_err, "enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL
            && (e = try_load_engine(engine)) == NULL) {
            BIO_printf(bio_err, "invalid engine \"%s\"\n", engine);
            ERR_print_errors(bio_err);
            return NULL;
        }
        if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
        }
        //ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1);
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            BIO_printf(bio_err, "can't use that engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(e);
            return NULL;
        }

        BIO_printf(bio_err, "engine \"%s\" set.\n", ENGINE_get_id(e));
    }
#endif
    return e;
}

void release_engine(ENGINE *e)
{
#ifndef OPENSSL_NO_ENGINE
    if (e != NULL)
        /* Free our "structural" reference. */
        ENGINE_free(e);
#endif
}

EVP_PKEY *EVP_PKEY_keygen_wrapper(int nid, int arg2, ENGINE *engine)
{
    int st = 0;
    // PARAMETER GENERATION ---------- {{{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;

    /* Create the context for generating the parameters */
    if (!(pctx = EVP_PKEY_CTX_new_id(nid, engine))) {
        BIO_printf(bio_err,
                   "%s: Failure in parameters ctx generation\n",
                   OBJ_nid2sn(nid));
        goto evp_keygen_err;
    }
    ERR_set_mark();
    if (!EVP_PKEY_paramgen_init(pctx)) {
        BIO_printf(bio_err, "%s: Failure in paramgen init\n", OBJ_nid2sn(nid));
        goto evp_keygen_err;
    }
    ERR_pop_to_mark();

    /* Set the paramgen parameters according to the type */
    switch (nid) {
    case EVP_PKEY_EC:
        /* Use arg2 as the NID for a named curve - defined in obj_mac.h */
        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, arg2)) {
            BIO_printf(bio_err,
                       "%s: Failure in setting the curve nid: %d (%s)\n",
                       OBJ_nid2sn(nid), arg2, OBJ_nid2sn(arg2));
            goto evp_keygen_err;
        }
        break;

    case EVP_PKEY_DSA:
        /* Set a bit length of arg2 bits */
        if (!EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, arg2)) {
            BIO_printf(bio_err,
                       "%s: Failure in setting key bits: %d\n",
                       OBJ_nid2sn(nid), arg2);
            goto evp_keygen_err;
        }
        break;

    case EVP_PKEY_DH:
        /* Set a bit length of arg2 bits */
        if (!EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, arg2)) {
            BIO_printf(bio_err,
                       "%s: Failure in setting key bits: %d\n",
                       OBJ_nid2sn(nid), arg2);
            goto evp_keygen_err;
        }
        break;
    }

    /* Generate parameters */
    ERR_set_mark();
    st = EVP_PKEY_paramgen(pctx, &params);
    if (st != 1 && st != -2) {
        BIO_printf(bio_err,
                   "%s: Failure in params generation (returned %d)\n",
                   OBJ_nid2sn(nid), st);
        goto evp_keygen_err;
    } else if (st == -2) {
        ERR_pop_to_mark();
    }
    // }}} ---------- PARAMETER GENERATION

    // {{{ KEY GENERATION ----------
    if (params != NULL) {
        kctx = EVP_PKEY_CTX_new(params, engine);
    } else {
        /* Create context for the key generation */
        kctx = EVP_PKEY_CTX_new_id(nid, engine);
    }
    if (!kctx) {
        BIO_printf(bio_err,
                   "%s: Failure in keygen ctx generation\n", OBJ_nid2sn(nid));
        goto evp_keygen_err;
    }

    if (!EVP_PKEY_keygen_init(kctx)) {
        BIO_printf(bio_err, "%s: Failure in keygen init\n", OBJ_nid2sn(nid));
        goto evp_keygen_err;
    }

    /* RSA keys set the key length during key generation rather than parameter generation! */
    if (nid == EVP_PKEY_RSA) {
        if (!EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, arg2)) {
            BIO_printf(bio_err,
                       "%s: Failure in setting key bits: %d\n",
                       OBJ_nid2sn(nid), arg2);
            goto evp_keygen_err;
        }
    }

    /* Generate the key */
    if (!EVP_PKEY_keygen(kctx, &pkey)) {
        BIO_printf(bio_err,
                   "%s: Failure in key generation\n", OBJ_nid2sn(nid));
        goto evp_keygen_err;
    }
    // }}} ---------- KEY GENERATION

    goto evp_keygen_end;
 evp_keygen_err:
    ERR_print_errors(bio_err);
    pkey = NULL;
 evp_keygen_end:
    if (params)
        EVP_PKEY_free(params);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (kctx)
        EVP_PKEY_CTX_free(kctx);
    return pkey;
}

int EVP_PKEY_name_parser(int *_nid, int *_subparam, ENGINE **_e, const char *name)
{
    int rt = 0;
    int nid = NID_undef;
    const char * arg2;
    int subparam = 0;
    ENGINE *e = NULL;

    size_t len = strlen(name);

    if (len > 12 && !strncmp(name, "EVP_PKEY_EC:", 12)) {
        nid = EVP_PKEY_EC;
        arg2 = &name[12];
        subparam = OBJ_sn2nid(arg2);
    } else if (len > 13 && !strncmp(name, "EVP_PKEY_DSA:", 13)) {
        nid = EVP_PKEY_DSA;
        ((char *)name)[12] = '\0';
        arg2 = &name[13];
        subparam = (int)strtol(arg2, NULL, 10);
    } else if (len > 13 && !strncmp(name, "EVP_PKEY_RSA:", 13)) {
        nid = EVP_PKEY_RSA;
        ((char *)name)[12] = '\0';
        arg2 = &name[13];
        subparam = (int)strtol(arg2, NULL, 10);
    } else {
        nid = OBJ_sn2nid(name);
        subparam = 0;

        if (nid == NID_undef) {
            BIO_printf(bio_err,
                    "%s is an unknown algorithm\n", name);
            goto end;
        }
        EVP_PKEY_asn1_find(&e, nid);
    }

    *_nid = nid;
    *_subparam = subparam;
    *_e = e;
    rt = 1;
end:
    return rt;
}

/* vim: set ts=4 sw=4 tw=78 et : */
