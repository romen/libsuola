#include "apps.h"
#include "ossl_compat.h"

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "ossl/suola_objects.h"
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include <string.h>


#define LOAD_SUOLA

#ifdef LOAD_SUOLA
    #ifndef _DEBUG
        #define _DEBUG
    #endif /* _DEBUG */
    #include "meths/ed25519_meth.h"
#endif /* LOAD_SUOLA */

const char *prog_name = __FILE__;

void print_help()
{
    BIO_printf(bio_err,
            "Syntax: %s {op} {name} {privkey_hexstring}\n"
            "\t{op} is either:\n"
            "\t\t1\t : print private key\n"
            "\t\t2\t : print public key\n"
            "\t\t3\t : print both\n",
            prog_name);
    BIO_printf(bio_err,
            "\n"
            "EXAMPLE (print PEM private key):\n\t\"%s 1 %s %s\"\n",
            prog_name,
            "EVP_PKEY_EC:prime192v1",
            "323FA3169D8E9C6593F59476BC142000AB5BE0E249C43426");
    BIO_printf(bio_err,
            "\n"
            "EXAMPLE (print PEM public key):\n\t\"%s 2 %s %s\"\n",
            prog_name,
            "ED25519",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    return;
}

static EC_KEY *EC_KEY_new_set_private(int nid, const char *hexprivkey)
{
    const EC_GROUP *group = NULL;
    EC_POINT *pub_key = NULL;
    EC_KEY *eck = NULL;
    BIGNUM *bn = NULL;

    eck = EC_KEY_new_by_curve_name(nid);
    if(!eck) {
        BIO_printf(bio_err, "Error creating EC_KEY by nid=%i\n", nid);
        goto err;
    }

    int hexlen = BN_hex2bn(&bn, hexprivkey);
    if(strlen(hexprivkey)!=hexlen) {
        BIO_printf(bio_err, "Error creating BIGNUM\n");
        goto err;
    }

    if(!EC_KEY_set_private_key(eck, bn)) {
        BIO_printf(bio_err, "Error setting private key\n");
        goto err;
    }

    // generate the corresponding public key
    group = EC_KEY_get0_group(eck);
    pub_key = EC_POINT_new(group);

    if (!EC_POINT_mul(group, pub_key, bn, NULL, NULL, NULL)) {
        BIO_printf(bio_err, "Error deriving public key\n");
        goto err;
    }

    if (!EC_KEY_set_public_key(eck, pub_key)) {
        BIO_printf(bio_err, "Error setting public key\n");
        goto err;
    }

    return eck;

err:
    ERR_print_errors (bio_err);
    if(eck) EC_KEY_free(eck);
    if(bn) BN_free(bn);
    if(pub_key) EC_POINT_free(pub_key);
    return NULL;
}


EVP_PKEY *EVP_PKEY_set_private(const char *name, const char *hexprivkey)
{
    void *to_free = NULL;
    EVP_PKEY *pkey = NULL;

    ENGINE *e = NULL;
    int nid = NID_undef, subparam = 0;

    if ( 1 != EVP_PKEY_name_parser(&nid, &subparam, &e, name) ) {
        BIO_printf(bio_err, "Cannot identify %s\n", name);
        goto err;
    }

    pkey = EVP_PKEY_keygen_wrapper(nid, subparam, e);
    if (!pkey) {
        BIO_printf(bio_err, "Cannot generate key for %s\n", name);
        goto err;
    }

    if (!hexprivkey)
        return pkey;

    if (nid == EVP_PKEY_EC) {
        EC_KEY *eck = NULL;

        eck = EC_KEY_new_set_private(subparam, hexprivkey);
        if (!eck) {
            BIO_printf(bio_err, "Error setting EC_KEY private key\n");
            goto err;
        }
        if(!EVP_PKEY_set1_EC_KEY(pkey, eck)) {
            BIO_printf(bio_err, "Error setting EVP private key\n");
            goto err;
        }
#ifdef LOAD_SUOLA
    } else if (nid == NID_ED25519) {
        size_t len = 0;
        unsigned char *sk = OPENSSL_hexstr2buf(hexprivkey, &len);

        if (len != Ed25519_PRIVKEYLEN) {
            OPENSSL_free(sk);
            BIO_printf(bio_err, "Private key length should be exactly %u bytes (read %lu B)\n",
                    Ed25519_PRIVKEYLEN, len);
            goto err;
        }
        if (1 != EVP_PKEY_ed25519_set_private(pkey, sk)) {
            OPENSSL_free(sk);
            BIO_printf(bio_err, "Error setting EVP private key\n");
            goto err;
        }

        OPENSSL_free(sk);
#endif /* LOAD_SUOLA */
//  } else if (nid == EVP_PKEY_DSA) {
//  } else if (nid == EVP_PKEY_RSA) {
    } else {
            BIO_printf(bio_err, "%s NOT IMPLEMENTED for %s\n", __func__, name);
            goto err;
    }

    return pkey;
err:
    ERR_print_errors (bio_err);
    if(pkey) EVP_PKEY_free(pkey);
    return NULL;
}

enum op_type {
    UNDEF = -1,
    PRINT_PRIVATE = 0x1,
    PRINT_PUBLIC = 0x2,
    PRINT_BOTH = 0x3,
};

int main(int argc, char *argv[])
{
    EVP_PKEY *pkey = NULL;

    prog_name = argv[0];
    apps_init();
    enum op_type op = UNDEF;

    if(argc==4) {
        if(0==strcmp("1",argv[1])) op = PRINT_PRIVATE;
        if(0==strcmp("2",argv[1])) op = PRINT_PUBLIC;
        if(0==strcmp("3",argv[1])) op = PRINT_BOTH;
    }

    if(argc!=4 || op==UNDEF) {
        print_help();
        return -1;
    }

#ifdef LOAD_SUOLA
    const char *engine_id = "libsuola";
    setup_engine(engine_id, 0);
#endif

    const char *name = argv[2];
    const char *hexprivkey = argv[3];

    if (!(pkey = EVP_PKEY_set_private(name, hexprivkey)) ) {
        BIO_printf(bio_err, "Error setting EVP_PKEY\n");
        ERR_print_errors (bio_err);
        return 1;
    }

    if(op & PRINT_PRIVATE)
        if(!PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL)) {
            BIO_printf(bio_err, "Error writing PEM\n");
            ERR_print_errors (bio_err);
            return 1;
        }

    if(op & PRINT_PUBLIC)
        if(!PEM_write_PUBKEY(stdout, pkey)) {
            BIO_printf(bio_err, "Error writing PEM\n");
            ERR_print_errors (bio_err);
            return 1;
        }

    if(pkey) EVP_PKEY_free(pkey);
    BIO_free(bio_err);
    return 0;
}

/* vim: set ts=4 sw=4 tw=78 et : */
