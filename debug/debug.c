#ifdef _DEBUG

#include "debug.h"

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h> /* getenv(), strtol() */
#include <errno.h>

static BIO *debug_out = NULL;
static BIO *debug_b64_out = NULL;

FILE *_dbgstream = NULL;
int debug_level = LOG_WARN;
char debug_brief = 0;

static void debug_out_init()
{
    if (debug_out || debug_b64_out ) return;

    debug_out = BIO_new_fp(_dbgstream, BIO_NOCLOSE);
    debug_b64_out = BIO_new(BIO_f_base64());
    BIO_push(debug_b64_out, debug_out);
}

static void debug_out_finish()
{
    if (debug_out)
        BIO_free(debug_out);
    if (debug_b64_out)
        BIO_free(debug_b64_out);
}

void debug_EVP_PKEY_print_private(EVP_PKEY *pkey)
{
    EVP_PKEY_print_private(debug_out, pkey, 0, 0);
}
void debug_EVP_PKEY_print_public(EVP_PKEY *pkey)
{
    EVP_PKEY_print_public(debug_out, pkey, 0, 0);
}

void debug_32B(int lvl, const void *pt)
{
    const unsigned char *p = pt;
    int i;
    if (lvl > debug_level) return;
    for(i=0;i<32;i++){
        fprintf(_dbgstream, "%02x:", p[i]);
    }
    fprintf(_dbgstream, "\n");
}

void _debug_print_b64(int lvl, const void *p, size_t len)
{
    if (lvl > debug_level) return;
    BIO_write(debug_b64_out, p, len);
    BIO_flush(debug_b64_out);
}

void debug_logging_init(int default_level, const char *envvar_name)
{
    char *var = NULL, *tmp = NULL;
    long val = -1;

    debug_level = default_level;
    _dbgstream = stderr;

    if ( !envvar_name || !(var=getenv(envvar_name)) )
        goto err;

    errno = 0;
    val = strtol(var, &tmp, 10);

    if ( errno || tmp == var || *tmp != '\0' ) {
        warn("Invalid value for %s\n", envvar_name);
        goto err;
    }

    if ( val < 0 ) {
        val = -val;
        debug_brief = 1;
    }

    debug_level = val;
err:
    debug_out_init();
    return;
}

void debug_logging_finish()
{
    debug_out_finish();
}


#endif // _DEBUG

/* vim: set ts=4 sw=4 tw=78 et : */
