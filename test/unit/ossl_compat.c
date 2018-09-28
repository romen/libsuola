#ifdef OPENSSL_V102_COMPAT

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "ossl_compat.h"

#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA EXTRA_str_functs[] = {
    {ERR_PACK(0, CRYPTO_F_OPENSSL_HEXSTR2BUF, 0), "OPENSSL_hexstr2buf"},
    {0, NULL}
};

static ERR_STRING_DATA EXTRA_str_reasons[] = {
    {ERR_PACK(0, 0, CRYPTO_R_ODD_NUMBER_OF_DIGITS), "odd number of hex digits"},
    {ERR_PACK(0, 0, CRYPTO_R_ILLEGAL_HEX_DIGIT), "illegal hex digit"},
    {0, NULL}
};

#endif

static int error_loaded = 0;

int ERR_load_EXTRA_strings(void)
{
    if (!error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(ERR_LIB_CRYPTO, EXTRA_str_functs);
        ERR_load_strings(ERR_LIB_CRYPTO, EXTRA_str_reasons);
#endif
        error_loaded = 1;
    }
    return 1;
}

void ERR_unload_EXTRA_strings(void)
{
    if (error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(ERR_LIB_CRYPTO, EXTRA_str_functs);
        ERR_unload_strings(ERR_LIB_CRYPTO, EXTRA_str_reasons);
#endif
        error_loaded = 0;
    }
}

static int OPENSSL_hexchar2int(unsigned char c)
{
#ifdef CHARSET_EBCDIC
    c = os_toebcdic[c];
#endif

    switch (c) {
    case '0':
        return 0;
    case '1':
        return 1;
    case '2':
        return 2;
    case '3':
        return 3;
    case '4':
          return 4;
    case '5':
          return 5;
    case '6':
          return 6;
    case '7':
          return 7;
    case '8':
          return 8;
    case '9':
          return 9;
    case 'a': case 'A':
          return 0x0A;
    case 'b': case 'B':
          return 0x0B;
    case 'c': case 'C':
          return 0x0C;
    case 'd': case 'D':
          return 0x0D;
    case 'e': case 'E':
          return 0x0E;
    case 'f': case 'F':
          return 0x0F;
    }
    return -1;
}



/*
 * Give a string of hex digits convert to a buffer
 */
unsigned char *OPENSSL_hexstr2buf(const char *str, long *len)
{
    unsigned char *hexbuf, *q;
    unsigned char ch, cl;
    int chi, cli;
    const unsigned char *p;
    size_t s;

    s = strlen(str);
    if ((hexbuf = OPENSSL_malloc(s >> 1)) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (p = (const unsigned char *)str, q = hexbuf; *p; ) {
        ch = *p++;
        if (ch == ':')
            continue;
        cl = *p++;
        if (!cl) {
            CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF,
                      CRYPTO_R_ODD_NUMBER_OF_DIGITS);
            OPENSSL_free(hexbuf);
            return NULL;
        }
        cli = OPENSSL_hexchar2int(cl);
        chi = OPENSSL_hexchar2int(ch);
        if (cli < 0 || chi < 0) {
            OPENSSL_free(hexbuf);
            CRYPTOerr(CRYPTO_F_OPENSSL_HEXSTR2BUF, CRYPTO_R_ILLEGAL_HEX_DIGIT);
            return NULL;
        }
        *q++ = (unsigned char)((chi << 4) | cli);
    }

    if (len)
        *len = q - hexbuf;
    return hexbuf;
}



#endif /* OPENSSL_V102_COMPAT */

/* vim: set ts=4 sw=4 tw=78 et : */
