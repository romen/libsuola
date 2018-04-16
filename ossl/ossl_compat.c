#ifdef OPENSSL_V102_COMPAT

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "ossl_compat.h"

#include <string.h> // memcpy


EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type)
{
	EVP_MD *ret = OPENSSL_zalloc(sizeof(*ret));

	if (ret != NULL) {
		ret->type = md_type;
		// FIXME: we are discarding pkey_type
	}

	return ret;
}

#define _EVP_MD_meth_set(md, field, value) \
	{ \
		if ( (md) == NULL) { \
			return 0; \
		} \
		md->field = (value); \
		return 1; \
	}

int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize)
	_EVP_MD_meth_set(md, md_size, resultsize)

int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize)
	_EVP_MD_meth_set(md, ctx_size, datasize)

int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx))
	_EVP_MD_meth_set(md, init, init)

int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count))
	_EVP_MD_meth_set(md, update, update)

int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx, unsigned char *md))
	_EVP_MD_meth_set(md, final, final)

int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to, const EVP_MD_CTX *from))
	_EVP_MD_meth_set(md, copy, copy)

int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx))
	_EVP_MD_meth_set(md, cleanup, cleanup)



void *OPENSSL_memdup(const void *src, size_t size)
{
	void *ret = OPENSSL_malloc(size);
	if (ret != NULL) {
		memcpy(ret, src, size);
	}
	return ret;
}

void CRYPTO_clear_free(void *src, size_t oldlen, const char *file, int line)
{
    if (src == NULL)
        return;
    if (oldlen > 0)
        OPENSSL_cleanse(src, oldlen);
    CRYPTO_free(src);
}

void *CRYPTO_clear_realloc(void *src, size_t oldlen, size_t newlen, const char *file, int line)
{
    void *ret = NULL;

    if (src == NULL)
        return CRYPTO_malloc(newlen, file, line);

    if (newlen == 0) {
        CRYPTO_clear_free(src, oldlen, file, line);
        return NULL;
    }

    /* Can't shrink the buffer since memcpy below copies |oldlen| bytes. */
    if (newlen < oldlen) {
        OPENSSL_cleanse((char*)src + newlen, oldlen - newlen);
        return src;
    }

    ret = CRYPTO_malloc(newlen, file, line);
    if (ret != NULL) {
        memcpy(ret, src, oldlen);
        CRYPTO_clear_free(src, oldlen, file, line);
    }
    return ret;
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = CRYPTO_malloc(num, file, line);

    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}


/* Number of octets per line */
#define ASN1_BUF_PRINT_WIDTH    15
/* Maximum indent */
#define ASN1_PRINT_MAX_INDENT 128

int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int indent)
{
    size_t i;

    for (i = 0; i < buflen; i++) {
        if ((i % ASN1_BUF_PRINT_WIDTH) == 0) {
            if (i > 0 && BIO_puts(bp, "\n") <= 0)
                return 0;
            if (!BIO_indent(bp, indent, ASN1_PRINT_MAX_INDENT))
                return 0;
        }
        /*
         * Use colon separators for each octet for compatibility as
         * this function is used to print out key components.
         */
        if (BIO_printf(bp, "%02x%s", buf[i],
                       (i == buflen - 1) ? "" : ":") <= 0)
                return 0;
    }
    if (BIO_write(bp, "\n", 1) <= 0)
        return 0;
    return 1;
}

#endif /* OPENSSL_V102_COMPAT */
