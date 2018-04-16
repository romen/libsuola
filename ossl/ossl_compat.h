#ifdef OPENSSL_V102_COMPAT

#ifndef HEADER_OSSL_COMPAT_H
#define HEADER_OSSL_COMPAT_H

#define EVP_MD_CTX_md_data(ctx) ((ctx)->md_data)
EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type);
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize);
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize);
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx));
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count));
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md));
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to,
                                                 const EVP_MD_CTX *from));
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx));


#define OPENSSL_secure_malloc(a) OPENSSL_malloc(a)
#define OPENSSL_secure_free(a) OPENSSL_free(a)
void *OPENSSL_memdup(const void *src, size_t size);
#define OPENSSL_clear_free(ptr, oldsize) \
	CRYPTO_clear_free(ptr, oldsize, __FILE__, __LINE__)
void CRYPTO_clear_free(void *src, size_t oldlen, const char *file, int line);
#define OPENSSL_clear_realloc(src, oldlen, newlen) \
	CRYPTO_clear_realloc(src, oldlen, newlen, __FILE__, __LINE__)
void *CRYPTO_clear_realloc(void *s, size_t oldlen, size_t newlen, const char *file, int line);
void *OPENSSL_zalloc(size_t size);
#define OPENSSL_zalloc(size) CRYPTO_zalloc(size, __FILE__, __LINE__)
void *CRYPTO_zalloc(size_t num, const char *file, int line);

int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int indent);
#define ASN1_STRING_get0_data(x) ((x)->data)

#endif /* HEADER_OSSL_COMPAT_H */

#endif /* OPENSSL_V102_COMPAT */
