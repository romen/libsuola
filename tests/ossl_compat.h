#ifdef OPENSSL_V102_COMPAT

#ifndef HEADER_TESTS_OSSL_COMPAT_H
#define HEADER_TESTS_OSSL_COMPAT_H

/* OPENSSL_hexstr2buf() parses str as a hex string and returns a pointer to
 * the parsed value. The memory is allocated by calling OPENSSL_malloc() and
 * should be released by calling OPENSSL_free(). If len is not NULL, it is
 * filled in with the output length. Colons between two-character hex "bytes"
 * are ignored. An odd number of hex digits is an error. */
unsigned char *OPENSSL_hexstr2buf(const char *str, long *len);

int ERR_load_EXTRA_strings(void);
void ERR_unload_EXTRA_strings(void);

#define CRYPTO_F_OPENSSL_HEXSTR2BUF     200

#define CRYPTO_R_ODD_NUMBER_OF_DIGITS   200
#define CRYPTO_R_ILLEGAL_HEX_DIGIT      201

#endif /* HEADER_TESTS_OSSL_COMPAT_H */

#endif /* OPENSSL_V102_COMPAT */

/* vim: set ts=4 sw=4 tw=78 et : */
