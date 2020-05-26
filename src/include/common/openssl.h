/*-------------------------------------------------------------------------
 *
 * openssl.h
 *	  OpenSSL supporting functionality shared between frontend and backend
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *		  src/include/common/openssl.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef COMMON_OPENSSL_H
#define COMMON_OPENSSL_H

#ifdef USE_OPENSSL
#include <openssl/ssl.h>

/* src/common/protocol_openssl.c */
#ifndef SSL_CTX_set_min_proto_version
extern int	SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version);
extern int	SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int version);
#endif

/* src/common/cert_openssl.c */
#if OPENSSL_VERSION_MAJOR < 3
extern int SSL_CTX_load_verify_file(SSL_CTX *ctx, const char *CAfile);
int X509_STORE_load_file(X509_STORE *ctx, const char *file);
#endif

#endif

#endif							/* COMMON_OPENSSL_H */
