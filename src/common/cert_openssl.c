/*-------------------------------------------------------------------------
 *
 * protocol_openssl.c
 *	  OpenSSL certificate functionality shared between frontend and backend
 *
 * This should only be used if code is compiled with OpenSSL support.
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *		  src/common/cert_openssl.c
 *
 *-------------------------------------------------------------------------
 */

#ifndef FRONTEND
#include "postgres.h"
#else
#include "postgres_fe.h"
#endif

#include "common/openssl.h"

/*
 * SSL_CTX_load_verify_locations and X509_STORE_load_locations were deprecated
 * in OpenSSL 3.0.0 and replaced by their new _file counterparts.  Provide
 * implementations of the replacement for OpenSSL versions 1.0.1 through 1.1.1
 * where they are missing.
 */
#if OPENSSL_VERSION_MAJOR < 3
int
SSL_CTX_load_verify_file(SSL_CTX *ctx, const char *CAfile)
{
	return SSL_CTX_load_verify_locations(ctx, CAfile, NULL);
}
int
X509_STORE_load_file(X509_STORE *ctx, const char *file)
{
	return X509_STORE_load_locations(ctx, file, NULL);
}
#endif
