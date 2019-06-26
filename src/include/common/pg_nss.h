/*-------------------------------------------------------------------------
 *
 * pg_nss.h
 *	  Support for NSS as a TLS backend
 *
 * These definitions are used by both frontend and backend code.
 *
 * Copyright (c) 2020, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *        src/include/common/pg_nss.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_NSS_H
#define PG_NSS_H

#ifdef USE_NSS

#include <sslproto.h>

PRUint16 pg_find_cipher(char *name);

typedef struct
{
    const char     *name;
    PRUint16        number;
} NSSCiphers;

#define INVALID_CIPHER	0xFFFF

static const NSSCiphers NSS_CipherList[] = {

    {"TLS_NULL_WITH_NULL_NULL", TLS_NULL_WITH_NULL_NULL},

	{"TLS_RSA_WITH_NULL_MD5", TLS_RSA_WITH_NULL_MD5},
	{"TLS_RSA_WITH_NULL_SHA", TLS_RSA_WITH_NULL_SHA},
	{"TLS_RSA_WITH_RC4_128_MD5", TLS_RSA_WITH_RC4_128_MD5},
	{"TLS_RSA_WITH_RC4_128_SHA", TLS_RSA_WITH_RC4_128_SHA},
	{"TLS_RSA_WITH_IDEA_CBC_SHA", TLS_RSA_WITH_IDEA_CBC_SHA},
	{"TLS_RSA_WITH_DES_CBC_SHA", TLS_RSA_WITH_DES_CBC_SHA},
	{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", TLS_RSA_WITH_3DES_EDE_CBC_SHA},

	{"TLS_DH_DSS_WITH_DES_CBC_SHA", TLS_DH_DSS_WITH_DES_CBC_SHA},
	{"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA},
	{"TLS_DH_RSA_WITH_DES_CBC_SHA", TLS_DH_RSA_WITH_DES_CBC_SHA},
	{"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA},

/*
 * TODO: Try to remember why these are commented out ..
#define TLS_DHE_DSS_WITH_DES_CBC_SHA            0x0012
#define TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA       0x0013
#define TLS_DHE_RSA_WITH_DES_CBC_SHA            0x0015
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA       0x0016

#define TLS_DH_anon_WITH_RC4_128_MD5            0x0018
#define TLS_DH_anon_WITH_DES_CBC_SHA            0x001a
#define TLS_DH_anon_WITH_3DES_EDE_CBC_SHA       0x001b

#define TLS_RSA_WITH_AES_128_CBC_SHA            0x002F
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA         0x0030
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA         0x0031
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA        0x0032
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA        0x0033
#define TLS_DH_anon_WITH_AES_128_CBC_SHA        0x0034

#define TLS_RSA_WITH_AES_256_CBC_SHA            0x0035
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA         0x0036
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA         0x0037
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA        0x0038
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA        0x0039
#define TLS_DH_anon_WITH_AES_256_CBC_SHA        0x003A
#define TLS_RSA_WITH_NULL_SHA256                0x003B
#define TLS_RSA_WITH_AES_128_CBC_SHA256         0x003C
#define TLS_RSA_WITH_AES_256_CBC_SHA256         0x003D

#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA256     0x0040
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA       0x0041
#define TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA    0x0042
#define TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA    0x0043
#define TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA   0x0044
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA   0x0045
#define TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA   0x0046

#define TLS_DHE_DSS_WITH_RC4_128_SHA            0x0066
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256     0x0067
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA256     0x006A
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256     0x006B

#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA       0x0084
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA    0x0085
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA    0x0086
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA   0x0087
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA   0x0088
#define TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA   0x0089

#define TLS_RSA_WITH_SEED_CBC_SHA               0x0096

#define TLS_RSA_WITH_AES_128_GCM_SHA256         0x009C
#define TLS_RSA_WITH_AES_256_GCM_SHA384         0x009D
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     0x009E
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     0x009F
#define TLS_DHE_DSS_WITH_AES_128_GCM_SHA256     0x00A2
#define TLS_DHE_DSS_WITH_AES_256_GCM_SHA384     0x00A3
*/
	{NULL, 0}
};

/*
 * pg_find_cipher
 *			Translate an NSS ciphername to the cipher code
 *
 * Searches the configured ciphers for the corresponding cipher code to the
 * name. Search is performed case insensitive.
 */
PRUint16
pg_find_cipher(char *name)
{
	const NSSCiphers	*cipher_list = NSS_CipherList;

	while (cipher_list->name)
	{
		if (pg_strcasecmp(cipher_list->name, name) == 0)
			return cipher_list->number;

		cipher_list++;
	}

	return 0xFFFF;
}

#endif							/* USE_NSS */

#endif							/* PG_NSS_H */
