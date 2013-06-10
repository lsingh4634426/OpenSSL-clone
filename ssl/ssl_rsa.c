/* ssl/ssl_rsa.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

static int ssl_set_cert(CERT *c, X509 *x509);
static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey);
#ifndef OPENSSL_NO_TLSEXT
static int ssl_set_authz(CERT *c, unsigned char *authz,
			 size_t authz_length);
#endif
int SSL_use_certificate(SSL *ssl, X509 *x)
	{
	if (x == NULL)
		{
		SSLerr(SSL_F_SSL_USE_CERTIFICATE,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if (!ssl_cert_inst(&ssl->cert))
		{
		SSLerr(SSL_F_SSL_USE_CERTIFICATE,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	return(ssl_set_cert(ssl->cert,x));
	}

#ifndef OPENSSL_NO_STDIO
int SSL_use_certificate_file(SSL *ssl, const char *file, int type)
	{
	int j;
	BIO *in;
	int ret=0;
	X509 *x=NULL;

	in=BIO_new(BIO_s_file_internal());
	if (in == NULL)
		{
		SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE,ERR_R_BUF_LIB);
		goto end;
		}

	if (BIO_read_filename(in,file) <= 0)
		{
		SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE,ERR_R_SYS_LIB);
		goto end;
		}
	if (type == SSL_FILETYPE_ASN1)
		{
		j=ERR_R_ASN1_LIB;
		x=d2i_X509_bio(in,NULL);
		}
	else if (type == SSL_FILETYPE_PEM)
		{
		j=ERR_R_PEM_LIB;
		x=PEM_read_bio_X509(in,NULL,ssl->ctx->default_passwd_callback,ssl->ctx->default_passwd_callback_userdata);
		}
	else
		{
		SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE,SSL_R_BAD_SSL_FILETYPE);
		goto end;
		}

	if (x == NULL)
		{
		SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE,j);
		goto end;
		}

	ret=SSL_use_certificate(ssl,x);
end:
	if (x != NULL) X509_free(x);
	if (in != NULL) BIO_free(in);
	return(ret);
	}
#endif

int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len)
	{
	X509 *x;
	int ret;

	x=d2i_X509(NULL,&d,(long)len);
	if (x == NULL)
		{
		SSLerr(SSL_F_SSL_USE_CERTIFICATE_ASN1,ERR_R_ASN1_LIB);
		return(0);
		}

	ret=SSL_use_certificate(ssl,x);
	X509_free(x);
	return(ret);
	}

#ifndef OPENSSL_NO_RSA
int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa)
	{
	EVP_PKEY *pkey;
	int ret;

	if (rsa == NULL)
		{
		SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if (!ssl_cert_inst(&ssl->cert))
		{
		SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	if ((pkey=EVP_PKEY_new()) == NULL)
		{
		SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY,ERR_R_EVP_LIB);
		return(0);
		}

	RSA_up_ref(rsa);
	EVP_PKEY_assign_RSA(pkey,rsa);

	ret=ssl_set_pkey(ssl->cert,pkey);
	EVP_PKEY_free(pkey);
	return(ret);
	}
#endif

static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey)
	{
	int i;
	/* Special case for DH: check two DH certificate types for a match.
	 * This means for DH certificates we must set the certificate first.
	 */
	if (pkey->type == EVP_PKEY_DH)
		{
		X509 *x;
		i = -1;
		x = c->pkeys[SSL_PKEY_DH_RSA].x509;
		if (x && X509_check_private_key(x, pkey))
				i = SSL_PKEY_DH_RSA;
		x = c->pkeys[SSL_PKEY_DH_DSA].x509;
		if (i == -1 && x && X509_check_private_key(x, pkey))
				i = SSL_PKEY_DH_DSA;
		ERR_clear_error();
		}
	else 
		i=ssl_cert_type(NULL,pkey);
	if (i < 0)
		{
		SSLerr(SSL_F_SSL_SET_PKEY,SSL_R_UNKNOWN_CERTIFICATE_TYPE);
		return(0);
		}

	if (c->pkeys[i].x509 != NULL)
		{
		EVP_PKEY *pktmp;
		pktmp =	X509_get_pubkey(c->pkeys[i].x509);
		EVP_PKEY_copy_parameters(pktmp,pkey);
		EVP_PKEY_free(pktmp);
		ERR_clear_error();

#ifndef OPENSSL_NO_RSA
		/* Don't check the public/private key, this is mostly
		 * for smart cards. */
		if ((pkey->type == EVP_PKEY_RSA) &&
			(RSA_flags(pkey->pkey.rsa) & RSA_METHOD_FLAG_NO_CHECK))
			;
		else
#endif
		if (!X509_check_private_key(c->pkeys[i].x509,pkey))
			{
			X509_free(c->pkeys[i].x509);
			c->pkeys[i].x509 = NULL;
			return 0;
			}
		}

	if (c->pkeys[i].privatekey != NULL)
		EVP_PKEY_free(c->pkeys[i].privatekey);
	CRYPTO_add(&pkey->references,1,CRYPTO_LOCK_EVP_PKEY);
	c->pkeys[i].privatekey=pkey;
	c->key= &(c->pkeys[i]);

	c->valid=0;
	return(1);
	}

#ifndef OPENSSL_NO_RSA
#ifndef OPENSSL_NO_STDIO
int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type)
	{
	int j,ret=0;
	BIO *in;
	RSA *rsa=NULL;

	in=BIO_new(BIO_s_file_internal());
	if (in == NULL)
		{
		SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE,ERR_R_BUF_LIB);
		goto end;
		}

	if (BIO_read_filename(in,file) <= 0)
		{
		SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE,ERR_R_SYS_LIB);
		goto end;
		}
	if	(type == SSL_FILETYPE_ASN1)
		{
		j=ERR_R_ASN1_LIB;
		rsa=d2i_RSAPrivateKey_bio(in,NULL);
		}
	else if (type == SSL_FILETYPE_PEM)
		{
		j=ERR_R_PEM_LIB;
		rsa=PEM_read_bio_RSAPrivateKey(in,NULL,
			ssl->ctx->default_passwd_callback,ssl->ctx->default_passwd_callback_userdata);
		}
	else
		{
		SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE,SSL_R_BAD_SSL_FILETYPE);
		goto end;
		}
	if (rsa == NULL)
		{
		SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE,j);
		goto end;
		}
	ret=SSL_use_RSAPrivateKey(ssl,rsa);
	RSA_free(rsa);
end:
	if (in != NULL) BIO_free(in);
	return(ret);
	}
#endif

int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len)
	{
	int ret;
	const unsigned char *p;
	RSA *rsa;

	p=d;
	if ((rsa=d2i_RSAPrivateKey(NULL,&p,(long)len)) == NULL)
		{
		SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1,ERR_R_ASN1_LIB);
		return(0);
		}

	ret=SSL_use_RSAPrivateKey(ssl,rsa);
	RSA_free(rsa);
	return(ret);
	}
#endif /* !OPENSSL_NO_RSA */

int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)
	{
	int ret;

	if (pkey == NULL)
		{
		SSLerr(SSL_F_SSL_USE_PRIVATEKEY,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if (!ssl_cert_inst(&ssl->cert))
		{
		SSLerr(SSL_F_SSL_USE_PRIVATEKEY,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	ret=ssl_set_pkey(ssl->cert,pkey);
	return(ret);
	}

#ifndef OPENSSL_NO_STDIO
int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type)
	{
	int j,ret=0;
	BIO *in;
	EVP_PKEY *pkey=NULL;

	in=BIO_new(BIO_s_file_internal());
	if (in == NULL)
		{
		SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE,ERR_R_BUF_LIB);
		goto end;
		}

	if (BIO_read_filename(in,file) <= 0)
		{
		SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE,ERR_R_SYS_LIB);
		goto end;
		}
	if (type == SSL_FILETYPE_PEM)
		{
		j=ERR_R_PEM_LIB;
		pkey=PEM_read_bio_PrivateKey(in,NULL,
			ssl->ctx->default_passwd_callback,ssl->ctx->default_passwd_callback_userdata);
		}
	else if (type == SSL_FILETYPE_ASN1)
		{
		j = ERR_R_ASN1_LIB;
		pkey = d2i_PrivateKey_bio(in,NULL);
		}
	else
		{
		SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE,SSL_R_BAD_SSL_FILETYPE);
		goto end;
		}
	if (pkey == NULL)
		{
		SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE,j);
		goto end;
		}
	ret=SSL_use_PrivateKey(ssl,pkey);
	EVP_PKEY_free(pkey);
end:
	if (in != NULL) BIO_free(in);
	return(ret);
	}
#endif

int SSL_use_PrivateKey_ASN1(int type, SSL *ssl, const unsigned char *d, long len)
	{
	int ret;
	const unsigned char *p;
	EVP_PKEY *pkey;

	p=d;
	if ((pkey=d2i_PrivateKey(type,NULL,&p,(long)len)) == NULL)
		{
		SSLerr(SSL_F_SSL_USE_PRIVATEKEY_ASN1,ERR_R_ASN1_LIB);
		return(0);
		}

	ret=SSL_use_PrivateKey(ssl,pkey);
	EVP_PKEY_free(pkey);
	return(ret);
	}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
	{
	if (x == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if (!ssl_cert_inst(&ctx->cert))
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	return(ssl_set_cert(ctx->cert, x));
	}

static int ssl_set_cert(CERT *c, X509 *x)
	{
	EVP_PKEY *pkey;
	int i;

	pkey=X509_get_pubkey(x);
	if (pkey == NULL)
		{
		SSLerr(SSL_F_SSL_SET_CERT,SSL_R_X509_LIB);
		return(0);
		}

	i=ssl_cert_type(x,pkey);
	if (i < 0)
		{
		SSLerr(SSL_F_SSL_SET_CERT,SSL_R_UNKNOWN_CERTIFICATE_TYPE);
		EVP_PKEY_free(pkey);
		return(0);
		}

	if (c->pkeys[i].privatekey != NULL)
		{
		EVP_PKEY_copy_parameters(pkey,c->pkeys[i].privatekey);
		ERR_clear_error();

#ifndef OPENSSL_NO_RSA
		/* Don't check the public/private key, this is mostly
		 * for smart cards. */
		if ((c->pkeys[i].privatekey->type == EVP_PKEY_RSA) &&
			(RSA_flags(c->pkeys[i].privatekey->pkey.rsa) &
			 RSA_METHOD_FLAG_NO_CHECK))
			 ;
		else
#endif /* OPENSSL_NO_RSA */
		if (!X509_check_private_key(x,c->pkeys[i].privatekey))
			{
			/* don't fail for a cert/key mismatch, just free
			 * current private key (when switching to a different
			 * cert & key, first this function should be used,
			 * then ssl_set_pkey */
			EVP_PKEY_free(c->pkeys[i].privatekey);
			c->pkeys[i].privatekey=NULL;
			/* clear error queue */
			ERR_clear_error();
			}
		}

	EVP_PKEY_free(pkey);

	if (c->pkeys[i].x509 != NULL)
		X509_free(c->pkeys[i].x509);
	CRYPTO_add(&x->references,1,CRYPTO_LOCK_X509);
	c->pkeys[i].x509=x;
#ifndef OPENSSL_NO_TLSEXT
	/* Free the old authz data, if it exists. */
	if (c->pkeys[i].authz != NULL)
		{
		OPENSSL_free(c->pkeys[i].authz);
		c->pkeys[i].authz = NULL;
		c->pkeys[i].authz_length = 0;
		}

	/* Free the old serverinfo data, if it exists. */
	if (c->pkeys[i].serverinfo != NULL)
		{
		OPENSSL_free(c->pkeys[i].serverinfo);
		c->pkeys[i].serverinfo = NULL;
		c->pkeys[i].serverinfo_length = 0;
		}
#endif
	c->key= &(c->pkeys[i]);

	c->valid=0;
	return(1);
	}

#ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
	{
	int j;
	BIO *in;
	int ret=0;
	X509 *x=NULL;

	in=BIO_new(BIO_s_file_internal());
	if (in == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,ERR_R_BUF_LIB);
		goto end;
		}

	if (BIO_read_filename(in,file) <= 0)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,ERR_R_SYS_LIB);
		goto end;
		}
	if (type == SSL_FILETYPE_ASN1)
		{
		j=ERR_R_ASN1_LIB;
		x=d2i_X509_bio(in,NULL);
		}
	else if (type == SSL_FILETYPE_PEM)
		{
		j=ERR_R_PEM_LIB;
		x=PEM_read_bio_X509(in,NULL,ctx->default_passwd_callback,ctx->default_passwd_callback_userdata);
		}
	else
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,SSL_R_BAD_SSL_FILETYPE);
		goto end;
		}

	if (x == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE,j);
		goto end;
		}

	ret=SSL_CTX_use_certificate(ctx,x);
end:
	if (x != NULL) X509_free(x);
	if (in != NULL) BIO_free(in);
	return(ret);
	}
#endif

int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d)
	{
	X509 *x;
	int ret;

	x=d2i_X509(NULL,&d,(long)len);
	if (x == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1,ERR_R_ASN1_LIB);
		return(0);
		}

	ret=SSL_CTX_use_certificate(ctx,x);
	X509_free(x);
	return(ret);
	}

#ifndef OPENSSL_NO_RSA
int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)
	{
	int ret;
	EVP_PKEY *pkey;

	if (rsa == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if (!ssl_cert_inst(&ctx->cert))
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	if ((pkey=EVP_PKEY_new()) == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY,ERR_R_EVP_LIB);
		return(0);
		}

	RSA_up_ref(rsa);
	EVP_PKEY_assign_RSA(pkey,rsa);

	ret=ssl_set_pkey(ctx->cert, pkey);
	EVP_PKEY_free(pkey);
	return(ret);
	}

#ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type)
	{
	int j,ret=0;
	BIO *in;
	RSA *rsa=NULL;

	in=BIO_new(BIO_s_file_internal());
	if (in == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE,ERR_R_BUF_LIB);
		goto end;
		}

	if (BIO_read_filename(in,file) <= 0)
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE,ERR_R_SYS_LIB);
		goto end;
		}
	if	(type == SSL_FILETYPE_ASN1)
		{
		j=ERR_R_ASN1_LIB;
		rsa=d2i_RSAPrivateKey_bio(in,NULL);
		}
	else if (type == SSL_FILETYPE_PEM)
		{
		j=ERR_R_PEM_LIB;
		rsa=PEM_read_bio_RSAPrivateKey(in,NULL,
			ctx->default_passwd_callback,ctx->default_passwd_callback_userdata);
		}
	else
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE,SSL_R_BAD_SSL_FILETYPE);
		goto end;
		}
	if (rsa == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE,j);
		goto end;
		}
	ret=SSL_CTX_use_RSAPrivateKey(ctx,rsa);
	RSA_free(rsa);
end:
	if (in != NULL) BIO_free(in);
	return(ret);
	}
#endif

int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d, long len)
	{
	int ret;
	const unsigned char *p;
	RSA *rsa;

	p=d;
	if ((rsa=d2i_RSAPrivateKey(NULL,&p,(long)len)) == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1,ERR_R_ASN1_LIB);
		return(0);
		}

	ret=SSL_CTX_use_RSAPrivateKey(ctx,rsa);
	RSA_free(rsa);
	return(ret);
	}
#endif /* !OPENSSL_NO_RSA */

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
	{
	if (pkey == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY,ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if (!ssl_cert_inst(&ctx->cert))
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY,ERR_R_MALLOC_FAILURE);
		return(0);
		}
	return(ssl_set_pkey(ctx->cert,pkey));
	}

#ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
	{
	int j,ret=0;
	BIO *in;
	EVP_PKEY *pkey=NULL;

	in=BIO_new(BIO_s_file_internal());
	if (in == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,ERR_R_BUF_LIB);
		goto end;
		}

	if (BIO_read_filename(in,file) <= 0)
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,ERR_R_SYS_LIB);
		goto end;
		}
	if (type == SSL_FILETYPE_PEM)
		{
		j=ERR_R_PEM_LIB;
		pkey=PEM_read_bio_PrivateKey(in,NULL,
			ctx->default_passwd_callback,ctx->default_passwd_callback_userdata);
		}
	else if (type == SSL_FILETYPE_ASN1)
		{
		j = ERR_R_ASN1_LIB;
		pkey = d2i_PrivateKey_bio(in,NULL);
		}
	else
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,SSL_R_BAD_SSL_FILETYPE);
		goto end;
		}
	if (pkey == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE,j);
		goto end;
		}
	ret=SSL_CTX_use_PrivateKey(ctx,pkey);
	EVP_PKEY_free(pkey);
end:
	if (in != NULL) BIO_free(in);
	return(ret);
	}
#endif

int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx, const unsigned char *d,
	     long len)
	{
	int ret;
	const unsigned char *p;
	EVP_PKEY *pkey;

	p=d;
	if ((pkey=d2i_PrivateKey(type,NULL,&p,(long)len)) == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1,ERR_R_ASN1_LIB);
		return(0);
		}

	ret=SSL_CTX_use_PrivateKey(ctx,pkey);
	EVP_PKEY_free(pkey);
	return(ret);
	}


#ifndef OPENSSL_NO_STDIO
/* Read a file that contains our certificate in "PEM" format,
 * possibly followed by a sequence of CA certificates that should be
 * sent to the peer in the Certificate message.
 */
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
	{
	BIO *in;
	int ret=0;
	X509 *x=NULL;

	ERR_clear_error(); /* clear error stack for SSL_CTX_use_certificate() */

	in = BIO_new(BIO_s_file_internal());
	if (in == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE,ERR_R_BUF_LIB);
		goto end;
		}

	if (BIO_read_filename(in,file) <= 0)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE,ERR_R_SYS_LIB);
		goto end;
		}

	x=PEM_read_bio_X509_AUX(in,NULL,ctx->default_passwd_callback,
				ctx->default_passwd_callback_userdata);
	if (x == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE,ERR_R_PEM_LIB);
		goto end;
		}

	ret = SSL_CTX_use_certificate(ctx, x);

	if (ERR_peek_error() != 0)
		ret = 0;  /* Key/certificate mismatch doesn't imply ret==0 ... */
	if (ret)
		{
		/* If we could set up our certificate, now proceed to
		 * the CA certificates.
		 */
		X509 *ca;
		int r;
		unsigned long err;
		
		if (ctx->extra_certs != NULL)
			{
			sk_X509_pop_free(ctx->extra_certs, X509_free);
			ctx->extra_certs = NULL;
			}

		while ((ca = PEM_read_bio_X509(in, NULL,
					ctx->default_passwd_callback,
					ctx->default_passwd_callback_userdata))
			!= NULL)
			{
			r = SSL_CTX_add_extra_chain_cert(ctx, ca);
			if (!r) 
				{
				X509_free(ca);
				ret = 0;
				goto end;
				}
			/* Note that we must not free r if it was successfully
			 * added to the chain (while we must free the main
			 * certificate, since its reference count is increased
			 * by SSL_CTX_use_certificate). */
			}
		/* When the while loop ends, it's usually just EOF. */
		err = ERR_peek_last_error();
		if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
			ERR_clear_error();
		else 
			ret = 0; /* some real error */
		}

end:
	if (x != NULL) X509_free(x);
	if (in != NULL) BIO_free(in);
	return(ret);
	}
#endif

#ifndef OPENSSL_NO_TLSEXT
/* authz_validate returns true iff authz is well formed, i.e. that it meets the
 * wire format as documented in the CERT_PKEY structure and that there are no
 * duplicate entries. */
static char authz_validate(const unsigned char *authz, size_t length)
	{
	unsigned char types_seen_bitmap[32];

	if (!authz)
		return 1;

	memset(types_seen_bitmap, 0, sizeof(types_seen_bitmap));

	for (;;)
		{
		unsigned char type, byte, bit;
		unsigned short len;

		if (!length)
			return 1;

		type = *(authz++);
		length--;

		byte = type / 8;
		bit = type & 7;
		if (types_seen_bitmap[byte] & (1 << bit))
			return 0;
		types_seen_bitmap[byte] |= (1 << bit);

		if (length < 2)
			return 0;
		len = ((unsigned short) authz[0]) << 8 |
		      ((unsigned short) authz[1]);
		authz += 2;
		length -= 2;

		if (length < len)
			return 0;

		authz += len;
		length -= len;
		}
	}

static int serverinfo_find_extension(unsigned char *serverinfo,
				   size_t serverinfo_length,
				   unsigned short extension_type,
				   unsigned char** extension_data,
				   unsigned short* extension_length)
	{
	*extension_data = NULL;
	*extension_length = 0;
	if (serverinfo == NULL || serverinfo_length == 0)
		return 0;
	for (;;)
		{
		unsigned short type = 0; /* uint16 */
		unsigned short len = 0;  /* uint16 */

		/* end of serverinfo */
		if (serverinfo_length == 0)
			return 0;

		/* read 2-byte type field */
		if (serverinfo_length < 2)
			return 0;	/* error */
		type = (serverinfo[0] << 8) + serverinfo[1];
		serverinfo += 2;
		serverinfo_length -= 2;

		/* read 2-byte len field */
		if (serverinfo_length < 2)
			return 0;	/* error */
		len = (serverinfo[0] << 8) + serverinfo[1];
		serverinfo += 2;
		serverinfo_length -= 2;

		if (len > serverinfo_length)
			return 0;	/* error */

		if (type == extension_type)
			{
			*extension_data = serverinfo;
			*extension_length = len;
			return 1;
			}

		serverinfo += len;
		serverinfo_length -= len;
		}
	return 0;
	}

static int serverinfo_srv_cb(SSL* s, unsigned short ext_num,
													   unsigned char** out, unsigned short* outlen, 
													   void* arg)
	{
	unsigned char *serverinfo = NULL;
	size_t serverinfo_length = 0;

	/* Is there a serverinfo for the chosen server cert? */
	if ((ssl_get_server_cert_serverinfo(s, &serverinfo, &serverinfo_length)) != 0)
		{
		/* Find the relevant extension from the serverinfo */
		serverinfo_find_extension(serverinfo, serverinfo_length, ext_num, out, outlen);
		}
		return 1;
	}

static int serverinfo_validate(const unsigned char *serverinfo, size_t serverinfo_length, SSL_CTX* ctx)
	{
	if (serverinfo == NULL || serverinfo_length == 0)
		return 0;
	for (;;)
		{
		unsigned short ext_num = 0; /* uint16 */
		unsigned short len = 0;  /* uint16 */

		/* end of serverinfo */
		if (serverinfo_length == 0)
			return 1;

		/* read 2-byte type field */
		if (serverinfo_length < 2)
			return 0;
		/* FIXME: check for types we understand explicitly? */

		/* Register callbacks for extensions */
		ext_num = (serverinfo[0] << 8) + serverinfo[1];
		if (ctx && !SSL_CTX_set_custom_srv_ext(ctx, ext_num, NULL, serverinfo_srv_cb, NULL))
			return 0;

		serverinfo += 2;
		serverinfo_length -= 2;

		/* read 2-byte len field */
		if (serverinfo_length < 2)
			return 0;
		len = (serverinfo[0] << 8) + serverinfo[1];
		serverinfo += 2;
		serverinfo_length -= 2;

		if (len > serverinfo_length)
			return 0;

		serverinfo += len;
		serverinfo_length -= len;
		}
	}

static const unsigned char *authz_find_data(const unsigned char *authz,
					    size_t authz_length,
					    unsigned char data_type,
					    size_t *data_length)
	{
	if (authz == NULL) return NULL;
	if (!authz_validate(authz, authz_length))
		{
		SSLerr(SSL_F_AUTHZ_FIND_DATA,SSL_R_INVALID_AUTHZ_DATA);
		return NULL;
		}

	for (;;)
		{
		unsigned char type;
		unsigned short len;
		if (!authz_length)
			return NULL;

		type = *(authz++);
		authz_length--;

		/* We've validated the authz data, so we don't have to
		 * check again that we have enough bytes left. */
		len = ((unsigned short) authz[0]) << 8 |
		      ((unsigned short) authz[1]);
		authz += 2;
		authz_length -= 2;
		if (type == data_type)
			{
			*data_length = len;
			return authz;
			}
		authz += len;
		authz_length -= len;
		}
	/* No match */
	return NULL;
	}

static int ssl_set_authz(CERT *c, unsigned char *authz, size_t authz_length)
	{
	CERT_PKEY *current_key = c->key;
	if (current_key == NULL)
		return 0;
	if (!authz_validate(authz, authz_length))
		{
		SSLerr(SSL_F_SSL_SET_AUTHZ,SSL_R_INVALID_AUTHZ_DATA);
		return(0);
		}
	current_key->authz = OPENSSL_realloc(current_key->authz, authz_length);
	if (current_key->authz == NULL)
		{
		SSLerr(SSL_F_SSL_SET_AUTHZ,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	current_key->authz_length = authz_length;
	memcpy(current_key->authz, authz, authz_length);
	return 1;
	}

int SSL_CTX_use_authz(SSL_CTX *ctx, unsigned char *authz,
	size_t authz_length)
	{
	if (authz == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_AUTHZ,ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	if (!ssl_cert_inst(&ctx->cert))
		{
		SSLerr(SSL_F_SSL_CTX_USE_AUTHZ,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	return ssl_set_authz(ctx->cert, authz, authz_length);
	}

int SSL_CTX_use_serverinfo(SSL_CTX *ctx, const unsigned char *serverinfo,
			 size_t serverinfo_length)
	{
	if (ctx == NULL || serverinfo == NULL || serverinfo_length == 0)
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO,ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	if (!serverinfo_validate(serverinfo, serverinfo_length, NULL))
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO,SSL_R_INVALID_SERVERINFO_DATA);
		return(0);
		}
	if (!ssl_cert_inst(&ctx->cert))
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	if (ctx->cert->key == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO,ERR_R_INTERNAL_ERROR);
		return 0;
		}
	ctx->cert->key->serverinfo = OPENSSL_realloc(ctx->cert->key->serverinfo,
												serverinfo_length);
	if (ctx->cert->key->serverinfo == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	memcpy(ctx->cert->key->serverinfo, serverinfo, serverinfo_length);
	ctx->cert->key->serverinfo_length = serverinfo_length;

	/* Now that the serverinfo is validated and stored, go ahead and 
	 * register callbacks. */
	if (!serverinfo_validate(serverinfo, serverinfo_length, ctx))
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO,SSL_R_INVALID_SERVERINFO_DATA);
		return(0);
		}
	return 1;
	}

int SSL_use_authz(SSL *ssl, unsigned char *authz, size_t authz_length)
	{
	if (authz == NULL)
		{
		SSLerr(SSL_F_SSL_USE_AUTHZ,ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	if (!ssl_cert_inst(&ssl->cert))
		{
		SSLerr(SSL_F_SSL_USE_AUTHZ,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	return ssl_set_authz(ssl->cert, authz, authz_length);
	}

const unsigned char *SSL_CTX_get_authz_data(SSL_CTX *ctx, unsigned char type,
					    size_t *data_length)
	{
	CERT_PKEY *current_key;

	if (ctx->cert == NULL)
		return NULL;
	current_key = ctx->cert->key;
	if (current_key->authz == NULL)
		return NULL;
	return authz_find_data(current_key->authz,
		current_key->authz_length, type, data_length);
	}

#ifndef OPENSSL_NO_STDIO
/* read_authz returns a newly allocated buffer with authz data */
static unsigned char *read_authz(const char *file, size_t *authz_length)
	{
	BIO *authz_in = NULL;
	unsigned char *authz = NULL;
	/* Allow authzs up to 64KB. */
	static const size_t authz_limit = 65536;
	size_t read_length;
	unsigned char *ret = NULL;

	authz_in = BIO_new(BIO_s_file_internal());
	if (authz_in == NULL)
		{
		SSLerr(SSL_F_READ_AUTHZ,ERR_R_BUF_LIB);
		goto end;
		}

	if (BIO_read_filename(authz_in,file) <= 0)
		{
		SSLerr(SSL_F_READ_AUTHZ,ERR_R_SYS_LIB);
		goto end;
		}

	authz = OPENSSL_malloc(authz_limit);
	read_length = BIO_read(authz_in, authz, authz_limit);
	if (read_length == authz_limit || read_length <= 0)
		{
		SSLerr(SSL_F_READ_AUTHZ,SSL_R_AUTHZ_DATA_TOO_LARGE);
		OPENSSL_free(authz);
		goto end;
		}
	*authz_length = read_length;
	ret = authz;
end:
	if (authz_in != NULL) BIO_free(authz_in);
	return ret;
	}

int SSL_CTX_use_authz_file(SSL_CTX *ctx, const char *file)
	{
	unsigned char *authz = NULL;
	size_t authz_length = 0;
	int ret;

	authz = read_authz(file, &authz_length);
	if (authz == NULL)
		return 0;

	ret = SSL_CTX_use_authz(ctx, authz, authz_length);
	/* SSL_CTX_use_authz makes a local copy of the authz. */
	OPENSSL_free(authz);
	return ret;
	}

int SSL_use_authz_file(SSL *ssl, const char *file)
	{
	unsigned char *authz = NULL;
	size_t authz_length = 0;
	int ret;

	authz = read_authz(file, &authz_length);
	if (authz == NULL)
		return 0;

	ret = SSL_use_authz(ssl, authz, authz_length);
	/* SSL_use_authz makes a local copy of the authz. */
	OPENSSL_free(authz);
	return ret;
	}

int SSL_CTX_use_serverinfo_file(SSL_CTX *ctx, const char *file)
	{
	unsigned char *serverinfo = NULL;
	size_t serverinfo_length = 0;
	unsigned char* extension = 0;
	long extension_length = 0;
	char* name = NULL;
	char* header = NULL;
	int ret = 0;
	BIO *bin = NULL;
	size_t num_extensions = 0;

	if (ctx == NULL || file == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,ERR_R_PASSED_NULL_PARAMETER);
		goto end;
		}

	bin = BIO_new(BIO_s_file_internal());
	if (bin == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_BUF_LIB);
		goto end;
		}
	if (BIO_read_filename(bin, file) <= 0)
		{
		SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_SYS_LIB);
		goto end;
		}

	for (num_extensions=0;; num_extensions++)
		{
		if (PEM_read_bio(bin, &name, &header, &extension, &extension_length) == 0)
			{
			/* There must be at least one extension in this file */
			if (num_extensions == 0)
				{
				SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_PEM_LIB);
				goto end;
				}
			else /* End of file, we're done */
				break;
			}
		/* Check that the decoded PEM data is plausible (valid length field) */
		if (extension_length < 4 || (extension[2] << 8) + extension[3] != extension_length - 4)
			{
				SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_PEM_LIB);
				goto end;
			}
		/* Append the decoded extension to the serverinfo buffer */
		serverinfo = OPENSSL_realloc(serverinfo, serverinfo_length + extension_length);
		if (serverinfo == NULL)
			{
			SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_MALLOC_FAILURE);
			goto end;
			}
		memcpy(serverinfo + serverinfo_length, extension, extension_length);
		serverinfo_length += extension_length;

		OPENSSL_free(name); name = NULL;
		OPENSSL_free(header); header = NULL;
		OPENSSL_free(extension); extension = NULL;
		}

	ret = SSL_CTX_use_serverinfo(ctx, serverinfo, serverinfo_length);
end:
	/* SSL_CTX_use_serverinfo makes a local copy of the serverinfo. */
	OPENSSL_free(name);
	OPENSSL_free(header);
	OPENSSL_free(extension);
	OPENSSL_free(serverinfo);
	if (bin != NULL)
		BIO_free(bin);
	return ret;
	}
#endif /* OPENSSL_NO_STDIO */
#endif /* OPENSSL_NO_TLSEXT */
