/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_APPS_LIBCTX_H
#define OSSL_APPS_APPS_LIBCTX_H

#include "openssl/x509.h"

OSSL_LIB_CTX *app_create_libctx(void);
OSSL_LIB_CTX *app_get0_libctx(void);

#endif                          /* ! OSSL_APPS_APPS_LIBCTX_H */
