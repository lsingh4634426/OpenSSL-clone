/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "e_capi_err.h"

#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA CAPI_str_functs[] = {
    {ERR_PACK(0, CAPI_F_CAPI_CERT_GET_FNAME, 0), "capi_cert_get_fname"},
    {ERR_PACK(0, CAPI_F_CAPI_CTRL, 0), "capi_ctrl"},
    {ERR_PACK(0, CAPI_F_CAPI_CTX_NEW, 0), "capi_ctx_new"},
    {ERR_PACK(0, CAPI_F_CAPI_CTX_SET_PROVNAME, 0), "capi_ctx_set_provname"},
    {ERR_PACK(0, CAPI_F_CAPI_DSA_DO_SIGN, 0), "capi_dsa_do_sign"},
    {ERR_PACK(0, CAPI_F_CAPI_GET_KEY, 0), "capi_get_key"},
    {ERR_PACK(0, CAPI_F_CAPI_GET_PKEY, 0), "capi_get_pkey"},
    {ERR_PACK(0, CAPI_F_CAPI_GET_PROVNAME, 0), "capi_get_provname"},
    {ERR_PACK(0, CAPI_F_CAPI_GET_PROV_INFO, 0), "capi_get_prov_info"},
    {ERR_PACK(0, CAPI_F_CAPI_INIT, 0), "capi_init"},
    {ERR_PACK(0, CAPI_F_CAPI_LIST_CONTAINERS, 0), "capi_list_containers"},
    {ERR_PACK(0, CAPI_F_CAPI_LOAD_PRIVKEY, 0), "capi_load_privkey"},
    {ERR_PACK(0, CAPI_F_CAPI_OPEN_STORE, 0), "capi_open_store"},
    {ERR_PACK(0, CAPI_F_CAPI_RSA_PRIV_DEC, 0), "capi_rsa_priv_dec"},
    {ERR_PACK(0, CAPI_F_CAPI_RSA_PRIV_ENC, 0), "capi_rsa_priv_enc"},
    {ERR_PACK(0, CAPI_F_CAPI_RSA_SIGN, 0), "capi_rsa_sign"},
    {ERR_PACK(0, CAPI_F_CAPI_VTRACE, 0), "capi_vtrace"},
    {ERR_PACK(0, CAPI_F_CERT_SELECT_DIALOG, 0), "cert_select_dialog"},
    {ERR_PACK(0, CAPI_F_CLIENT_CERT_SELECT, 0), "CLIENT_CERT_SELECT"},
    {ERR_PACK(0, CAPI_F_WIDE_TO_ASC, 0), "wide_to_asc"},
    {0, NULL}
};

static ERR_STRING_DATA CAPI_str_reasons[] = {
    {ERR_PACK(0, 0, CAPI_R_CANT_CREATE_HASH_OBJECT),
    "cant create hash object"},
    {ERR_PACK(0, 0, CAPI_R_CANT_FIND_CAPI_CONTEXT), "cant find capi context"},
    {ERR_PACK(0, 0, CAPI_R_CANT_GET_KEY), "cant get key"},
    {ERR_PACK(0, 0, CAPI_R_CANT_SET_HASH_VALUE), "cant set hash value"},
    {ERR_PACK(0, 0, CAPI_R_CRYPTACQUIRECONTEXT_ERROR),
    "cryptacquirecontext error"},
    {ERR_PACK(0, 0, CAPI_R_CRYPTENUMPROVIDERS_ERROR),
    "cryptenumproviders error"},
    {ERR_PACK(0, 0, CAPI_R_DECRYPT_ERROR), "decrypt error"},
    {ERR_PACK(0, 0, CAPI_R_ENGINE_NOT_INITIALIZED), "engine not initialized"},
    {ERR_PACK(0, 0, CAPI_R_ENUMCONTAINERS_ERROR), "enumcontainers error"},
    {ERR_PACK(0, 0, CAPI_R_ERROR_ADDING_CERT), "error adding cert"},
    {ERR_PACK(0, 0, CAPI_R_ERROR_CREATING_STORE), "error creating store"},
    {ERR_PACK(0, 0, CAPI_R_ERROR_GETTING_FRIENDLY_NAME),
    "error getting friendly name"},
    {ERR_PACK(0, 0, CAPI_R_ERROR_GETTING_KEY_PROVIDER_INFO),
    "error getting key provider info"},
    {ERR_PACK(0, 0, CAPI_R_ERROR_OPENING_STORE), "error opening store"},
    {ERR_PACK(0, 0, CAPI_R_ERROR_SIGNING_HASH), "error signing hash"},
    {ERR_PACK(0, 0, CAPI_R_FILE_OPEN_ERROR), "file open error"},
    {ERR_PACK(0, 0, CAPI_R_FUNCTION_NOT_SUPPORTED), "function not supported"},
    {ERR_PACK(0, 0, CAPI_R_GETUSERKEY_ERROR), "getuserkey error"},
    {ERR_PACK(0, 0, CAPI_R_INVALID_DIGEST_LENGTH), "invalid digest length"},
    {ERR_PACK(0, 0, CAPI_R_INVALID_DSA_PUBLIC_KEY_BLOB_MAGIC_NUMBER),
    "invalid dsa public key blob magic number"},
    {ERR_PACK(0, 0, CAPI_R_INVALID_LOOKUP_METHOD), "invalid lookup method"},
    {ERR_PACK(0, 0, CAPI_R_INVALID_PUBLIC_KEY_BLOB),
    "invalid public key blob"},
    {ERR_PACK(0, 0, CAPI_R_INVALID_RSA_PUBLIC_KEY_BLOB_MAGIC_NUMBER),
    "invalid rsa public key blob magic number"},
    {ERR_PACK(0, 0, CAPI_R_PUBKEY_EXPORT_ERROR), "pubkey export error"},
    {ERR_PACK(0, 0, CAPI_R_PUBKEY_EXPORT_LENGTH_ERROR),
    "pubkey export length error"},
    {ERR_PACK(0, 0, CAPI_R_UNKNOWN_COMMAND), "unknown command"},
    {ERR_PACK(0, 0, CAPI_R_UNSUPPORTED_ALGORITHM_NID),
    "unsupported algorithm nid"},
    {ERR_PACK(0, 0, CAPI_R_UNSUPPORTED_PADDING), "unsupported padding"},
    {ERR_PACK(0, 0, CAPI_R_UNSUPPORTED_PUBLIC_KEY_ALGORITHM),
    "unsupported public key algorithm"},
    {ERR_PACK(0, 0, CAPI_R_WIN32_ERROR), "win32 error"},
    {0, NULL}
};

#endif

static int lib_code = 0;
static int error_loaded = 0;

int ERR_load_CAPI_strings(void)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();

    if (!error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(lib_code, CAPI_str_functs);
        ERR_load_strings(lib_code, CAPI_str_reasons);
#endif
        error_loaded = 1;
    }
    return 1;
}

void ERR_unload_CAPI_strings(void)
{
    if (error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(lib_code, CAPI_str_functs);
        ERR_unload_strings(lib_code, CAPI_str_reasons);
#endif
        error_loaded = 0;
    }
}

void ERR_CAPI_error(int function, int reason, char *file, int line)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();
    ERR_PUT_error(lib_code, function, reason, file, line);
}
