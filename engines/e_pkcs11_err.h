/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_PKCS11ERR_H
# define HEADER_PKCS11ERR_H

# define PKCS11err(f, r) ERR_PKCS11_error((f), (r), OPENSSL_FILE, OPENSSL_LINE)


/*
 * PKCS11 function codes.
 */
# define PKCS11_F_PKCS11_CTRL                             110
# define PKCS11_F_PKCS11_CTX_NEW                          111
# define PKCS11_F_PKCS11_ENGINE_LOAD_PRIVATE_KEY          100
# define PKCS11_F_PKCS11_GET_CONSOLE_PIN                  113
# define PKCS11_F_PKCS11_GET_PRIVATE_KEY                  101
# define PKCS11_F_PKCS11_GET_SLOT                         102
# define PKCS11_F_PKCS11_INIT                             112
# define PKCS11_F_PKCS11_INITIALIZE                       107
# define PKCS11_F_PKCS11_LOAD_FUNCTIONS                   108
# define PKCS11_F_PKCS11_LOAD_PKEY                        114
# define PKCS11_F_PKCS11_LOGIN                            103
# define PKCS11_F_PKCS11_LOGOUT                           104
# define PKCS11_F_PKCS11_PARSE                            115
# define PKCS11_F_PKCS11_PARSE_URI                        116
# define PKCS11_F_PKCS11_RSA_ENC                          105
# define PKCS11_F_PKCS11_START_SESSION                    106
# define PKCS11_F_PKCS11_TRACE                            109

/*
 * PKCS11 reason codes.
 */
# define PKCS11_R_ENGINE_NOT_INITIALIZED                  117
# define PKCS11_R_FILE_OPEN_ERROR                         102
# define PKCS11_R_FIND_OBJECT_FAILED                      103
# define PKCS11_R_FIND_OBJECT_FINAL_FAILED                119
# define PKCS11_R_FIND_OBJECT_INIT_FAILED                 104
# define PKCS11_R_GETATTRIBUTEVALUE_FAILED                114
# define PKCS11_R_GETFUNCTIONLIST_NOT_FOUND               105
# define PKCS11_R_GETTING_FUNCTION_LIST_FAILED            106
# define PKCS11_R_GET_SLOTINFO_FAILED                     116
# define PKCS11_R_GET_SLOTLIST_FAILED                     107
# define PKCS11_R_INITIALIZE_FAILED                       108
# define PKCS11_R_LIBRARY_PATH_NOT_FOUND                  109
# define PKCS11_R_LOGIN_FAILED                            110
# define PKCS11_R_LOGOUT_FAILED                           111
# define PKCS11_R_MEMORY_ALLOCATION_FAILED                115
# define PKCS11_R_OPEN_SESSION_ERROR                      112
# define PKCS11_R_RSA_NOT_FOUND                           118
# define PKCS11_R_SIGN_FAILED                             100
# define PKCS11_R_SIGN_INIT_FAILED                        101
# define PKCS11_R_SLOT_NOT_FOUND                          113

#endif
