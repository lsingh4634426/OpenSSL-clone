/*
 * Copyright 2015-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "testutil.h"
#include "internal/nelem.h"

/*
 * kExampleRSAKeyDER is an RSA private key in ASN.1, DER format. Of course, you
 * should never use this key anywhere but in an example.
 */
static const unsigned char kExampleRSAKeyDER[] = {
    0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xf8,
    0xb8, 0x6c, 0x83, 0xb4, 0xbc, 0xd9, 0xa8, 0x57, 0xc0, 0xa5, 0xb4, 0x59,
    0x76, 0x8c, 0x54, 0x1d, 0x79, 0xeb, 0x22, 0x52, 0x04, 0x7e, 0xd3, 0x37,
    0xeb, 0x41, 0xfd, 0x83, 0xf9, 0xf0, 0xa6, 0x85, 0x15, 0x34, 0x75, 0x71,
    0x5a, 0x84, 0xa8, 0x3c, 0xd2, 0xef, 0x5a, 0x4e, 0xd3, 0xde, 0x97, 0x8a,
    0xdd, 0xff, 0xbb, 0xcf, 0x0a, 0xaa, 0x86, 0x92, 0xbe, 0xb8, 0x50, 0xe4,
    0xcd, 0x6f, 0x80, 0x33, 0x30, 0x76, 0x13, 0x8f, 0xca, 0x7b, 0xdc, 0xec,
    0x5a, 0xca, 0x63, 0xc7, 0x03, 0x25, 0xef, 0xa8, 0x8a, 0x83, 0x58, 0x76,
    0x20, 0xfa, 0x16, 0x77, 0xd7, 0x79, 0x92, 0x63, 0x01, 0x48, 0x1a, 0xd8,
    0x7b, 0x67, 0xf1, 0x52, 0x55, 0x49, 0x4e, 0xd6, 0x6e, 0x4a, 0x5c, 0xd7,
    0x7a, 0x37, 0x36, 0x0c, 0xde, 0xdd, 0x8f, 0x44, 0xe8, 0xc2, 0xa7, 0x2c,
    0x2b, 0xb5, 0xaf, 0x64, 0x4b, 0x61, 0x07, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x81, 0x80, 0x74, 0x88, 0x64, 0x3f, 0x69, 0x45, 0x3a, 0x6d, 0xc7,
    0x7f, 0xb9, 0xa3, 0xc0, 0x6e, 0xec, 0xdc, 0xd4, 0x5a, 0xb5, 0x32, 0x85,
    0x5f, 0x19, 0xd4, 0xf8, 0xd4, 0x3f, 0x3c, 0xfa, 0xc2, 0xf6, 0x5f, 0xee,
    0xe6, 0xba, 0x87, 0x74, 0x2e, 0xc7, 0x0c, 0xd4, 0x42, 0xb8, 0x66, 0x85,
    0x9c, 0x7b, 0x24, 0x61, 0xaa, 0x16, 0x11, 0xf6, 0xb5, 0xb6, 0xa4, 0x0a,
    0xc9, 0x55, 0x2e, 0x81, 0xa5, 0x47, 0x61, 0xcb, 0x25, 0x8f, 0xc2, 0x15,
    0x7b, 0x0e, 0x7c, 0x36, 0x9f, 0x3a, 0xda, 0x58, 0x86, 0x1c, 0x5b, 0x83,
    0x79, 0xe6, 0x2b, 0xcc, 0xe6, 0xfa, 0x2c, 0x61, 0xf2, 0x78, 0x80, 0x1b,
    0xe2, 0xf3, 0x9d, 0x39, 0x2b, 0x65, 0x57, 0x91, 0x3d, 0x71, 0x99, 0x73,
    0xa5, 0xc2, 0x79, 0x20, 0x8c, 0x07, 0x4f, 0xe5, 0xb4, 0x60, 0x1f, 0x99,
    0xa2, 0xb1, 0x4f, 0x0c, 0xef, 0xbc, 0x59, 0x53, 0x00, 0x7d, 0xb1, 0x02,
    0x41, 0x00, 0xfc, 0x7e, 0x23, 0x65, 0x70, 0xf8, 0xce, 0xd3, 0x40, 0x41,
    0x80, 0x6a, 0x1d, 0x01, 0xd6, 0x01, 0xff, 0xb6, 0x1b, 0x3d, 0x3d, 0x59,
    0x09, 0x33, 0x79, 0xc0, 0x4f, 0xde, 0x96, 0x27, 0x4b, 0x18, 0xc6, 0xd9,
    0x78, 0xf1, 0xf4, 0x35, 0x46, 0xe9, 0x7c, 0x42, 0x7a, 0x5d, 0x9f, 0xef,
    0x54, 0xb8, 0xf7, 0x9f, 0xc4, 0x33, 0x6c, 0xf3, 0x8c, 0x32, 0x46, 0x87,
    0x67, 0x30, 0x7b, 0xa7, 0xac, 0xe3, 0x02, 0x41, 0x00, 0xfc, 0x2c, 0xdf,
    0x0c, 0x0d, 0x88, 0xf5, 0xb1, 0x92, 0xa8, 0x93, 0x47, 0x63, 0x55, 0xf5,
    0xca, 0x58, 0x43, 0xba, 0x1c, 0xe5, 0x9e, 0xb6, 0x95, 0x05, 0xcd, 0xb5,
    0x82, 0xdf, 0xeb, 0x04, 0x53, 0x9d, 0xbd, 0xc2, 0x38, 0x16, 0xb3, 0x62,
    0xdd, 0xa1, 0x46, 0xdb, 0x6d, 0x97, 0x93, 0x9f, 0x8a, 0xc3, 0x9b, 0x64,
    0x7e, 0x42, 0xe3, 0x32, 0x57, 0x19, 0x1b, 0xd5, 0x6e, 0x85, 0xfa, 0xb8,
    0x8d, 0x02, 0x41, 0x00, 0xbc, 0x3d, 0xde, 0x6d, 0xd6, 0x97, 0xe8, 0xba,
    0x9e, 0x81, 0x37, 0x17, 0xe5, 0xa0, 0x64, 0xc9, 0x00, 0xb7, 0xe7, 0xfe,
    0xf4, 0x29, 0xd9, 0x2e, 0x43, 0x6b, 0x19, 0x20, 0xbd, 0x99, 0x75, 0xe7,
    0x76, 0xf8, 0xd3, 0xae, 0xaf, 0x7e, 0xb8, 0xeb, 0x81, 0xf4, 0x9d, 0xfe,
    0x07, 0x2b, 0x0b, 0x63, 0x0b, 0x5a, 0x55, 0x90, 0x71, 0x7d, 0xf1, 0xdb,
    0xd9, 0xb1, 0x41, 0x41, 0x68, 0x2f, 0x4e, 0x39, 0x02, 0x40, 0x5a, 0x34,
    0x66, 0xd8, 0xf5, 0xe2, 0x7f, 0x18, 0xb5, 0x00, 0x6e, 0x26, 0x84, 0x27,
    0x14, 0x93, 0xfb, 0xfc, 0xc6, 0x0f, 0x5e, 0x27, 0xe6, 0xe1, 0xe9, 0xc0,
    0x8a, 0xe4, 0x34, 0xda, 0xe9, 0xa2, 0x4b, 0x73, 0xbc, 0x8c, 0xb9, 0xba,
    0x13, 0x6c, 0x7a, 0x2b, 0x51, 0x84, 0xa3, 0x4a, 0xe0, 0x30, 0x10, 0x06,
    0x7e, 0xed, 0x17, 0x5a, 0x14, 0x00, 0xc9, 0xef, 0x85, 0xea, 0x52, 0x2c,
    0xbc, 0x65, 0x02, 0x40, 0x51, 0xe3, 0xf2, 0x83, 0x19, 0x9b, 0xc4, 0x1e,
    0x2f, 0x50, 0x3d, 0xdf, 0x5a, 0xa2, 0x18, 0xca, 0x5f, 0x2e, 0x49, 0xaf,
    0x6f, 0xcc, 0xfa, 0x65, 0x77, 0x94, 0xb5, 0xa1, 0x0a, 0xa9, 0xd1, 0x8a,
    0x39, 0x37, 0xf4, 0x0b, 0xa0, 0xd7, 0x82, 0x27, 0x5e, 0xae, 0x17, 0x17,
    0xa1, 0x1e, 0x54, 0x34, 0xbf, 0x6e, 0xc4, 0x8e, 0x99, 0x5d, 0x08, 0xf1,
    0x2d, 0x86, 0x9d, 0xa5, 0x20, 0x1b, 0xe5, 0xdf,
};

/*
 * kExampleBadRSAKeyDER is an RSA private key in ASN.1, DER format. The private
 * components are not correct.
 */
static const unsigned char kExampleBadRSAKeyDER[] = {
    0x30, 0x82, 0x04, 0x27, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
    0xa6, 0x1a, 0x1e, 0x6e, 0x7b, 0xee, 0xc6, 0x89, 0x66, 0xe7, 0x93, 0xef,
    0x54, 0x12, 0x68, 0xea, 0xbf, 0x86, 0x2f, 0xdd, 0xd2, 0x79, 0xb8, 0xa9,
    0x6e, 0x03, 0xc2, 0xa3, 0xb9, 0xa3, 0xe1, 0x4b, 0x2a, 0xb3, 0xf8, 0xb4,
    0xcd, 0xea, 0xbe, 0x24, 0xa6, 0x57, 0x5b, 0x83, 0x1f, 0x0f, 0xf2, 0xd3,
    0xb7, 0xac, 0x7e, 0xd6, 0x8e, 0x6e, 0x1e, 0xbf, 0xb8, 0x73, 0x8c, 0x05,
    0x56, 0xe6, 0x35, 0x1f, 0xe9, 0x04, 0x0b, 0x09, 0x86, 0x7d, 0xf1, 0x26,
    0x08, 0x99, 0xad, 0x7b, 0xc8, 0x4d, 0x94, 0xb0, 0x0b, 0x8b, 0x38, 0xa0,
    0x5c, 0x62, 0xa0, 0xab, 0xd3, 0x8f, 0xd4, 0x09, 0x60, 0x72, 0x1e, 0x33,
    0x50, 0x80, 0x6e, 0x22, 0xa6, 0x77, 0x57, 0x6b, 0x9a, 0x33, 0x21, 0x66,
    0x87, 0x6e, 0x21, 0x7b, 0xc7, 0x24, 0x0e, 0xd8, 0x13, 0xdf, 0x83, 0xde,
    0xcd, 0x40, 0x58, 0x1d, 0x84, 0x86, 0xeb, 0xb8, 0x12, 0x4e, 0xd2, 0xfa,
    0x80, 0x1f, 0xe4, 0xe7, 0x96, 0x29, 0xb8, 0xcc, 0xce, 0x66, 0x6d, 0x53,
    0xca, 0xb9, 0x5a, 0xd7, 0xf6, 0x84, 0x6c, 0x2d, 0x9a, 0x1a, 0x14, 0x1c,
    0x4e, 0x93, 0x39, 0xba, 0x74, 0xed, 0xed, 0x87, 0x87, 0x5e, 0x48, 0x75,
    0x36, 0xf0, 0xbc, 0x34, 0xfb, 0x29, 0xf9, 0x9f, 0x96, 0x5b, 0x0b, 0xa7,
    0x54, 0x30, 0x51, 0x29, 0x18, 0x5b, 0x7d, 0xac, 0x0f, 0xd6, 0x5f, 0x7c,
    0xf8, 0x98, 0x8c, 0xd8, 0x86, 0x62, 0xb3, 0xdc, 0xff, 0x0f, 0xff, 0x7a,
    0xaf, 0x5c, 0x4c, 0x61, 0x49, 0x2e, 0xc8, 0x95, 0x86, 0xc4, 0x0e, 0x87,
    0xfc, 0x1d, 0xcf, 0x8b, 0x7c, 0x61, 0xf6, 0xd8, 0xd0, 0x69, 0xf6, 0xcd,
    0x8a, 0x8c, 0xf6, 0x62, 0xa2, 0x56, 0xa9, 0xe3, 0xd1, 0xcf, 0x4d, 0xa0,
    0xf6, 0x2d, 0x20, 0x0a, 0x04, 0xb7, 0xa2, 0xf7, 0xb5, 0x99, 0x47, 0x18,
    0x56, 0x85, 0x87, 0xc7, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
    0x01, 0x00, 0x99, 0x41, 0x38, 0x1a, 0xd0, 0x96, 0x7a, 0xf0, 0x83, 0xd5,
    0xdf, 0x94, 0xce, 0x89, 0x3d, 0xec, 0x7a, 0x52, 0x21, 0x10, 0x16, 0x06,
    0xe0, 0xee, 0xd2, 0xe6, 0xfd, 0x4b, 0x7b, 0x19, 0x4d, 0xe1, 0xc0, 0xc0,
    0xd5, 0x14, 0x5d, 0x79, 0xdd, 0x7e, 0x8b, 0x4b, 0xc6, 0xcf, 0xb0, 0x75,
    0x52, 0xa3, 0x2d, 0xb1, 0x26, 0x46, 0x68, 0x9c, 0x0a, 0x1a, 0xf2, 0xe1,
    0x09, 0xac, 0x53, 0x85, 0x8c, 0x36, 0xa9, 0x14, 0x65, 0xea, 0xa0, 0x00,
    0xcb, 0xe3, 0x3f, 0xc4, 0x2b, 0x61, 0x2e, 0x6b, 0x06, 0x69, 0x77, 0xfd,
    0x38, 0x7e, 0x1d, 0x3f, 0x92, 0xe7, 0x77, 0x08, 0x19, 0xa7, 0x9d, 0x29,
    0x2d, 0xdc, 0x42, 0xc6, 0x7c, 0xd7, 0xd3, 0xa8, 0x01, 0x2c, 0xf2, 0xd5,
    0x82, 0x57, 0xcb, 0x55, 0x3d, 0xe7, 0xaa, 0xd2, 0x06, 0x30, 0x30, 0x05,
    0xe6, 0xf2, 0x47, 0x86, 0xba, 0xc6, 0x61, 0x64, 0xeb, 0x4f, 0x2a, 0x5e,
    0x07, 0x29, 0xe0, 0x96, 0xb2, 0x43, 0xff, 0x5f, 0x1a, 0x54, 0x16, 0xcf,
    0xb5, 0x56, 0x5c, 0xa0, 0x9b, 0x0c, 0xfd, 0xb3, 0xd2, 0xe3, 0x79, 0x1d,
    0x21, 0xe2, 0xd6, 0x13, 0xc4, 0x74, 0xa6, 0xf5, 0x8e, 0x8e, 0x81, 0xbb,
    0xb4, 0xad, 0x8a, 0xf0, 0x93, 0x0a, 0xd8, 0x0a, 0x42, 0x36, 0xbc, 0xe5,
    0x26, 0x2a, 0x0d, 0x5d, 0x57, 0x13, 0xc5, 0x4e, 0x2f, 0x12, 0x0e, 0xef,
    0xa7, 0x81, 0x1e, 0xc3, 0xa5, 0xdb, 0xc9, 0x24, 0xeb, 0x1a, 0xa1, 0xf9,
    0xf6, 0xa1, 0x78, 0x98, 0x93, 0x77, 0x42, 0x45, 0x03, 0xe2, 0xc9, 0xa2,
    0xfe, 0x2d, 0x77, 0xc8, 0xc6, 0xac, 0x9b, 0x98, 0x89, 0x6d, 0x9a, 0xe7,
    0x61, 0x63, 0xb7, 0xf2, 0xec, 0xd6, 0xb1, 0xa1, 0x6e, 0x0a, 0x1a, 0xff,
    0xfd, 0x43, 0x28, 0xc3, 0x0c, 0xdc, 0xf2, 0x47, 0x4f, 0x27, 0xaa, 0x99,
    0x04, 0x8e, 0xac, 0xe8, 0x7c, 0x01, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78,
    0x02, 0x81, 0x81, 0x00, 0xca, 0x69, 0xe5, 0xbb, 0x3a, 0x90, 0x82, 0xcb,
    0x82, 0x50, 0x2f, 0x29, 0xe2, 0x76, 0x6a, 0x57, 0x55, 0x45, 0x4e, 0x35,
    0x18, 0x61, 0xe0, 0x12, 0x70, 0xc0, 0xab, 0xc7, 0x80, 0xa2, 0xd4, 0x46,
    0x34, 0x03, 0xa0, 0x19, 0x26, 0x23, 0x9e, 0xef, 0x1a, 0xcb, 0x75, 0xd6,
    0xba, 0x81, 0xf4, 0x7e, 0x52, 0xe5, 0x2a, 0xe8, 0xf1, 0x49, 0x6c, 0x0f,
    0x1a, 0xa0, 0xf9, 0xc6, 0xe7, 0xec, 0x60, 0xe4, 0xcb, 0x2a, 0xb5, 0x56,
    0xe9, 0x9c, 0xcd, 0x19, 0x75, 0x92, 0xb1, 0x66, 0xce, 0xc3, 0xd9, 0x3d,
    0x11, 0xcb, 0xc4, 0x09, 0xce, 0x1e, 0x30, 0xba, 0x2f, 0x60, 0x60, 0x55,
    0x8d, 0x02, 0xdc, 0x5d, 0xaf, 0xf7, 0x52, 0x31, 0x17, 0x07, 0x53, 0x20,
    0x33, 0xad, 0x8c, 0xd5, 0x2f, 0x5a, 0xd0, 0x57, 0xd7, 0xd1, 0x80, 0xd6,
    0x3a, 0x9b, 0x04, 0x4f, 0x35, 0xbf, 0xe7, 0xd5, 0xbc, 0x8f, 0xd4, 0x81,
    0x02, 0x81, 0x81, 0x00, 0xc0, 0x9f, 0xf8, 0xcd, 0xf7, 0x3f, 0x26, 0x8a,
    0x3d, 0x4d, 0x2b, 0x0c, 0x01, 0xd0, 0xa2, 0xb4, 0x18, 0xfe, 0xf7, 0x5e,
    0x2f, 0x06, 0x13, 0xcd, 0x63, 0xaa, 0x12, 0xa9, 0x24, 0x86, 0xe3, 0xf3,
    0x7b, 0xda, 0x1a, 0x3c, 0xb1, 0x38, 0x80, 0x80, 0xef, 0x64, 0x64, 0xa1,
    0x9b, 0xfe, 0x76, 0x63, 0x8e, 0x83, 0xd2, 0xd9, 0xb9, 0x86, 0xb0, 0xe6,
    0xa6, 0x0c, 0x7e, 0xa8, 0x84, 0x90, 0x98, 0x0c, 0x1e, 0xf3, 0x14, 0x77,
    0xe0, 0x5f, 0x81, 0x08, 0x11, 0x8f, 0xa6, 0x23, 0xc4, 0xba, 0xc0, 0x8a,
    0xe4, 0xc6, 0xe3, 0x5c, 0xbe, 0xc5, 0xec, 0x2c, 0xb9, 0xd8, 0x8c, 0x4d,
    0x1a, 0x9d, 0xe7, 0x7c, 0x85, 0x4c, 0x0d, 0x71, 0x4e, 0x72, 0x33, 0x1b,
    0xfe, 0xa9, 0x17, 0x72, 0x76, 0x56, 0x9d, 0x74, 0x7e, 0x52, 0x67, 0x9a,
    0x87, 0x9a, 0xdb, 0x30, 0xde, 0xe4, 0x49, 0x28, 0x3b, 0xd2, 0x67, 0xaf,
    0x02, 0x81, 0x81, 0x00, 0x89, 0x74, 0x9a, 0x8e, 0xa7, 0xb9, 0xa5, 0x28,
    0xc0, 0x68, 0xe5, 0x6e, 0x63, 0x1c, 0x99, 0x20, 0x8f, 0x86, 0x8e, 0x12,
    0x9e, 0x69, 0x30, 0xfa, 0x34, 0xd9, 0x92, 0x8d, 0xdb, 0x7c, 0x37, 0xfd,
    0x28, 0xab, 0x61, 0x98, 0x52, 0x7f, 0x14, 0x1a, 0x39, 0xae, 0xfb, 0x6a,
    0x03, 0xa3, 0xe6, 0xbd, 0xb6, 0x5b, 0x6b, 0xe5, 0x5e, 0x9d, 0xc6, 0xa5,
    0x07, 0x27, 0x54, 0x17, 0xd0, 0x3d, 0x84, 0x9b, 0x3a, 0xa0, 0xd9, 0x1e,
    0x99, 0x6c, 0x63, 0x17, 0xab, 0xf1, 0x1f, 0x49, 0xba, 0x95, 0xe3, 0x3b,
    0x86, 0x8f, 0x42, 0xa4, 0x89, 0xf5, 0x94, 0x8f, 0x8b, 0x46, 0xbe, 0x84,
    0xba, 0x4a, 0xbc, 0x0d, 0x5f, 0x46, 0xeb, 0xe8, 0xec, 0x43, 0x8c, 0x1e,
    0xad, 0x19, 0x69, 0x2f, 0x08, 0x86, 0x7a, 0x3f, 0x7d, 0x0f, 0x07, 0x97,
    0xf3, 0x9a, 0x7b, 0xb5, 0xb2, 0xc1, 0x8c, 0x95, 0x68, 0x04, 0xa0, 0x81,
    0x02, 0x81, 0x80, 0x4e, 0xbf, 0x7e, 0x1b, 0xcb, 0x13, 0x61, 0x75, 0x3b,
    0xdb, 0x59, 0x5f, 0xb1, 0xd4, 0xb8, 0xeb, 0x9e, 0x73, 0xb5, 0xe7, 0xf6,
    0x89, 0x3d, 0x1c, 0xda, 0xf0, 0x36, 0xff, 0x35, 0xbd, 0x1e, 0x0b, 0x74,
    0xe3, 0x9e, 0xf0, 0xf2, 0xf7, 0xd7, 0x82, 0xb7, 0x7b, 0x6a, 0x1b, 0x0e,
    0x30, 0x4a, 0x98, 0x0e, 0xb4, 0xf9, 0x81, 0x07, 0xe4, 0x75, 0x39, 0xe9,
    0x53, 0xca, 0xbb, 0x5c, 0xaa, 0x93, 0x07, 0x0e, 0xa8, 0x2f, 0xba, 0x98,
    0x49, 0x30, 0xa7, 0xcc, 0x1a, 0x3c, 0x68, 0x0c, 0xe1, 0xa4, 0xb1, 0x05,
    0xe6, 0xe0, 0x25, 0x78, 0x58, 0x14, 0x37, 0xf5, 0x1f, 0xe3, 0x22, 0xef,
    0xa8, 0x0e, 0x22, 0xa0, 0x94, 0x3a, 0xf6, 0xc9, 0x13, 0xe6, 0x06, 0xbf,
    0x7f, 0x99, 0xc6, 0xcc, 0xd8, 0xc6, 0xbe, 0xd9, 0x2e, 0x24, 0xc7, 0x69,
    0x8c, 0x95, 0xba, 0xf6, 0x04, 0xb3, 0x0a, 0xf4, 0xcb, 0xf0, 0xce,
};

static const unsigned char kMsg[] = { 1, 2, 3, 4 };

static const unsigned char kSignature[] = {
    0xa5, 0xf0, 0x8a, 0x47, 0x5d, 0x3c, 0xb3, 0xcc, 0xa9, 0x79, 0xaf, 0x4d,
    0x8c, 0xae, 0x4c, 0x14, 0xef, 0xc2, 0x0b, 0x34, 0x36, 0xde, 0xf4, 0x3e,
    0x3d, 0xbb, 0x4a, 0x60, 0x5c, 0xc8, 0x91, 0x28, 0xda, 0xfb, 0x7e, 0x04,
    0x96, 0x7e, 0x63, 0x13, 0x90, 0xce, 0xb9, 0xb4, 0x62, 0x7a, 0xfd, 0x09,
    0x3d, 0xc7, 0x67, 0x78, 0x54, 0x04, 0xeb, 0x52, 0x62, 0x6e, 0x24, 0x67,
    0xb4, 0x40, 0xfc, 0x57, 0x62, 0xc6, 0xf1, 0x67, 0xc1, 0x97, 0x8f, 0x6a,
    0xa8, 0xae, 0x44, 0x46, 0x5e, 0xab, 0x67, 0x17, 0x53, 0x19, 0x3a, 0xda,
    0x5a, 0xc8, 0x16, 0x3e, 0x86, 0xd5, 0xc5, 0x71, 0x2f, 0xfc, 0x23, 0x48,
    0xd9, 0x0b, 0x13, 0xdd, 0x7b, 0x5a, 0x25, 0x79, 0xef, 0xa5, 0x7b, 0x04,
    0xed, 0x44, 0xf6, 0x18, 0x55, 0xe4, 0x0a, 0xe9, 0x57, 0x79, 0x5d, 0xd7,
    0x55, 0xa7, 0xab, 0x45, 0x02, 0x97, 0x60, 0x42,
};

/*
 * kExampleRSAKeyPKCS8 is kExampleRSAKeyDER encoded in a PKCS #8
 * PrivateKeyInfo.
 */
static const unsigned char kExampleRSAKeyPKCS8[] = {
    0x30, 0x82, 0x02, 0x76, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
    0x02, 0x60, 0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81,
    0x00, 0xf8, 0xb8, 0x6c, 0x83, 0xb4, 0xbc, 0xd9, 0xa8, 0x57, 0xc0, 0xa5,
    0xb4, 0x59, 0x76, 0x8c, 0x54, 0x1d, 0x79, 0xeb, 0x22, 0x52, 0x04, 0x7e,
    0xd3, 0x37, 0xeb, 0x41, 0xfd, 0x83, 0xf9, 0xf0, 0xa6, 0x85, 0x15, 0x34,
    0x75, 0x71, 0x5a, 0x84, 0xa8, 0x3c, 0xd2, 0xef, 0x5a, 0x4e, 0xd3, 0xde,
    0x97, 0x8a, 0xdd, 0xff, 0xbb, 0xcf, 0x0a, 0xaa, 0x86, 0x92, 0xbe, 0xb8,
    0x50, 0xe4, 0xcd, 0x6f, 0x80, 0x33, 0x30, 0x76, 0x13, 0x8f, 0xca, 0x7b,
    0xdc, 0xec, 0x5a, 0xca, 0x63, 0xc7, 0x03, 0x25, 0xef, 0xa8, 0x8a, 0x83,
    0x58, 0x76, 0x20, 0xfa, 0x16, 0x77, 0xd7, 0x79, 0x92, 0x63, 0x01, 0x48,
    0x1a, 0xd8, 0x7b, 0x67, 0xf1, 0x52, 0x55, 0x49, 0x4e, 0xd6, 0x6e, 0x4a,
    0x5c, 0xd7, 0x7a, 0x37, 0x36, 0x0c, 0xde, 0xdd, 0x8f, 0x44, 0xe8, 0xc2,
    0xa7, 0x2c, 0x2b, 0xb5, 0xaf, 0x64, 0x4b, 0x61, 0x07, 0x02, 0x03, 0x01,
    0x00, 0x01, 0x02, 0x81, 0x80, 0x74, 0x88, 0x64, 0x3f, 0x69, 0x45, 0x3a,
    0x6d, 0xc7, 0x7f, 0xb9, 0xa3, 0xc0, 0x6e, 0xec, 0xdc, 0xd4, 0x5a, 0xb5,
    0x32, 0x85, 0x5f, 0x19, 0xd4, 0xf8, 0xd4, 0x3f, 0x3c, 0xfa, 0xc2, 0xf6,
    0x5f, 0xee, 0xe6, 0xba, 0x87, 0x74, 0x2e, 0xc7, 0x0c, 0xd4, 0x42, 0xb8,
    0x66, 0x85, 0x9c, 0x7b, 0x24, 0x61, 0xaa, 0x16, 0x11, 0xf6, 0xb5, 0xb6,
    0xa4, 0x0a, 0xc9, 0x55, 0x2e, 0x81, 0xa5, 0x47, 0x61, 0xcb, 0x25, 0x8f,
    0xc2, 0x15, 0x7b, 0x0e, 0x7c, 0x36, 0x9f, 0x3a, 0xda, 0x58, 0x86, 0x1c,
    0x5b, 0x83, 0x79, 0xe6, 0x2b, 0xcc, 0xe6, 0xfa, 0x2c, 0x61, 0xf2, 0x78,
    0x80, 0x1b, 0xe2, 0xf3, 0x9d, 0x39, 0x2b, 0x65, 0x57, 0x91, 0x3d, 0x71,
    0x99, 0x73, 0xa5, 0xc2, 0x79, 0x20, 0x8c, 0x07, 0x4f, 0xe5, 0xb4, 0x60,
    0x1f, 0x99, 0xa2, 0xb1, 0x4f, 0x0c, 0xef, 0xbc, 0x59, 0x53, 0x00, 0x7d,
    0xb1, 0x02, 0x41, 0x00, 0xfc, 0x7e, 0x23, 0x65, 0x70, 0xf8, 0xce, 0xd3,
    0x40, 0x41, 0x80, 0x6a, 0x1d, 0x01, 0xd6, 0x01, 0xff, 0xb6, 0x1b, 0x3d,
    0x3d, 0x59, 0x09, 0x33, 0x79, 0xc0, 0x4f, 0xde, 0x96, 0x27, 0x4b, 0x18,
    0xc6, 0xd9, 0x78, 0xf1, 0xf4, 0x35, 0x46, 0xe9, 0x7c, 0x42, 0x7a, 0x5d,
    0x9f, 0xef, 0x54, 0xb8, 0xf7, 0x9f, 0xc4, 0x33, 0x6c, 0xf3, 0x8c, 0x32,
    0x46, 0x87, 0x67, 0x30, 0x7b, 0xa7, 0xac, 0xe3, 0x02, 0x41, 0x00, 0xfc,
    0x2c, 0xdf, 0x0c, 0x0d, 0x88, 0xf5, 0xb1, 0x92, 0xa8, 0x93, 0x47, 0x63,
    0x55, 0xf5, 0xca, 0x58, 0x43, 0xba, 0x1c, 0xe5, 0x9e, 0xb6, 0x95, 0x05,
    0xcd, 0xb5, 0x82, 0xdf, 0xeb, 0x04, 0x53, 0x9d, 0xbd, 0xc2, 0x38, 0x16,
    0xb3, 0x62, 0xdd, 0xa1, 0x46, 0xdb, 0x6d, 0x97, 0x93, 0x9f, 0x8a, 0xc3,
    0x9b, 0x64, 0x7e, 0x42, 0xe3, 0x32, 0x57, 0x19, 0x1b, 0xd5, 0x6e, 0x85,
    0xfa, 0xb8, 0x8d, 0x02, 0x41, 0x00, 0xbc, 0x3d, 0xde, 0x6d, 0xd6, 0x97,
    0xe8, 0xba, 0x9e, 0x81, 0x37, 0x17, 0xe5, 0xa0, 0x64, 0xc9, 0x00, 0xb7,
    0xe7, 0xfe, 0xf4, 0x29, 0xd9, 0x2e, 0x43, 0x6b, 0x19, 0x20, 0xbd, 0x99,
    0x75, 0xe7, 0x76, 0xf8, 0xd3, 0xae, 0xaf, 0x7e, 0xb8, 0xeb, 0x81, 0xf4,
    0x9d, 0xfe, 0x07, 0x2b, 0x0b, 0x63, 0x0b, 0x5a, 0x55, 0x90, 0x71, 0x7d,
    0xf1, 0xdb, 0xd9, 0xb1, 0x41, 0x41, 0x68, 0x2f, 0x4e, 0x39, 0x02, 0x40,
    0x5a, 0x34, 0x66, 0xd8, 0xf5, 0xe2, 0x7f, 0x18, 0xb5, 0x00, 0x6e, 0x26,
    0x84, 0x27, 0x14, 0x93, 0xfb, 0xfc, 0xc6, 0x0f, 0x5e, 0x27, 0xe6, 0xe1,
    0xe9, 0xc0, 0x8a, 0xe4, 0x34, 0xda, 0xe9, 0xa2, 0x4b, 0x73, 0xbc, 0x8c,
    0xb9, 0xba, 0x13, 0x6c, 0x7a, 0x2b, 0x51, 0x84, 0xa3, 0x4a, 0xe0, 0x30,
    0x10, 0x06, 0x7e, 0xed, 0x17, 0x5a, 0x14, 0x00, 0xc9, 0xef, 0x85, 0xea,
    0x52, 0x2c, 0xbc, 0x65, 0x02, 0x40, 0x51, 0xe3, 0xf2, 0x83, 0x19, 0x9b,
    0xc4, 0x1e, 0x2f, 0x50, 0x3d, 0xdf, 0x5a, 0xa2, 0x18, 0xca, 0x5f, 0x2e,
    0x49, 0xaf, 0x6f, 0xcc, 0xfa, 0x65, 0x77, 0x94, 0xb5, 0xa1, 0x0a, 0xa9,
    0xd1, 0x8a, 0x39, 0x37, 0xf4, 0x0b, 0xa0, 0xd7, 0x82, 0x27, 0x5e, 0xae,
    0x17, 0x17, 0xa1, 0x1e, 0x54, 0x34, 0xbf, 0x6e, 0xc4, 0x8e, 0x99, 0x5d,
    0x08, 0xf1, 0x2d, 0x86, 0x9d, 0xa5, 0x20, 0x1b, 0xe5, 0xdf,
};

#ifndef OPENSSL_NO_EC
/*
 * kExampleECKeyDER is a sample EC private key encoded as an ECPrivateKey
 * structure.
 */
static const unsigned char kExampleECKeyDER[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x07, 0x0f, 0x08, 0x72, 0x7a,
    0xd4, 0xa0, 0x4a, 0x9c, 0xdd, 0x59, 0xc9, 0x4d, 0x89, 0x68, 0x77, 0x08,
    0xb5, 0x6f, 0xc9, 0x5d, 0x30, 0x77, 0x0e, 0xe8, 0xd1, 0xc9, 0xce, 0x0a,
    0x8b, 0xb4, 0x6a, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xe6, 0x2b, 0x69,
    0xe2, 0xbf, 0x65, 0x9f, 0x97, 0xbe, 0x2f, 0x1e, 0x0d, 0x94, 0x8a, 0x4c,
    0xd5, 0x97, 0x6b, 0xb7, 0xa9, 0x1e, 0x0d, 0x46, 0xfb, 0xdd, 0xa9, 0xa9,
    0x1e, 0x9d, 0xdc, 0xba, 0x5a, 0x01, 0xe7, 0xd6, 0x97, 0xa8, 0x0a, 0x18,
    0xf9, 0xc3, 0xc4, 0xa3, 0x1e, 0x56, 0xe2, 0x7c, 0x83, 0x48, 0xdb, 0x16,
    0x1a, 0x1c, 0xf5, 0x1d, 0x7e, 0xf1, 0x94, 0x2d, 0x4b, 0xcf, 0x72, 0x22,
    0xc1,
};

/*
 * kExampleBadECKeyDER is a sample EC private key encoded as an ECPrivateKey
 * structure. The private key is equal to the order and will fail to import
 */
static const unsigned char kExampleBadECKeyDER[] = {
    0x30, 0x66, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
    0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03,
    0x01, 0x07, 0x04, 0x4C, 0x30, 0x4A, 0x02, 0x01, 0x01, 0x04, 0x20, 0xFF,
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3,
    0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51, 0xA1, 0x23, 0x03, 0x21, 0x00,
    0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};
#endif

typedef struct APK_DATA_st {
    const unsigned char *kder;
    size_t size;
    int evptype;
    int check;
} APK_DATA;

static APK_DATA keydata[] = {
    {kExampleRSAKeyDER, sizeof(kExampleRSAKeyDER), EVP_PKEY_RSA},
    {kExampleRSAKeyPKCS8, sizeof(kExampleRSAKeyPKCS8), EVP_PKEY_RSA},
#ifndef OPENSSL_NO_EC
    {kExampleECKeyDER, sizeof(kExampleECKeyDER), EVP_PKEY_EC}
#endif
};

static APK_DATA keycheckdata[] = {
    {kExampleRSAKeyDER, sizeof(kExampleRSAKeyDER), EVP_PKEY_RSA, 1},
    {kExampleBadRSAKeyDER, sizeof(kExampleBadRSAKeyDER), EVP_PKEY_RSA, 0},
#ifndef OPENSSL_NO_EC
    {kExampleECKeyDER, sizeof(kExampleECKeyDER), EVP_PKEY_EC, 1}
#endif
};

static EVP_PKEY *load_example_rsa_key(void)
{
    EVP_PKEY *ret = NULL;
    const unsigned char *derp = kExampleRSAKeyDER;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    if (!TEST_true(d2i_RSAPrivateKey(&rsa, &derp, sizeof(kExampleRSAKeyDER))))
        return NULL;

    if (!TEST_ptr(pkey = EVP_PKEY_new())
            || !TEST_true(EVP_PKEY_set1_RSA(pkey, rsa)))
        goto end;

    ret = pkey;
    pkey = NULL;

end:
    EVP_PKEY_free(pkey);
    RSA_free(rsa);

    return ret;
}

static int test_EVP_DigestSignInit(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    EVP_MD_CTX *md_ctx, *md_ctx_verify = NULL;

    if (!TEST_ptr(md_ctx = EVP_MD_CTX_new())
            || !TEST_ptr(md_ctx_verify = EVP_MD_CTX_new())
            || !TEST_ptr(pkey = load_example_rsa_key()))
        goto out;

    if (!TEST_true(EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey))
            || !TEST_true(EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg))))
        goto out;

    /* Determine the size of the signature. */
    if (!TEST_true(EVP_DigestSignFinal(md_ctx, NULL, &sig_len))
            || !TEST_size_t_eq(sig_len, (size_t)EVP_PKEY_size(pkey)))
        goto out;

    if (!TEST_ptr(sig = OPENSSL_malloc(sig_len))
            || !TEST_true(EVP_DigestSignFinal(md_ctx, sig, &sig_len)))
        goto out;

    /* Ensure that the signature round-trips. */
    if (!TEST_true(EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sha256(),
                                        NULL, pkey))
            || !TEST_true(EVP_DigestVerifyUpdate(md_ctx_verify,
                                                 kMsg, sizeof(kMsg)))
            || !TEST_true(EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len)))
        goto out;

    ret = 1;

 out:
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_CTX_free(md_ctx_verify);
    EVP_PKEY_free(pkey);
    OPENSSL_free(sig);

    return ret;
}

static int test_EVP_DigestVerifyInit(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    if (!TEST_ptr(md_ctx = EVP_MD_CTX_new())
            || !TEST_ptr(pkey = load_example_rsa_key()))
        goto out;

    if (!TEST_true(EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey))
            || !TEST_true(EVP_DigestVerifyUpdate(md_ctx, kMsg, sizeof(kMsg)))
            || !TEST_true(EVP_DigestVerifyFinal(md_ctx, kSignature,
                                                 sizeof(kSignature))))
        goto out;
    ret = 1;

 out:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_d2i_AutoPrivateKey(int i)
{
    int ret = 0;
    const unsigned char *p;
    EVP_PKEY *pkey = NULL;
    const APK_DATA *ak = &keydata[i];
    const unsigned char *input = ak->kder;
    size_t input_len = ak->size;
    int expected_id = ak->evptype;

    p = input;
    if (!TEST_ptr(pkey = d2i_AutoPrivateKey(NULL, &p, input_len))
            || !TEST_ptr_eq(p, input + input_len)
            || !TEST_int_eq(EVP_PKEY_id(pkey), expected_id))
        goto done;

    ret = 1;

 done:
    EVP_PKEY_free(pkey);
    return ret;
}

#ifndef OPENSSL_NO_EC
/* Tests loading a bad key in PKCS8 format */
static int test_EVP_PKCS82PKEY(void)
{
    int ret = 0;
    const unsigned char *derp = kExampleBadECKeyDER;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    EVP_PKEY *pkey = NULL;

    if (!TEST_ptr(p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &derp,
                                              sizeof(kExampleBadECKeyDER))))
        goto done;

    if (!TEST_ptr_eq(derp,
                     kExampleBadECKeyDER + sizeof(kExampleBadECKeyDER)))
        goto done;

    if (!TEST_ptr_null(pkey = EVP_PKCS82PKEY(p8inf)))
        goto done;

    ret = 1;

 done:
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    EVP_PKEY_free(pkey);

    return ret;
}
#endif

static int test_EVP_PKEY_check(int i)
{
    int ret = 0;
    const unsigned char *p;
    EVP_PKEY *pkey = NULL;
    const APK_DATA *ak = &keycheckdata[i];
    const unsigned char *input = ak->kder;
    size_t input_len = ak->size;
    int expected_id = ak->evptype;
    int expected_check = ak->check;

    p = input;
    if (!TEST_ptr(pkey = d2i_AutoPrivateKey(NULL, &p, input_len))
            || !TEST_ptr_eq(p, input + input_len)
            || !TEST_int_eq(EVP_PKEY_id(pkey), expected_id))
        goto done;

    if (expected_check == 1) {
        if (!TEST_int_eq(EVP_PKEY_check(pkey), 1))
            goto done;
    } else {
        if (!TEST_int_ne(EVP_PKEY_check(pkey), 1))
            goto done;
    }

    ret = 1;

 done:
    EVP_PKEY_free(pkey);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_EVP_DigestSignInit);
    ADD_TEST(test_EVP_DigestVerifyInit);
    ADD_ALL_TESTS(test_d2i_AutoPrivateKey, OSSL_NELEM(keydata));
#ifndef OPENSSL_NO_EC
    ADD_TEST(test_EVP_PKCS82PKEY);
#endif
    ADD_ALL_TESTS(test_EVP_PKEY_check, OSSL_NELEM(keycheckdata));
    return 1;
}
