/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CRYPTOERR_H
# define OPENSSL_CRYPTOERR_H
# pragma once

//# include <openssl/macros.h>
# include "macros.h"
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_CRYPTOERR_H
# endif

//# include <openssl/opensslconf.h>
//# include <openssl/symhacks.h>
# include "symhacks.h"


# ifdef  __cplusplus
extern "C"
# endif
int ERR_load_CRYPTO_strings(void);

/*
 * CRYPTO function codes.
 */
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define CRYPTO_F_CMAC_CTX_NEW                            0
#  define CRYPTO_F_CRYPTO_DUP_EX_DATA                      0
#  define CRYPTO_F_CRYPTO_FREE_EX_DATA                     0
#  define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX                 0
#  define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX_EX              0
#  define CRYPTO_F_CRYPTO_MEMDUP                           0
#  define CRYPTO_F_CRYPTO_NEW_EX_DATA                      0
#  define CRYPTO_F_CRYPTO_NEW_EX_DATA_EX                   0
#  define CRYPTO_F_CRYPTO_OCB128_COPY_CTX                  0
#  define CRYPTO_F_CRYPTO_OCB128_INIT                      0
#  define CRYPTO_F_CRYPTO_SET_EX_DATA                      0
#  define CRYPTO_F_FIPS_MODE_SET                           0
#  define CRYPTO_F_GET_AND_LOCK                            0
#  define CRYPTO_F_GET_PROVIDER_STORE                      0
#  define CRYPTO_F_OPENSSL_ATEXIT                          0
#  define CRYPTO_F_OPENSSL_BUF2HEXSTR                      0
#  define CRYPTO_F_OPENSSL_BUF2HEXSTR_EX                   0
#  define CRYPTO_F_OPENSSL_FOPEN                           0
#  define CRYPTO_F_OPENSSL_HEXSTR2BUF                      0
#  define CRYPTO_F_OPENSSL_HEXSTR2BUF_EX                   0
#  define CRYPTO_F_OPENSSL_INIT_CRYPTO                     0
#  define CRYPTO_F_OPENSSL_LH_NEW                          0
#  define CRYPTO_F_OPENSSL_SK_DEEP_COPY                    0
#  define CRYPTO_F_OPENSSL_SK_DUP                          0
#  define CRYPTO_F_OSSL_PARAM_BLD_PUSH_BN                  0
#  define CRYPTO_F_OSSL_PARAM_BLD_PUSH_OCTET_PTR           0
#  define CRYPTO_F_OSSL_PARAM_BLD_PUSH_OCTET_STRING        0
#  define CRYPTO_F_OSSL_PARAM_BLD_PUSH_UTF8_PTR            0
#  define CRYPTO_F_OSSL_PARAM_BLD_PUSH_UTF8_STRING         0
#  define CRYPTO_F_OSSL_PARAM_BLD_TO_PARAM                 0
#  define CRYPTO_F_OSSL_PARAM_BLD_TO_PARAM_EX              0
#  define CRYPTO_F_OSSL_PARAM_TYPE_TO_PARAM                0
#  define CRYPTO_F_OSSL_PROVIDER_ACTIVATE                  0
#  define CRYPTO_F_OSSL_PROVIDER_ADD_BUILTIN               0
#  define CRYPTO_F_OSSL_PROVIDER_ADD_PARAMETER             0
#  define CRYPTO_F_OSSL_PROVIDER_NEW                       0
#  define CRYPTO_F_OSSL_PROVIDER_SET_MODULE_PATH           0
#  define CRYPTO_F_PARAM_PUSH                              0
#  define CRYPTO_F_PARAM_PUSH_NUM                          0
#  define CRYPTO_F_PKEY_HMAC_INIT                          0
#  define CRYPTO_F_PKEY_POLY1305_INIT                      0
#  define CRYPTO_F_PKEY_SIPHASH_INIT                       0
#  define CRYPTO_F_PROVIDER_ACTIVATE                       0
#  define CRYPTO_F_PROVIDER_CONF_INIT                      0
#  define CRYPTO_F_PROVIDER_CONF_LOAD                      0
#  define CRYPTO_F_PROVIDER_NEW                            0
#  define CRYPTO_F_PROVIDER_STORE_NEW                      0
#  define CRYPTO_F_SK_RESERVE                              0
# endif

/*
 * CRYPTO reason codes.
 */
# define CRYPTO_R_BAD_ALGORITHM_NAME                      117
# define CRYPTO_R_CONFLICTING_NAMES                       118
# define CRYPTO_R_FIPS_MODE_NOT_SUPPORTED                 101
# define CRYPTO_R_ILLEGAL_HEX_DIGIT                       102
# define CRYPTO_R_INSUFFICIENT_DATA_SPACE                 106
# define CRYPTO_R_INSUFFICIENT_PARAM_SIZE                 107
# define CRYPTO_R_INSUFFICIENT_SECURE_DATA_SPACE          108
# define CRYPTO_R_INVALID_NULL_ARGUMENT                   109
# define CRYPTO_R_INVALID_OSSL_PARAM_TYPE                 110
# define CRYPTO_R_ODD_NUMBER_OF_DIGITS                    103
# define CRYPTO_R_PROVIDER_ALREADY_EXISTS                 104
# define CRYPTO_R_PROVIDER_SECTION_ERROR                  105
# define CRYPTO_R_SECURE_MALLOC_FAILURE                   111
# define CRYPTO_R_STRING_TOO_LONG                         112
# define CRYPTO_R_TOO_MANY_BYTES                          113
# define CRYPTO_R_TOO_MANY_RECORDS                        114
# define CRYPTO_R_TOO_SMALL_BUFFER                        116
# define CRYPTO_R_ZERO_LENGTH_NUMBER                      115

#endif
