/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * NB: these functions have been "upgraded", the deprecated versions (which
 * are compatibility wrappers using these functions) are in rsa_depr.c. -
 * Geoff
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/self_test.h>
#include "prov/providercommon.h"
#include "rsa_local.h"

static int rsa_keygen_pairwise_test(RSA *rsa, OSSL_CALLBACK *cb, void *cbarg);
static int rsa_keygen(OSSL_LIB_CTX *libctx, RSA *rsa, int bits, int primes,
                      BIGNUM *e_value, BN_GENCB *cb, int pairwise_test);

/*
 * NB: this wrapper would normally be placed in rsa_lib.c and the static
 * implementation would probably be in rsa_eay.c. Nonetheless, is kept here
 * so that we don't introduce a new linker dependency. Eg. any application
 * that wasn't previously linking object code related to key-generation won't
 * have to now just because key-generation is part of RSA_METHOD.
 */
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)
{
    if (rsa->meth->rsa_keygen != NULL)
        return rsa->meth->rsa_keygen(rsa, bits, e_value, cb);

    return RSA_generate_multi_prime_key(rsa, bits, RSA_DEFAULT_PRIME_NUM,
                                        e_value, cb);
}

int RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes,
                                 BIGNUM *e_value, BN_GENCB *cb)
{
#ifndef FIPS_MODULE
    /* multi-prime is only supported with the builtin key generation */
    if (rsa->meth->rsa_multi_prime_keygen != NULL) {
        return rsa->meth->rsa_multi_prime_keygen(rsa, bits, primes,
                                                 e_value, cb);
    } else if (rsa->meth->rsa_keygen != NULL) {
        /*
         * However, if rsa->meth implements only rsa_keygen, then we
         * have to honour it in 2-prime case and assume that it wouldn't
         * know what to do with multi-prime key generated by builtin
         * subroutine...
         */
        if (primes == 2)
            return rsa->meth->rsa_keygen(rsa, bits, e_value, cb);
        else
            return 0;
    }
#endif /* FIPS_MODULE */
    return rsa_keygen(rsa->libctx, rsa, bits, primes, e_value, cb, 0);
}

DEFINE_STACK_OF(BIGNUM)

/*
 * Given input values, q, p, n, d and e, derive the exponents
 * and coefficients for each prime in this key, placing the result
 * on their respective exps and coeffs stacks
 */
#ifndef FIPS_MODULE
int ossl_rsa_multiprime_derive(RSA *rsa, int bits, int primes,
                               BIGNUM *e_value,
                               STACK_OF(BIGNUM) *factors,
                               STACK_OF(BIGNUM) *exps,
                               STACK_OF(BIGNUM) *coeffs)
{
    STACK_OF(BIGNUM) *pplist = NULL, *pdlist = NULL;
    BIGNUM *factor = NULL, *newpp = NULL, *newpd = NULL;
    BIGNUM *dval = NULL, *newexp = NULL, *newcoeff = NULL;
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BIGNUM *r0 = NULL, *r1 = NULL, *r2 = NULL;
    BN_CTX *ctx = NULL;
    int i;
    int ret = 0;

    ctx = BN_CTX_new_ex(rsa->libctx);
    if (ctx == NULL)
        goto err;

    BN_CTX_start(ctx);

    pplist = sk_BIGNUM_new_null();
    if (pplist == NULL)
        goto err;

    pdlist = sk_BIGNUM_new_null();
    if (pdlist == NULL)
        goto err;

    r0 = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);

    if (r2 == NULL)
        goto err;

    BN_set_flags(r0, BN_FLG_CONSTTIME);
    BN_set_flags(r1, BN_FLG_CONSTTIME);
    BN_set_flags(r2, BN_FLG_CONSTTIME);

    if (BN_copy(r1, rsa->n) == NULL)
        goto err;

    p = sk_BIGNUM_value(factors, 0);
    q = sk_BIGNUM_value(factors, 1);

    /* Build list of partial products of primes */
    for (i = 0; i < sk_BIGNUM_num(factors); i++) {
        switch (i) {
        case 0:
            /* our first prime, p */
            if (!BN_sub(r2, p, BN_value_one()))
                goto err;
            BN_set_flags(r2, BN_FLG_CONSTTIME);
            if (!BN_mod_inverse(r1, r2, rsa->e, ctx))
                goto err;
            break;
        case 1:
            /* second prime q */
            if (!BN_mul(r1, p, q, ctx))
                goto err;
            sk_BIGNUM_insert(pplist, BN_dup(r1), sk_BIGNUM_num(pplist));
            break;
        default:
            factor = sk_BIGNUM_value(factors, i);
            /* all other primes */
            if (!BN_mul(r1, r1, factor, ctx))
                goto err;
            sk_BIGNUM_insert(pplist, BN_dup(r1), sk_BIGNUM_num(pplist));
            break;
        }
    }

    /* build list of relative d values */
    /* p -1 */
    if (!BN_sub(r1, p, BN_value_one()))
        goto err;
    if (!BN_sub(r2, q, BN_value_one()))
        goto err;
    if (!BN_mul(r0, r1, r2, ctx))
        goto err;
    for (i = 2; i < sk_BIGNUM_num(factors); i++) {
        factor = sk_BIGNUM_value(factors, i);
        dval = BN_new();
        if (!dval)
            goto err;
        BN_set_flags(dval, BN_FLG_CONSTTIME);
        if (!BN_sub(dval, factor, BN_value_one()))
            goto err;
        if (!BN_mul(r0, r0, dval, ctx))
            goto err;
        sk_BIGNUM_insert(pdlist, dval, sk_BIGNUM_num(pdlist));
    }

    /* Calculate dmp1, dmq1 and additional exponents */
    dmp1 = BN_secure_new();
    if (dmp1 == NULL)
        goto err;
    dmq1 = BN_secure_new();
    if (dmq1 == NULL)
        goto err;

    if (!BN_mod(dmp1, rsa->d, r1, ctx))
        goto err;
    sk_BIGNUM_insert(exps, dmp1, sk_BIGNUM_num(exps));
    dmp1 = NULL;

    if (!BN_mod(dmq1, rsa->d, r2, ctx))
        goto err;
    sk_BIGNUM_insert(exps, dmq1, sk_BIGNUM_num(exps));
    dmq1 = NULL;

    for (i = 2; i < sk_BIGNUM_num(factors); i++) {
        newpd = sk_BIGNUM_value(pdlist, i - 2);
        newexp = BN_new();
        if (!newexp)
            goto err;
        if (!BN_mod(newexp, rsa->d, newpd, ctx)) {
            BN_free(newexp);
            goto err;
        }
        sk_BIGNUM_insert(exps, newexp, sk_BIGNUM_num(exps));
    }

    /* Calculate iqmp and additional coefficients */
    iqmp = BN_new();
    if (iqmp == NULL)
        goto err;

    if (!BN_mod_inverse(iqmp, sk_BIGNUM_value(factors, 1),
                        sk_BIGNUM_value(factors, 0), ctx))
        goto err;
    sk_BIGNUM_insert(coeffs, iqmp, sk_BIGNUM_num(coeffs));
    iqmp = NULL;

    for (i = 2; i < sk_BIGNUM_num(factors); i++) {
        newpp = sk_BIGNUM_value(pplist, i - 2);
        newcoeff = BN_new();
        if (newcoeff == NULL)
            goto err;
        if (!BN_mod_inverse(newcoeff, newpp, sk_BIGNUM_value(factors, i),
                            ctx)) {
            BN_free(newcoeff);
            goto err;
        }
        sk_BIGNUM_insert(coeffs, newcoeff, sk_BIGNUM_num(coeffs));
    }

    ret = 1;
 err:
    sk_BIGNUM_pop_free(pplist, BN_free);
    sk_BIGNUM_pop_free(pdlist, BN_free);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(dmp1);
    BN_clear_free(dmq1);
    BN_clear_free(iqmp);
    return ret;
}

static int rsa_multiprime_keygen(RSA *rsa, int bits, int primes,
                                 BIGNUM *e_value, BN_GENCB *cb)
{
    BIGNUM *r0 = NULL, *r1 = NULL, *r2 = NULL, *tmp, *tmp2, *prime;
    int n = 0, bitsr[RSA_MAX_PRIME_NUM], bitse = 0;
    int i = 0, quo = 0, rmd = 0, adj = 0, retries = 0;
    RSA_PRIME_INFO *pinfo = NULL;
    STACK_OF(RSA_PRIME_INFO) *prime_infos = NULL;
    STACK_OF(BIGNUM) *factors = NULL;
    STACK_OF(BIGNUM) *exps = NULL;
    STACK_OF(BIGNUM) *coeffs = NULL;
    BN_CTX *ctx = NULL;
    BN_ULONG bitst = 0;
    unsigned long error = 0;
    int ok = -1;

    if (bits < RSA_MIN_MODULUS_BITS) {
        ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        return 0;
    }
    if (e_value == NULL) {
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_E_VALUE);
        return 0;
    }
    /* A bad value for e can cause infinite loops */
    if (!ossl_rsa_check_public_exponent(e_value)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_PUB_EXPONENT_OUT_OF_RANGE);
        return 0;
    }

    if (primes < RSA_DEFAULT_PRIME_NUM || primes > ossl_rsa_multip_cap(bits)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_KEY_PRIME_NUM_INVALID);
        return 0;
    }

    factors = sk_BIGNUM_new_null();
    if (factors == NULL)
        return 0;

    exps = sk_BIGNUM_new_null();
    if (exps == NULL)
        goto err;

    coeffs = sk_BIGNUM_new_null();
    if (coeffs == NULL)
        goto err;

    ctx = BN_CTX_new_ex(rsa->libctx);
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    r0 = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    if (r2 == NULL)
        goto err;

    /* divide bits into 'primes' pieces evenly */
    quo = bits / primes;
    rmd = bits % primes;

    for (i = 0; i < primes; i++)
        bitsr[i] = (i < rmd) ? quo + 1 : quo;

    rsa->dirty_cnt++;

    /* We need the RSA components non-NULL */
    if (!rsa->n && ((rsa->n = BN_new()) == NULL))
        goto err;
    if (!rsa->d && ((rsa->d = BN_secure_new()) == NULL))
        goto err;
    BN_set_flags(rsa->d, BN_FLG_CONSTTIME);
    if (!rsa->e && ((rsa->e = BN_new()) == NULL))
        goto err;
    if (!rsa->p && ((rsa->p = BN_secure_new()) == NULL))
        goto err;
    BN_set_flags(rsa->p, BN_FLG_CONSTTIME);
    if (!rsa->q && ((rsa->q = BN_secure_new()) == NULL))
        goto err;
    BN_set_flags(rsa->q, BN_FLG_CONSTTIME);

    /* initialize multi-prime components */
    if (primes > RSA_DEFAULT_PRIME_NUM) {
        rsa->version = RSA_ASN1_VERSION_MULTI;
        prime_infos = sk_RSA_PRIME_INFO_new_reserve(NULL, primes - 2);
        if (prime_infos == NULL)
            goto err;
        if (rsa->prime_infos != NULL) {
            /* could this happen? */
            sk_RSA_PRIME_INFO_pop_free(rsa->prime_infos,
                                       ossl_rsa_multip_info_free);
        }
        rsa->prime_infos = prime_infos;

        /* prime_info from 2 to |primes| -1 */
        for (i = 2; i < primes; i++) {
            pinfo = ossl_rsa_multip_info_new();
            if (pinfo == NULL)
                goto err;
            (void)sk_RSA_PRIME_INFO_push(prime_infos, pinfo);
        }
    }

    if (BN_copy(rsa->e, e_value) == NULL)
        goto err;

    /* generate p, q and other primes (if any) */
    for (i = 0; i < primes; i++) {
        adj = 0;
        retries = 0;

        if (i == 0) {
            prime = rsa->p;
        } else if (i == 1) {
            prime = rsa->q;
        } else {
            pinfo = sk_RSA_PRIME_INFO_value(prime_infos, i - 2);
            prime = pinfo->r;
        }
        BN_set_flags(prime, BN_FLG_CONSTTIME);

        for (;;) {
 redo:
            if (!BN_generate_prime_ex2(prime, bitsr[i] + adj, 0, NULL, NULL,
                                       cb, ctx))
                goto err;
            /*
             * prime should not be equal to p, q, r_3...
             * (those primes prior to this one)
             */
            {
                int j;

                for (j = 0; j < i; j++) {
                    BIGNUM *prev_prime;

                    if (j == 0)
                        prev_prime = rsa->p;
                    else if (j == 1)
                        prev_prime = rsa->q;
                    else
                        prev_prime = sk_RSA_PRIME_INFO_value(prime_infos,
                                                             j - 2)->r;

                    if (!BN_cmp(prime, prev_prime)) {
                        goto redo;
                    }
                }
            }
            if (!BN_sub(r2, prime, BN_value_one()))
                goto err;
            ERR_set_mark();
            BN_set_flags(r2, BN_FLG_CONSTTIME);
            if (BN_mod_inverse(r1, r2, rsa->e, ctx) != NULL) {
                /* GCD == 1 since inverse exists */
                break;
            }
            error = ERR_peek_last_error();
            if (ERR_GET_LIB(error) == ERR_LIB_BN
                && ERR_GET_REASON(error) == BN_R_NO_INVERSE) {
                /* GCD != 1 */
                ERR_pop_to_mark();
            } else {
                goto err;
            }
            if (!BN_GENCB_call(cb, 2, n++))
                goto err;
        }

        bitse += bitsr[i];

        /* calculate n immediately to see if it's sufficient */
        if (i == 1) {
            /* we get at least 2 primes */
            if (!BN_mul(r1, rsa->p, rsa->q, ctx))
                goto err;
        } else if (i != 0) {
            /* modulus n = p * q * r_3 * r_4 ... */
            if (!BN_mul(r1, rsa->n, prime, ctx))
                goto err;
        } else {
            /* i == 0, do nothing */
            if (!BN_GENCB_call(cb, 3, i))
                goto err;
            tmp = BN_dup(prime);
            if (tmp == NULL)
                goto err;
            sk_BIGNUM_insert(factors, tmp, sk_BIGNUM_num(factors));
            continue;
        }

        /*
         * if |r1|, product of factors so far, is not as long as expected
         * (by checking the first 4 bits are less than 0x9 or greater than
         * 0xF). If so, re-generate the last prime.
         *
         * NOTE: This actually can't happen in two-prime case, because of
         * the way factors are generated.
         *
         * Besides, another consideration is, for multi-prime case, even the
         * length modulus is as long as expected, the modulus could start at
         * 0x8, which could be utilized to distinguish a multi-prime private
         * key by using the modulus in a certificate. This is also covered
         * by checking the length should not be less than 0x9.
         */
        if (!BN_rshift(r2, r1, bitse - 4))
            goto err;
        bitst = BN_get_word(r2);

        if (bitst < 0x9 || bitst > 0xF) {
            /*
             * For keys with more than 4 primes, we attempt longer factor to
             * meet length requirement.
             *
             * Otherwise, we just re-generate the prime with the same length.
             *
             * This strategy has the following goals:
             *
             * 1. 1024-bit factors are efficient when using 3072 and 4096-bit key
             * 2. stay the same logic with normal 2-prime key
             */
            bitse -= bitsr[i];
            if (!BN_GENCB_call(cb, 2, n++))
                goto err;
            if (primes > 4) {
                if (bitst < 0x9)
                    adj++;
                else
                    adj--;
            } else if (retries == 4) {
                /*
                 * re-generate all primes from scratch, mainly used
                 * in 4 prime case to avoid long loop. Max retry times
                 * is set to 4.
                 */
                i = -1;
                bitse = 0;
                sk_BIGNUM_pop_free(factors, BN_clear_free);
                factors = sk_BIGNUM_new_null();
                if (factors == NULL)
                    goto err;
                continue;
            }
            retries++;
            goto redo;
        }
        /* save product of primes for further use, for multi-prime only */
        if (i > 1 && BN_copy(pinfo->pp, rsa->n) == NULL)
            goto err;
        if (BN_copy(rsa->n, r1) == NULL)
            goto err;
        if (!BN_GENCB_call(cb, 3, i))
            goto err;
        tmp = BN_dup(prime);
        if (tmp == NULL)
            goto err;
        sk_BIGNUM_insert(factors, tmp, sk_BIGNUM_num(factors));
    }

    if (BN_cmp(rsa->p, rsa->q) < 0) {
        tmp = rsa->p;
        rsa->p = rsa->q;
        rsa->q = tmp;
        /* mirror this in our factor stack */
        sk_BIGNUM_insert(factors, sk_BIGNUM_delete(factors, 0), 1);
    }

    /* calculate d */

    /* p - 1 */
    if (!BN_sub(r1, rsa->p, BN_value_one()))
        goto err;
    /* q - 1 */
    if (!BN_sub(r2, rsa->q, BN_value_one()))
        goto err;
    /* (p - 1)(q - 1) */
    if (!BN_mul(r0, r1, r2, ctx))
        goto err;
    /* multi-prime */
    for (i = 2; i < primes; i++) {
        pinfo = sk_RSA_PRIME_INFO_value(prime_infos, i - 2);
        /* save r_i - 1 to pinfo->d temporarily */
        if (!BN_sub(pinfo->d, pinfo->r, BN_value_one()))
            goto err;
        if (!BN_mul(r0, r0, pinfo->d, ctx))
            goto err;
    }


    BN_set_flags(r0, BN_FLG_CONSTTIME);
    if (!BN_mod_inverse(rsa->d, rsa->e, r0, ctx)) {
        goto err;               /* d */
    }

    /* derive any missing exponents and coefficients */
    if (!ossl_rsa_multiprime_derive(rsa, bits, primes, e_value,
                                    factors, exps, coeffs))
        goto err;

    /*
     * first 2 factors/exps are already tracked in p/q/dmq1/dmp1
     * and the first coeff is in iqmp, so pop those off the stack
     * Note, the first 2 factors/exponents are already tracked by p and q
     * assign dmp1/dmq1 and iqmp
     * the remaining pinfo values are separately allocated, so copy and delete 
     * those
     */
    BN_clear_free(sk_BIGNUM_delete(factors, 0));
    BN_clear_free(sk_BIGNUM_delete(factors, 0));
    rsa->dmp1 = sk_BIGNUM_delete(exps, 0);
    rsa->dmq1 = sk_BIGNUM_delete(exps, 0);
    rsa->iqmp = sk_BIGNUM_delete(coeffs, 0);
    for (i = 2; i < primes; i++) {
        pinfo = sk_RSA_PRIME_INFO_value(prime_infos, i - 2);
        tmp = sk_BIGNUM_delete(factors, 0);
        BN_copy(pinfo->r, tmp);
        BN_clear_free(tmp);
        tmp = sk_BIGNUM_delete(exps, 0);
        tmp2 = BN_copy(pinfo->d, tmp);
        BN_clear_free(tmp);
        if (tmp2 == NULL)
            goto err;
        tmp = sk_BIGNUM_delete(coeffs, 0);
        tmp2 = BN_copy(pinfo->t, tmp);
        BN_clear_free(tmp);
        if (tmp2 == NULL)
            goto err;
    }
    ok = 1;
 err:
    sk_BIGNUM_free(factors);
    sk_BIGNUM_free(exps);
    sk_BIGNUM_free(coeffs);
    if (ok == -1) {
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        ok = 0;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}
#endif /* FIPS_MODULE */

static int rsa_keygen(OSSL_LIB_CTX *libctx, RSA *rsa, int bits, int primes,
                      BIGNUM *e_value, BN_GENCB *cb, int pairwise_test)
{
    int ok = 0;

#ifdef FIPS_MODULE
    ok = ossl_rsa_sp800_56b_generate_key(rsa, bits, e_value, cb);
    pairwise_test = 1; /* FIPS MODE needs to always run the pairwise test */
#else
    /*
     * Only multi-prime keys or insecure keys with a small key length or a
     * public exponent <= 2^16 will use the older rsa_multiprime_keygen().
     */
    if (primes == 2
            && bits >= 2048
            && (e_value == NULL || BN_num_bits(e_value) > 16))
        ok = ossl_rsa_sp800_56b_generate_key(rsa, bits, e_value, cb);
    else
        ok = rsa_multiprime_keygen(rsa, bits, primes, e_value, cb);
#endif /* FIPS_MODULE */

    if (pairwise_test && ok > 0) {
        OSSL_CALLBACK *stcb = NULL;
        void *stcbarg = NULL;

        OSSL_SELF_TEST_get_callback(libctx, &stcb, &stcbarg);
        ok = rsa_keygen_pairwise_test(rsa, stcb, stcbarg);
        if (!ok) {
            ossl_set_error_state(OSSL_SELF_TEST_TYPE_PCT);
            /* Clear intermediate results */
            BN_clear_free(rsa->d);
            BN_clear_free(rsa->p);
            BN_clear_free(rsa->q);
            BN_clear_free(rsa->dmp1);
            BN_clear_free(rsa->dmq1);
            BN_clear_free(rsa->iqmp);
            rsa->d = NULL;
            rsa->p = NULL;
            rsa->q = NULL;
            rsa->dmp1 = NULL;
            rsa->dmq1 = NULL;
            rsa->iqmp = NULL;
        }
    }
    return ok;
}

/*
 * For RSA key generation it is not known whether the key pair will be used
 * for key transport or signatures. FIPS 140-2 IG 9.9 states that in this case
 * either a signature verification OR an encryption operation may be used to
 * perform the pairwise consistency check. The simpler encrypt/decrypt operation
 * has been chosen for this case.
 */
static int rsa_keygen_pairwise_test(RSA *rsa, OSSL_CALLBACK *cb, void *cbarg)
{
    int ret = 0;
    unsigned int ciphertxt_len;
    unsigned char *ciphertxt = NULL;
    const unsigned char plaintxt[16] = {0};
    unsigned char *decoded = NULL;
    unsigned int decoded_len;
    unsigned int plaintxt_len = (unsigned int)sizeof(plaintxt_len);
    int padding = RSA_PKCS1_PADDING;
    OSSL_SELF_TEST *st = NULL;

    st = OSSL_SELF_TEST_new(cb, cbarg);
    if (st == NULL)
        goto err;
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_PCT,
                           OSSL_SELF_TEST_DESC_PCT_RSA_PKCS1);

    ciphertxt_len = RSA_size(rsa);
    /*
     * RSA_private_encrypt() and RSA_private_decrypt() requires the 'to'
     * parameter to be a maximum of RSA_size() - allocate space for both.
     */
    ciphertxt = OPENSSL_zalloc(ciphertxt_len * 2);
    if (ciphertxt == NULL)
        goto err;
    decoded = ciphertxt + ciphertxt_len;

    ciphertxt_len = RSA_public_encrypt(plaintxt_len, plaintxt, ciphertxt, rsa,
                                       padding);
    if (ciphertxt_len <= 0)
        goto err;
    if (ciphertxt_len == plaintxt_len
        && memcmp(ciphertxt, plaintxt, plaintxt_len) == 0)
        goto err;

    OSSL_SELF_TEST_oncorrupt_byte(st, ciphertxt);

    decoded_len = RSA_private_decrypt(ciphertxt_len, ciphertxt, decoded, rsa,
                                      padding);
    if (decoded_len != plaintxt_len
        || memcmp(decoded, plaintxt,  decoded_len) != 0)
        goto err;

    ret = 1;
err:
    OSSL_SELF_TEST_onend(st, ret);
    OSSL_SELF_TEST_free(st);
    OPENSSL_free(ciphertxt);

    return ret;
}
