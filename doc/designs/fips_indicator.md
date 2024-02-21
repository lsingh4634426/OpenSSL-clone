OpenSSL FIPS Indicators
=======================

References
----------

- [1] FIPS 140-3 Standards: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards>
- [2] Approved Security Functions: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information/sp800-140c>
- [3] Approved SSP generation and Establishment methods: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information/sp800-140d>
- [4] Key transitions: <https://csrc.nist.gov/pubs/sp/800/131/a/r2/final>
- [5] FIPS 140-3 Implementation Guidance: <https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips 140-3/FIPS 140-3 IG.pdf>

Requirements
------------

The following information was extracted from the FIPS 140-3 IG [5] “2.4.C Approved Security Service Indicator”

- A module must have an approved mode of operation that requires at least one service to use an approved security function (defined by [2] and [3]).
- A FIPS 140-3 compliant module requires a built-in service indicator capable of indicating the use of approved security services
- If a module only supports approved services in an approved manner an implicit indicator can be used (e.g. successful completion of a service is an indicator).
- An approved algorithm is not considered to be an approved implementation if it does not have a CAVP certificate or does not include its required self-tests. (i.e. My interpretation of this is that if the CAVP certificate lists an algorithm with only a subset of key sizes, digests, and/or ciphers compared to the implementation, the differences ARE NOT APPROVED. In many places we have no restrictions on the digest or cipher selected).
- Documentation is required to demonstrate how to use indicators for each approved cryptographic algorithm.
- Testing is required to execute all services and verify that the indicator provides an unambiguous indication of whether the service utilizes an approved cryptographic algorithm, security function or process in an approved manner or not.
- The Security Policy may require updates related to indicators. AWS/google have added a table in their security policy called ‘Non-Approved Algorithms not allowed in the approved mode of operation’. An example is RSA with a keysize of < 2048 bits (which has been enforced by [4]).

Legacy Support
--------------

Due to key transitions [4] we may have some legacy algorithms that are in a state of only being approved for processing (verification, decryption, validation), and not for protection (signing, encrypting, keygen).
For example DSA.

The options are:

- Completely remove the algorithm from the FIPS provider. This is simple but means older applications can no longer process existing data, which is not ideal.
- Allow the algorithm but make it not approved with an context specific indicator.

It is safer to make the protection operations fail rather than use an indicator.
The processing operation for DSA would set the indicator to approved.

Security Checks
---------------

OpenSSL currently defines configurable FIPS options.
These options are supplied via the FIPS configuration file - which is normally setup via fipsinstall.

- FIPS_FEATURE_CHECK(FIPS_security_check_enabled, fips_security_checks, 1)
- FIPS_FEATURE_CHECK(FIPS_tls_prf_ems_check, fips_tls1_prf_ems_check, 0)
- FIPS_FEATURE_CHECK(FIPS_restricted_drbg_digests_enabled, 0)
- OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS selftest_params.conditional_error_check

The following functions are available in providers/common/security_check.c.

- ossl_rsa_check_key()
- ossl_ec_check_key()
- ossl_dsa_check_key()
- ossl_dh_check_key()
- ossl_digest_get_approved_nid_with_sha1()
- ossl_digest_is_allowed()

Anywhere where these functions are called an indicator MAY be required.
Because these options are available I do not think it is sufficient to
document this in the security policy.

Each of these functions contains code of the following form:

``` c
#if !defined(OPENSSL_NO_FIPS_SECURITYCHECKS)
    if (ossl_securitycheck_enabled(ctx)) {
      // Do some checks, and maybe return 0 for a hard failure
      ...
    }
}
```

OPENSSL_NO_FIPS_SECURITYCHECKS is also a configurable option
If the security checks are not enabled then it is unapproved?

Implementation options
----------------------

The above requirements indicate 2 options.

### Option 1

Dont allow ANY non approved algorithms and then a indicator is not required.

- Pros: Simple
- Cons: Problematic since we already have configurable options that are used for security checks etc.
- Cons: We would need to return errors anywhere where an algorithm is not approved, which would cause compatibility issues

### Preferred Option

Add an indicator everywhere that it is required.

- Pros: Flexible solution
- Cons: Requires a lot more effort to add the indicator to all the required places.

Note that in order for a service to be ‘fips approved’ the following requirements would need to be met.

- Any algorithms come from FIPS provider.
- A service is a series of one or more API calls that must all succeed
- A extra API call is needed after the service succeeds, that should return 1 if the service is FIPS approved.

Solutions for the preferred Option
----------------------------------

### Solution 1 (Using an indicator everywhere)

Use a per thread global counter that is incremented when an algorithm is approved.  AWS/google have added this in places where a service is at the point of completing its output (e.g. digest_final). This design is complicated by the fact that a service may call another service (e.g HMAC using SHA256) that also wants to increment the approved counter. To get around this issue they have a second variable that is used for nesting. If the variable is non zero then the approved counter doesnt increment. This also allows non security relevant functions to not increment the approved count. Another variation of this would be to use flags instead of a counter.

- Cons: At the fips provider level this would require some plumbing to go from the core to the fips provider, which seems overly complex.
- Cons: The query can only be done after the output is set.
- Cons: The indicator code would end up having to be set in different places depending on the algorithm after the output is finalized. This would be fairly messy as the point where it is called is set could be different for different algorithms.
- Cons: The locking increment seems messy.

### Proposed Solution (Using an indicator everywhere)

Add a OSSL_PARAM getter to each provider algorithm context.
By default if the getter is not handled then it would return not approved.

- Pros: The code is easier to find since it is part of the get_ctx_params function.
- Pros: The getter can be called at any point after the setting is done.

Any fips algorithm that is approved would then need a setter that at a minimum contains code similar to the following

``` C
int ossl_xxx_fips_approved(void)
{
ifdef FIPS_MODULE
    return 1; // conditional code would go here for each algorithm if required *
else
    return 0;
endif
}
```

and in the algorithms get_ctx() function

``` C
int xxx_get_fips_approved(OSSL_PARAM params[])
{
    p = OSSL_PARAM_locate(params, OSSL_FIPS_PARAM_APPROVED);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_xxx_fips_approved()))
        return 0;
    return 1;
}
```

### API’s that would be used to support this are

- EVP_PKEY Keygen, Encryption, Signatures, Key Exchange, KEM

``` C
EVP_PKEY_CTX_get_params(ctx, );
```

(Note that this would mean you could not use functions that hide the ctx such as EVP_PKEY_Q_keygen()!)

- Ciphers

``` C
EVP_CIPHER_CTX_get_params()
```

- Digests

``` C
EVP_MD_CTX_get_params()
```

- KDF’s

``` C
EVP_KDF_CTX_get_params()
```

- MAC’s

``` C
EVP_MAC_CTX_get_params()
```

- RAND

``` C
EVP_RAND_CTX_get_params()
```

### Backwards Compatibility

Previous providers do not support this operation, so they will return not approved if they are not handled.

### Alternate Solution

If we had different kinds of compliance requirements (something other than FIPS) either a separate getter could be added or the getter could return a int type instead of a 0 or 1..
(e.g 1 = fips approved, 2 = some other compliance approved)

Changes Required for indicators
-------------------------------

### key size >= 112 bits

There are a few places where we do not enforce key size that need to be addressed.

- HMAC  Which applies to all algorithms that use HMAC also (e.g. HKDF, SSKDF, KBKDF)
- CMAC
- KMAC

### Algorithm Transitions

Should we remove these algorithms completely from the fips provider, or use indicators?

- DES_EDE3_ECB.  Disallowed for encryption, allowed for legacy decryption
- DSA.  Keygen and Signing are no longer approved, not sure if verify is still approved.
- ECDSA B & K curves are deprecated, but still approved according to (IG C.K Resolution 4). Should we remove these? If not we need to check that OSSL_PKEY_PARAM_USE_COFACTOR_ECDH is set for key agreement if the cofactor is not 1.
- ED25519/ED448 is now approved.
- X25519/X448 is not approved currently. keygen and keyexchange would also need an indicator if we allow it?
- RSA encryption(transport) using PKCSV15 is no longer allowed. (Note that this break TLS 1.2 using RSA for KeyAgreement),  Padding mode updates required. Check RSA KEM also.
- RSA signing using X931 is no longer allowed. (Still allowed for verification). Check if PSS saltlen needs a indicator (Note FIPS 186-4 Section 5.5 bullet(e). Padding mode updates required in rsa_check_padding(). Check if sha1 is allowed?
- RSA - (From SP800-131Ar2) RSA >= 2048 is approved for keygen, signatures and key transport. Verification allows 1024 also. Note also that according to the (IG section C.F) that fips 186-2 verification is also allowed (So this may need either testing OR an indicator). Check that rsa_keygen_pairwise_test() and RSA self tests are all compliant with the above RSA restrictions.

- TLS1_PRF  If we are only trying to support TLS1.2 here then we should remove the tls1.0/1.1 code from the FIPS MODULE.

### Digest Checks

Any algorithms that use a digest need to make sure that the CAVP certificate lists all supported FIPS digests otherwise an indicator is required.
This applies to the following algorithms:

- SSKDF
- TLS_1_3_KDF (Only SHA256 and SHA384 Are allowed due to RFC 8446  Appendix B.4)
- SSHKDF
- X963KDF
- X942KDF
- PBKDF2
- HKDF
- TLS1_PRF
- HMAC
- KBKDF
- KMAC

Note this includes SHAKE
KECCAK-KMAC-128 and KECCAK-KMAC-256 should not be allowed for anything other than KMAC.
Do we need to check which algorithms allow SHA1 also?

### Cipher Checks

- CMAC
- KBKDF CMAC
- GMAC

We should only allow AES. We currently just check the mode.

### Configurable options

- PBKDF2 'lower_bound_checks' needs to be part of the indicator check
- See the "security checks" Section. Anywhere using ossl_securitycheck_enabled() may need an indicator

Other Changes
-------------

- AES-GCM Security Policy must list AES GCM IV generation scenarios
- TEST_RAND is not approved.
- SSKDF  The security  policy needs to be specific about what it supports i.e. hash, kmac 128/256, hmac-hash. There are also currently no limitations on the digest for hash and hmac
- KBKDF  Security policy should list KMAC-128, KMAC-256 otherwise an indicator is required.
- KMAC may need a lower bound check on the output size (SP800-185 Section 8.4.2)
