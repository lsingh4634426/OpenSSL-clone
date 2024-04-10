OpenSSL FIPS Indicators
=======================

The following document refers to behaviour required by the OpenSSL FIPS provider,
the changes should not affect the default provider.

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

Solution
--------

We already have most of the existing code in the FIPS provider using
implicit indicators i.e. An error occurs if existing FIPS rules are violated.

The following rules will apply to any code that currently is not FIPS approved,
but needs to be.

- There will be a 'fips approved' mode per provider operation context that is on by default.
- In this mode any FIPS rule that is violated will result in an error.
- The 'fips approved' mode may be turned off per context via a OSSL_PARAM setter, if it
is turned off then the operation is not FIPS approved.
- A getter is required that returns if the operation is 'fips approved' using an
OSSL_PARAM. The returned value can be a combination of the set 'fips_approved' mode
plus any other logic. This is an explicit indicator.
- Any algorithm that is transitioning [4] to not being allowed should be removed from
the fips provider.
- If an algorithm is transitioning [4] to be only allowed for processing
(e.g. verification, signing, key validation) then the protection code
(keygen, signing, encryption) should be removed from the fips provider, any
attempt to use the protection API's should result in an error. The processing
code should still be functional.

Other rules:
The existing flags that we set in the fips config file to control security checks
will continue to function as they do now, and will not be affected by the
strict mode variable.
The getter to determine if we are fips approved will however take the flags
into account.

Motivation
----------

The nature of FIPS is that new rules are introduced that will break older code,
and this should be expected.
We have a FIPS provider to enforce FIPS rules, if you need NON FIPS approved
algorithms they should be coming from the default provider. 

Implicit indicators are being chosen as they are simple to understand and are
the most useful way of enforcing FIPS restrictions. In cases where FIPS cannot
be used, the setter will still provide a way to override the behaviour, but the
user must deliberately chose to do this.

A system that relies on explicit indicators to test after the operation as to
whether a operation is approved or NOT is subject to misuse. Although this may
provide an 'easier' path for backwards compatibility, this is not the intention
of a FIPS module.

There was discussion related to also having a global config setting that could
turn off FIPS mode. If we get to this point we should be using the default provider.
It would also be confusing having the existing fips configuration flags combined
with a global setting.

New Changes Required
--------------------

### key size >= 112 bits

There are a few places where we do not enforce key size that need to be addressed.

- HMAC  Which applies to all algorithms that use HMAC also (e.g. HKDF, SSKDF, KBKDF)
- CMAC
- KMAC

### Algorithm Transitions

- DES_EDE3_ECB.  Disallowed for encryption, allowed for legacy decryption
- DSA.  Keygen and Signing are no longer approved, verify is still allowed.
- ECDSA B & K curves are deprecated, but still approved according to (IG C.K Resolution 4).\
  If we chose not to remove them , then we need to check that OSSL_PKEY_PARAM_USE_COFACTOR_ECDH is set for key agreement if the cofactor is not 1.
- ED25519/ED448 is now approved.
- X25519/X448 is not approved currently. keygen and keyexchange would also need an indicator if we allow it?
- RSA encryption(for key agreement/key transport) using PKCSV15 is no longer allowed. (Note that this breaks TLS 1.2 using RSA for KeyAgreement),
  Padding mode updates required. Check RSA KEM also.
- RSA signing using PKCS1 is still allowed (i.e. signature uses shaXXXWithRSAEncryption)
- RSA signing using X931 is no longer allowed. (Still allowed for verification). Check if PSS saltlen needs a indicator (Note FIPS 186-4 Section 5.5 bullet(e). Padding mode updates required in rsa_check_padding(). Check if sha1 is allowed?
- RSA - (From SP800-131Ar2) RSA >= 2048 is approved for keygen, signatures and key transport. Verification allows 1024 also. Note also that according to the (IG section C.F) that fips 186-2 verification is also allowed (So this may need either testing OR an indicator - it also mentions the modulus size must be 1024 * 256*s). Check that rsa_keygen_pairwise_test() and RSA self tests are all compliant with the above RSA restrictions.

- TLS1_PRF  If we are only trying to support TLS1.2 here then we should remove the tls1.0/1.1 code from the FIPS MODULE.

### Digest Checks

Any algorithms that use a digest need to make sure that the CAVP certificate lists all supported FIPS digests otherwise an indicator is required.
This applies to the following algorithms:

- TLS_1_3_KDF (Only SHA256 and SHA384 Are allowed due to RFC 8446  Appendix B.4)
- TLS1_PRF (Only SHA256,SHA384,SHA512 are allowed)
- X963KDF (SHA1 is not allowed)
- X942KDF
- PBKDF2
- HKDF
- KBKDF
- SSKDF
- SSHKDF
- HMAC
- KMAC
- Any signature algorithms such as RSA, DSA, ECDSA.

The FIPS 140-3 IG Section C.B & C.C have notes related to Vendor affirmation.

Note many of these (such as KDF's will not support SHAKE).
See <https://gitlab.com/redhat/centos-stream/rpms/openssl/-/blob/c9s/0078-KDF-Add-FIPS-indicators.patch?ref_type=heads>
ECDSA and RSA-PSS Signatures allow use of SHAKE.

KECCAK-KMAC-128 and KECCAK-KMAC-256 should not be allowed for anything other than KMAC.
Do we need to check which algorithms allow SHA1 also?

Test that Deterministic ECDSA does not allow SHAKE (IG C.K Additional Comments 6)

### Cipher Checks

- CMAC
- KBKDF CMAC
- GMAC

We should only allow AES. We currently just check the mode.

### Configurable options

- PBKDF2 'lower_bound_checks' needs to be part of the indicator check

Other Changes
-------------

- AES-GCM Security Policy must list AES GCM IV generation scenarios
- TEST_RAND is not approved.
- SSKDF  The security  policy needs to be specific about what it supports i.e. hash, kmac 128/256, hmac-hash. There are also currently no limitations on the digest for hash and hmac
- KBKDF  Security policy should list KMAC-128, KMAC-256 otherwise it should be removed.
- KMAC may need a lower bound check on the output size (SP800-185 Section 8.4.2)
- HMAC (FIPS 140-3 IG Section C.D has notes about the output length when using a Truncated HMAC)
