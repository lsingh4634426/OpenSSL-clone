EVP APIs for supporting cipher pipelining in provided ciphers
=============================================================

OpenSSL previously supported "pipeline" ciphers via ENGINE implementations. That support was lost when we moved to providers. This document discusses API design to restore that capability and enable providers to implement such ciphers.

Pipeline operation
-------------------

Certain ciphers, such as AES-GCM, can be optimized by computing blocks in parallel. Cipher pipelining support allows application to submit multiple chunks of data in one cipher update call, thereby allowing the provided implementation to take advantage of parallel computing. This is very beneficial for hardware accelerators as pipeline amortizes the latency over multiple chunks. Our libssl makes use of pipeline as discussed in [here](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_max_pipelines.html).

Pipelining with ENGINE
-----------------------

Before discussing API design for providers, let's take a look at existing pipeline API that works with engines.

**EVP Interface:**
flag to denote pipeline support
```
cipher->flags & EVP_CIPH_FLAG_PIPELINE
```

Input/output and aad buffers are set using `EVP_CIPHER_CTX_ctrl()`
```
EVP_CIPHER_CTX_ctrl() 
    - EVP_CTRL_AEAD_TLS1_AAD (loop: one aad at a time)
    - EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS (array of buffer pointers)
    - EVP_CTRL_SET_PIPELINE_INPUT_BUFS (array of buffer pointers)
    - EVP_CTRL_SET_PIPELINE_INPUT_LENS
```

Single-call cipher invoked to perform encryption/decryption. 
```
EVP_Cipher()
```


Proposal for EVP pipeline APIs
-------------------------------------

Current API design is made similar to non-pipeline counterpart. The below proposal will be updated as per decisions made in next section (Design decisions).

**EVP Interface:**
API to check for pipeline support in provided cipher.
```c
/**
 * @brief checks if the provider has exported required pipeline functions
 * @return 0 (pipeline not supported) or 1 (pipeline supported)
 */
int EVP_CIPHER_can_pipeline(const EVP_CIPHER *cipher)
```

Multi-call APIs for init, update and final. Associated data for AEAD ciphers are set in `EVP_CipherPipelineUpdate`.
```c
typedef struct {
    unsigned char *buf;
    size_t buf_len;
} OSSL_cipher_buf;

/**
 * @param iv    array of pointers (array length must be numpipes)
 */
EVP_CipherPipelineInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, size_t numpipes, const unsigned char **iv, int enc);

/**
 * @param out       array of OSSL_cipher_buf containing output buffers (array length must be numpipes)
 *                  when this param is NULL, input buffers are treated as AAD data (individual pointers within array being NULL will be an error)
 * @param in        array of OSSL_cipher_buf containing input buffers (array length must be numpipes)
 * @param stride    The stride argument must be set to sizeof(OSSL_cipher_buf)
 */
EVP_CipherPipelineUpdate(EVP_CIPHER_CTX *ctx, OSSL_cipher_buf *out, OSSL_cipher_buf *in, size_t stride);

/**
 * @param outm      array of OSSL_cipher_buf containing output buffers (array length must be numpipes)
 * @param stride    The stride argument must be set to sizeof(OSSL_cipher_buf)
 */
EVP_CipherPipelineFinal(EVP_CIPHER_CTX *ctx, OSSL_cipher_buf *out, size_t stride);
```

API to get/set AEAD auth tag.
```c
/**
 * @param buf   array of OSSL_cipher_buf containing output buffers (array length must be numpipes)
 * @param bsize stride; sizeof(OSSL_cipher_buf)
 */
OSSL_CIPHER_PARAM_PIPELINE_AEAD_TAG (type OSSL_PARAM_OCTET_PTR)
```

**Design Decisions:**
1. Denoting pipeline support
    - [ ] a. A cipher flag `EVP_CIPH_FLAG_PROVIDED_PIPELINE` (this has to be different than EVP_CIPH_FLAG_PIPELINE, so that it doesn't break legacy applications).
    - [x] b. A function `EVP_CIPHER_can_pipeline()` that checks if the provider exports pipeline functions.
    > **Justification:** flags variable is deprecated in EVP_CIPHER struct. Moreover, EVP can check for presence of pipeline functions, rather than requiring providers to set a flag.

    With the introduction of this new API, there will be two APIs for pipelining available until the legacy code is phased out:

    - When an Engine that supports pipelining is loaded, it will set the `ctx->flags & EVP_CIPH_FLAG_PIPELINE`. If this flag is set, applications can continue to use the legacy API for pipelining.
    - When a Provider that supports pipelining is fetched, EVP_CIPHER_can_pipeline() will return true, allowing applications to utilize the new API for pipelining.

2. `numpipes` argument
    - [x] a. `numpipes` received only in `EVP_CipherPipelineInit()` and saved in EVP_CIPHER_CTX for further use.
    - [ ] b. `numpipes` value is repeatedly received in each `EVP_CipherPipelineInit()`, `EVP_CipherPipelineUpdate()` and `EVP_CipherPipelineFinal()` call.
    > **Justification:** It is expected for numpipes to be same across init, update and final operation.

3. Input/Output buffers
    - [ ] a. A set of buffers is represented by an array of buffer pointers and an array of lengths. Example: `unsigned char **out, size_t *outl`.
    - [x] b. iovec style: A new type that holds one buffer pointer along with its size. Example: `OSSL_cipher_buf *out`
    > **Justification:** iovec style keeps buffer pointer and buffer length together, which a good way of representing C buffers.

4. AEAD tag
    - [x] a. A new OSSL_CIPHER_PARAM of type OSSL_PARAM_OCTET_PTR, `OSSL_CIPHER_PARAM_PIPELINE_AEAD_TAG`, that uses an array of buffer pointers. This can be used with `iovec_buf` if we decide with 3.b.
    - [ ] b. Reuse `OSSL_CIPHER_PARAM_AEAD_TAG` by using it in a loop, processing one tag at a time.
    > **Justification:** Reduces cipher get/set param operations.

**Usage Examples:**
```c
/*
 * WARNING: This example aims to demonstrate only API usage. 
 * It leaves out multiple necessary steps required for secure AES-GCM use.
 * TODO: add error handling
 */
#define PIPE_COUNT  8
#define AAD_LEN     16
#define TAG_LEN     16
#define IV_LEN      12
void do_cipher_pipeline() {
    unsigned char key[128 / 8];
    unsigned char ct[PIPE_COUNT][64], pt[PIPE_COUNT][64], iv_data[8][IV_LEN];
    unsigned char add_data[PIPE_COUNT][AAD_LEN], tag[PIPE_COUNT][TAG_LEN];
    unsigned char *iv[PIPE_COUNT];
    OSSL_cipher_buf out[PIPE_COUNT], in[PIPE_COUNT], aad[PIPE_COUNT];

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    opt_cipher_silent("aes-128-gcm", &cipher);
    if (!EVP_CIPHER_can_pipeline(cipher)) {
        printf("Not supported\n");
        return;
    }
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherPipelineInit(ctx, cipher, key, PIPE_COUNT, NULL, 1);

    for (int i = 0; i < PIPE_COUNT; i++) {
        iv[i] = iv_data[i];
        in[i].buf = pt[i];
        in[i].buf_len = 64;
        aad[i].buf = add_data[i];
        aad[i].buf_len = AAD_LEN;
        out[i].buf = ct[i];
        out[i].buf_len = 0;
    }

    /* set IV */
    assert(EVP_CIPHER_CTX_get_iv_length(ctx) == IV_LEN);
    EVP_CipherPipelineInit(ctx, cipher, NULL, PIPE_COUNT, iv, 1);

    /* set AAD */
    EVP_CipherPipelineUpdate(ctx, NULL, aad);

    EVP_CipherPipelineUpdate(ctx, out, in, sizeof(OSSL_cipher_buf));

    for (int i = 0; i < PIPE_COUNT; i++) {
        out[i].buf += out[i].buf_len;
        out[i].buf_len = 0;
    }

    EVP_CipherPipelineFinal(ctx, out, sizeof(OSSL_cipher_buf));

    /* get auth tag */
    for (int i = 0; i < PIPE_COUNT; i++) {
        out[i].buf = tag[i];
        out[i].buf_len = 0;
    }
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    params[0] = OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_PIPELINE_AEAD_TAG, out, sizeof(OSSL_cipher_buf));
    evp_do_ciph_ctx_getparams(ctx->cipher, ctx->algctx, params);
}
```

Q&A
----
1. It would be nice to have a mechanism for fetching provider with pipeline support over other providers that don't support pipeline. How can we achieve this?