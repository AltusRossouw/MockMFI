#include "mfi_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

size_t mfi_iap2_build_request_certificate(uint8_t *out, size_t cap)
{
    return mfi_csm_encode_frame(out, cap, MFI_IAP2_REQUEST_CERTIFICATE, NULL, 0);
}

size_t mfi_iap2_build_certificate(uint8_t *out, size_t cap, const uint8_t *cert, size_t cert_len)
{
    uint8_t params[4 + MFI_MAX_CERTIFICATE];
    size_t plen;

    if (cert_len > MFI_MAX_CERTIFICATE)
        return 0;
    plen = mfi_csm_encode_param(params, sizeof params, 0, cert, cert_len);
    if (!plen)
        return 0;
    return mfi_csm_encode_frame(out, cap, MFI_IAP2_CERTIFICATE, params, plen);
}

size_t mfi_iap2_build_certificate_baa(uint8_t *out, size_t cap, const uint8_t *leaf, size_t leaf_len,
                                      const uint8_t *intermediate, size_t intermediate_len)
{
    uint8_t params[12 + 2 * MFI_MAX_CERTIFICATE];
    size_t off = 0;
    size_t n;
    uint8_t one = 1;

    n = mfi_csm_encode_param(params + off, sizeof params - off, 0, leaf, leaf_len);
    if (!n)
        return 0;
    off += n;
    n = mfi_csm_encode_param(params + off, sizeof params - off, 1, &one, 1);
    if (!n)
        return 0;
    off += n;
    n = mfi_csm_encode_param(params + off, sizeof params - off, 2, intermediate, intermediate_len);
    if (!n)
        return 0;
    off += n;
    return mfi_csm_encode_frame(out, cap, MFI_IAP2_CERTIFICATE, params, off);
}

size_t mfi_iap2_build_response(uint8_t *out, size_t cap, const uint8_t *sig, size_t sig_len)
{
    uint8_t params[4 + MFI_MAX_SIGNATURE];
    size_t plen = mfi_csm_encode_param(params, sizeof params, 0, sig, sig_len);
    if (!plen)
        return 0;
    return mfi_csm_encode_frame(out, cap, MFI_IAP2_RESPONSE, params, plen);
}

size_t mfi_iap2_build_success(uint8_t *out, size_t cap)
{
    return mfi_csm_encode_frame(out, cap, MFI_IAP2_AUTHENTICATION_SUCCEEDED, NULL, 0);
}

size_t mfi_iap2_build_failure(uint8_t *out, size_t cap)
{
    return mfi_csm_encode_frame(out, cap, MFI_IAP2_AUTHENTICATION_FAILED, NULL, 0);
}

size_t mfi_iap2_build_request_challenge(uint8_t *out, size_t cap, const uint8_t *ch, size_t len)
{
    uint8_t params[4 + MFI_MAX_CHALLENGE];
    size_t plen;

    if (len > MFI_MAX_CHALLENGE)
        return 0;
    plen = mfi_csm_encode_param(params, sizeof params, 0, ch, len);
    if (!plen)
        return 0;
    return mfi_csm_encode_frame(out, cap, MFI_IAP2_REQUEST_CHALLENGE, params, plen);
}

int mfi_iap2_challenge(const mfi_csm_message *msg, const uint8_t **data, size_t *len)
{
    if (!msg || !data || !len)
        return MFI_ERR_ARG;
    for (size_t i = 0; i < msg->param_count; i++) {
        if (msg->params[i].id == 0) {
            *data = msg->params[i].data;
            *len = msg->params[i].len;
            return MFI_OK;
        }
    }
    return MFI_ERR_FORMAT;
}

static int write_all(mfi_link *link, const uint8_t *buf, size_t len)
{
    return link->ops.write(link->ops.ctx, buf, len);
}

typedef struct {
    mfi_auth *auth;
    mfi_link *link;
    mfi_log_fn log;
    void *logctx;
    uint8_t *cert;
    size_t cert_len;
    int cert_type;
    int result; /* MFI_OK while running */
    int processed;
} auth_ctx;

static int handle_frame(void *vctx, const uint8_t *frame, size_t len)
{
    auth_ctx *c = vctx;
    mfi_csm_message msg;
    char err[160];
    uint8_t out[6 + 8 + 2 * MFI_MAX_CERTIFICATE];
    size_t out_len;

    if (mfi_csm_decode(frame, len, &msg, err, sizeof err) != MFI_OK) {
        mfi_log(c->log, c->logctx, "iap2: dropping malformed frame: %s", err);
        return 0;
    }

    switch (msg.msgid) {
    case MFI_IAP2_REQUEST_CERTIFICATE:
        mfi_log(c->log, c->logctx, "iap2 mfi rx=0xaa00 request-certificate");
        if (c->cert_type == MFI_CERT_TYPE_BAA) {
            const uint8_t *leaf = NULL, *inter = NULL;
            size_t leaf_len = 0, inter_len = 0;
            if (!c->auth->baa_certificates ||
                c->auth->baa_certificates(c->auth, &leaf, &leaf_len, &inter, &inter_len) != MFI_OK) {
                c->result = MFI_ERR_AUTH_FAILED;
                return 1;
            }
            out_len = mfi_iap2_build_certificate_baa(out, sizeof out, leaf, leaf_len, inter, inter_len);
        } else {
            out_len = mfi_iap2_build_certificate(out, sizeof out, c->cert, c->cert_len);
        }
        if (!out_len || write_all(c->link, out, out_len) != MFI_OK) {
            c->result = MFI_ERR_IO;
            return 1;
        }
        mfi_log(c->log, c->logctx, "iap2 mfi tx=0xaa01 certificate bytes=%zu", out_len);
        return 0;

    case MFI_IAP2_REQUEST_CHALLENGE: {
        const uint8_t *challenge = NULL;
        size_t challenge_len = 0;
        uint8_t sig[MFI_MAX_SIGNATURE];
        size_t sig_len = 0;

        if (mfi_iap2_challenge(&msg, &challenge, &challenge_len) != MFI_OK) {
            mfi_log(c->log, c->logctx, "iap2 mfi rx=0xaa02 without parameter 0");
            c->result = MFI_ERR_FORMAT;
            return 1;
        }
        if (challenge_len == 0 || challenge_len > MFI_MAX_CHALLENGE) {
            mfi_log(c->log, c->logctx, "iap2 mfi invalid challenge length %zu", challenge_len);
            c->result = MFI_ERR_FORMAT;
            return 1;
        }
        mfi_log(c->log, c->logctx, "iap2 mfi rx=0xaa02 challenge bytes=%zu", challenge_len);
        if (c->auth->sign_challenge(c->auth, challenge, challenge_len, sig, sizeof sig, &sig_len) !=
            MFI_OK) {
            c->result = MFI_ERR_AUTH_FAILED;
            return 1;
        }
        out_len = mfi_iap2_build_response(out, sizeof out, sig, sig_len);
        if (!out_len || write_all(c->link, out, out_len) != MFI_OK) {
            c->result = MFI_ERR_IO;
            return 1;
        }
        mfi_log(c->log, c->logctx, "iap2 mfi tx=0xaa03 signature bytes=%zu", sig_len);
        return 0;
    }

    case MFI_IAP2_AUTHENTICATION_SUCCEEDED:
        mfi_log(c->log, c->logctx, "iap2 mfi rx=0xaa05 authentication-succeeded");
        c->result = MFI_OK;
        return 1;

    case MFI_IAP2_AUTHENTICATION_FAILED:
        mfi_log(c->log, c->logctx, "iap2 mfi rx=0xaa04 authentication-failed");
        c->result = MFI_ERR_AUTH_FAILED;
        return 1;

    default:
        mfi_log(c->log, c->logctx, "iap2 mfi unexpected message 0x%04x", msg.msgid);
        c->result = MFI_ERR_STATE;
        return 1;
    }
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int mfi_iap2_authenticate(mfi_auth *auth, mfi_link *link, int timeout_ms,
                          mfi_log_fn log, void *logctx, char *err, size_t errlen)
{
    auth_ctx c;
    mfi_csm_parser parser;
    uint8_t buf[4096];
    long long deadline;

    if (err && errlen)
        err[0] = '\0';
    if (!auth || !link) {
        if (err)
            snprintf(err, errlen, "missing authenticator or link");
        return MFI_ERR_ARG;
    }
    if (timeout_ms <= 0 || timeout_ms > MFI_IAP2_MAX_TIMEOUT_MS) {
        if (err)
            snprintf(err, errlen, "timeout must be 1..%d ms", MFI_IAP2_MAX_TIMEOUT_MS);
        return MFI_ERR_ARG;
    }

    memset(&c, 0, sizeof c);
    c.auth = auth;
    c.link = link;
    c.log = log;
    c.logctx = logctx;
    c.cert_type = auth->cert_type;

    c.cert = malloc(MFI_MAX_CERTIFICATE);
    if (!c.cert)
        return MFI_ERR_NOMEM;
    if (c.cert_type == MFI_CERT_TYPE_MFI) {
        if (auth->read_certificate(auth, c.cert, MFI_MAX_CERTIFICATE, &c.cert_len) != MFI_OK ||
            c.cert_len == 0) {
            free(c.cert);
            if (err)
                snprintf(err, errlen, "authenticator did not return a certificate");
            return MFI_ERR_AUTH_FAILED;
        }
        mfi_log(log, logctx, "mfi type=MFI certificate loaded bytes=%zu", c.cert_len);
    } else {
        mfi_log(log, logctx, "mfi type=BAA certificate served on request");
    }

    mfi_csm_parser_init(&parser);
    c.result = MFI_ERR_TIMEOUT;
    deadline = now_ms() + timeout_ms;

    while (c.result == MFI_ERR_TIMEOUT) {
        long long remaining = deadline - now_ms();
        size_t got = 0;
        size_t delivered = 0;
        int rc;

        if (remaining <= 0) {
            c.result = MFI_ERR_TIMEOUT;
            break;
        }
        rc = link->ops.read(link->ops.ctx, buf, sizeof buf, (int)remaining, &got);
        if (rc == MFI_ERR_TIMEOUT || (rc == MFI_OK && got == 0)) {
            c.result = MFI_ERR_TIMEOUT;
            break;
        }
        if (rc != MFI_OK) {
            c.result = rc;
            break;
        }
        if (mfi_csm_parser_feed(&parser, buf, got, handle_frame, &c, &delivered) != MFI_OK)
            break; /* handle_frame stored the reason in c.result */
    }

    free(c.cert);
    if (c.result == MFI_OK)
        return MFI_OK;
    if (err)
        snprintf(err, errlen, "iAP2 MFi authentication did not complete (%s)",
                 mfi_strerror(c.result));
    return c.result;
}
