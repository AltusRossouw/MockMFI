#include "mfi_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A software implementation of the MFi authentication coprocessor register
 * protocol.  It is the reference fixture for mfi_cp_create() and lets a Linux
 * host exercise the exact same driver path without hardware. */
typedef struct {
    mfi_identity *id;
    uint8_t *cert;
    size_t cert_len;
    uint8_t selected;
    uint8_t challenge[MFI_MAX_CHALLENGE];
    size_t challenge_len;
    uint8_t response[256];
    size_t response_len;
    uint8_t status;
    uint8_t error;
} cp_sim;

static int sim_transaction(void *ctx, uint8_t addr7, const uint8_t *w, size_t wlen,
                           uint8_t *r, size_t rlen)
{
    cp_sim *s = ctx;
    (void)addr7;

    if (!s)
        return MFI_ERR_ARG;

    if (wlen == 0) {
        switch (s->selected) {
        case 0x00:
            if (rlen)
                r[0] = 0x02; /* device version */
            break;
        case 0x02:
            if (rlen)
                r[0] = 0x03; /* protocol major of a software identity */
            break;
        case 0x05:
            if (rlen)
                r[0] = s->error;
            break;
        case 0x10:
            if (rlen)
                r[0] = s->status;
            break;
        case 0x11:
            if (rlen >= 2) {
                r[0] = (uint8_t)(s->response_len >> 8);
                r[1] = (uint8_t)s->response_len;
            }
            break;
        case 0x12:
            memset(r, 0, rlen);
            if (s->response_len && rlen)
                memcpy(r, s->response, rlen < s->response_len ? rlen : s->response_len);
            break;
        case 0x30:
            if (rlen >= 2) {
                r[0] = (uint8_t)(s->cert_len >> 8);
                r[1] = (uint8_t)s->cert_len;
            }
            break;
        default:
            if (s->selected >= 0x31) {
                size_t offset = (size_t)(s->selected - 0x31) * 128;
                memset(r, 0, rlen);
                if (offset < s->cert_len) {
                    size_t n = s->cert_len - offset;
                    if (n > rlen)
                        n = rlen;
                    memcpy(r, s->cert + offset, n);
                }
            }
            break;
        }
        return MFI_OK;
    }

    s->selected = w[0];
    if (wlen == 1)
        return MFI_OK;

    switch (s->selected) {
    case 0x10:
        if (w[1] == 0x01) {
            uint8_t der[128];
            size_t der_len = 0;
            char err[96];
            if (s->challenge_len != 32) {
                s->error = 0x01;
                s->status = 0;
                return MFI_OK;
            }
            if (mfi_ecdsa_sign_digest(s->id->key, s->challenge, s->challenge_len, der,
                                      sizeof der, &der_len) != MFI_OK ||
                mfi_ecdsa_der_to_raw(der, der_len, s->response, err, sizeof err) != MFI_OK) {
                s->error = 0x02;
                s->status = 0;
                return MFI_OK;
            }
            s->response_len = 64;
            s->status = 0x10;
        }
        break;
    case 0x20:
        if (wlen >= 3)
            s->challenge_len = ((size_t)w[1] << 8) | w[2];
        break;
    case 0x21: {
        size_t n = wlen - 1;
        if (n > sizeof s->challenge)
            n = sizeof s->challenge;
        memcpy(s->challenge, w + 1, n);
        break;
    }
    default:
        break;
    }
    return MFI_OK;
}

static void sim_destroy(void *ctx)
{
    cp_sim *s = ctx;
    if (!s)
        return;
    mfi_identity_free(s->id);
    free(s->cert);
    free(s);
}

int mfi_cp_sim_create(mfi_i2c_io **out, const char *identity_dir, char *err, size_t errlen)
{
    mfi_identity *id = NULL;
    const uint8_t *cert = NULL;
    size_t cert_len = 0;
    cp_sim *s;
    mfi_i2c_io *io;

    if (err && errlen)
        err[0] = '\0';
    if (!out) {
        if (err)
            snprintf(err, errlen, "missing output");
        return MFI_ERR_ARG;
    }
    if (mfi_identity_load_dir(&id, identity_dir, err, errlen) != MFI_OK)
        return MFI_ERR_IO;
    if (mfi_identity_self_test(id, err, errlen) != MFI_OK) {
        mfi_identity_free(id);
        return MFI_ERR_AUTH_FAILED;
    }
    if (mfi_identity_certificate(id, &cert, &cert_len) != MFI_OK) {
        mfi_identity_free(id);
        return MFI_ERR_CRYPTO;
    }

    s = calloc(1, sizeof *s);
    io = calloc(1, sizeof *io);
    if (!s || !io) {
        free(s);
        free(io);
        mfi_identity_free(id);
        return MFI_ERR_NOMEM;
    }
    s->cert = malloc(cert_len);
    if (!s->cert) {
        free(s);
        free(io);
        mfi_identity_free(id);
        return MFI_ERR_NOMEM;
    }
    memcpy(s->cert, cert, cert_len);
    s->cert_len = cert_len;
    s->id = id;
    s->selected = 0x00;

    io->transaction = sim_transaction;
    io->destroy = sim_destroy;
    io->ctx = s;
    *out = io;
    return MFI_OK;
}
