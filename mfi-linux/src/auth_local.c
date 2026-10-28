#include "mfi_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    mfi_auth base;
    mfi_identity *id;
} local_auth;

static int local_protocol_major(mfi_auth *self)
{
    (void)self;
    /* LocalMfiAuthenticationClient.protocolMajor() == 3. */
    return 3;
}

static int local_read_certificate(mfi_auth *self, uint8_t *out, size_t cap, size_t *len)
{
    local_auth *l = (local_auth *)self;
    const uint8_t *cert;
    size_t cert_len;

    if (mfi_identity_certificate(l->id, &cert, &cert_len) != MFI_OK)
        return MFI_ERR_STATE;
    if (cert_len > cap)
        return MFI_ERR_ARG;
    memcpy(out, cert, cert_len);
    *len = cert_len;
    return MFI_OK;
}

static int local_sign_challenge(mfi_auth *self, const uint8_t *challenge, size_t len,
                                uint8_t *sig, size_t cap, size_t *sig_len)
{
    local_auth *l = (local_auth *)self;
    uint8_t der[128];
    size_t der_len = 0;
    char err[160];

    if (len != 32)
        return MFI_ERR_FORMAT;
    if (cap < 64)
        return MFI_ERR_ARG;
    if (mfi_ecdsa_sign_digest(l->id->key, challenge, len, der, sizeof der, &der_len) != MFI_OK)
        return MFI_ERR_CRYPTO;
    if (mfi_ecdsa_der_to_raw(der, der_len, sig, err, sizeof err) != MFI_OK)
        return MFI_ERR_CRYPTO;
    *sig_len = 64;
    return MFI_OK;
}

static void local_destroy(mfi_auth *self)
{
    local_auth *l = (local_auth *)self;
    if (!l)
        return;
    mfi_identity_free(l->id);
    free(l);
}

int mfi_auth_local_create(mfi_auth **out, mfi_identity *id, char *err, size_t errlen)
{
    local_auth *l;

    if (err && errlen)
        err[0] = '\0';
    if (!out || !id) {
        mfi_identity_free(id);
        if (err)
            snprintf(err, errlen, "missing identity");
        return MFI_ERR_ARG;
    }
    if (mfi_identity_self_test(id, err, errlen) != MFI_OK) {
        mfi_identity_free(id);
        return MFI_ERR_AUTH_FAILED;
    }
    l = calloc(1, sizeof *l);
    if (!l) {
        mfi_identity_free(id);
        return MFI_ERR_NOMEM;
    }
    l->id = id;
    l->base.name = "local-p256";
    l->base.cert_type = MFI_CERT_TYPE_MFI;
    l->base.protocol_major = local_protocol_major;
    l->base.read_certificate = local_read_certificate;
    l->base.sign_challenge = local_sign_challenge;
    l->base.destroy = local_destroy;
    l->base.ctx = l;
    *out = &l->base;
    return MFI_OK;
}
