#include "mfi/mfi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

size_t mfi_sap_encode_baa_intermediate(const uint8_t *intermediate, size_t len,
                                       uint8_t *out, size_t cap)
{
    size_t header;

    if (!out || !intermediate)
        return 0;
    /* OPACK: E1 44 'b' 'a' 'I' 'C' then a string length in 0x70+n / 0x91 /
     * 0x92 / 0x93 form. */
    if (len <= 0x20)
        header = 7;
    else if (len <= 0xff)
        header = 8;
    else if (len <= 0xffff)
        header = 9;
    else
        header = 11;
    if (header + len > cap)
        return 0;

    out[0] = 0xe1;
    out[1] = 0x44;
    out[2] = 'b';
    out[3] = 'a';
    out[4] = 'I';
    out[5] = 'C';
    if (len <= 0x20) {
        out[6] = (uint8_t)(0x70 + len);
    } else if (len <= 0xff) {
        out[6] = 0x91;
        out[7] = (uint8_t)len;
    } else if (len <= 0xffff) {
        out[6] = 0x92;
        out[7] = (uint8_t)len;
        out[8] = (uint8_t)(len >> 8);
    } else {
        out[6] = 0x93;
        out[7] = (uint8_t)len;
        out[8] = (uint8_t)(len >> 8);
        out[9] = (uint8_t)(len >> 16);
        out[10] = (uint8_t)(len >> 24);
    }
    memcpy(out + header, intermediate, len);
    return header + len;
}

static size_t build_mfi_response(const uint8_t public_key[32], const uint8_t *cert, size_t cert_len,
                                 const uint8_t *encrypted, size_t encrypted_len,
                                 uint8_t *out, size_t cap)
{
    size_t need = 32 + 4 + cert_len + 4 + encrypted_len;
    if (need > cap)
        return 0;
    memcpy(out, public_key, 32);
    put_u32(out + 32, (uint32_t)cert_len);
    memcpy(out + 36, cert, cert_len);
    put_u32(out + 36 + cert_len, (uint32_t)encrypted_len);
    memcpy(out + 40 + cert_len, encrypted, encrypted_len);
    return need;
}

static size_t build_baa_response(const uint8_t public_key[32], const uint8_t *leaf, size_t leaf_len,
                                 const uint8_t *encrypted, size_t encrypted_len,
                                 const uint8_t *baic, size_t baic_len, uint8_t *out, size_t cap)
{
    size_t need = 32 + 4 + leaf_len + 4 + encrypted_len + 4 + baic_len;
    if (need > cap)
        return 0;
    memcpy(out, public_key, 32);
    put_u32(out + 32, (uint32_t)leaf_len);
    memcpy(out + 36, leaf, leaf_len);
    put_u32(out + 36 + leaf_len, (uint32_t)encrypted_len);
    memcpy(out + 40 + leaf_len, encrypted, encrypted_len);
    put_u32(out + 40 + leaf_len + encrypted_len, (uint32_t)baic_len);
    memcpy(out + 44 + leaf_len + encrypted_len, baic, baic_len);
    return need;
}

static int derive_key_iv(const uint8_t shared[32], uint8_t key[16], uint8_t iv[16])
{
    static const uint8_t label_key[7] = {'A', 'E', 'S', '-', 'K', 'E', 'Y'};
    static const uint8_t label_iv[6] = {'A', 'E', 'S', '-', 'I', 'V'};
    const uint8_t *parts[2];
    size_t lens[2];
    uint8_t out[20];

    parts[0] = label_key;
    parts[1] = shared;
    lens[0] = sizeof label_key;
    lens[1] = 32;
    if (mfi_sha1(parts, lens, 2, out) != MFI_OK)
        return MFI_ERR_CRYPTO;
    memcpy(key, out, 16);

    parts[0] = label_iv;
    lens[0] = sizeof label_iv;
    if (mfi_sha1(parts, lens, 2, out) != MFI_OK)
        return MFI_ERR_CRYPTO;
    memcpy(iv, out, 16);
    return MFI_OK;
}

static size_t sap_handle_impl(mfi_auth *auth, const uint8_t *body, size_t len, uint8_t *out,
                              size_t cap, const uint8_t *fixed_priv)
{
    uint8_t priv[32], pub[32], peer[32], shared[32];
    uint8_t aes_key[16], aes_iv[16];
    uint8_t digest[32];
    uint8_t sig[MFI_MAX_SIGNATURE];
    uint8_t encrypted[MFI_MAX_SIGNATURE];
    size_t sig_len = 0;
    const uint8_t *parts[2];
    size_t lens[2];

    if (!auth || !body || !out)
        return 0;
    if (len != MFI_SAP_BODY_BYTES || body[0] != MFI_SAP_VERSION)
        return 0;
    memcpy(peer, body + 1, 32);

    if (fixed_priv) {
        memcpy(priv, fixed_priv, 32);
        if (mfi_x25519_public(priv, pub) != MFI_OK)
            return 0;
    } else if (mfi_x25519_keypair(priv, pub) != MFI_OK) {
        return 0;
    }

    if (mfi_x25519_shared(priv, peer, shared) != MFI_OK)
        return 0;
    {
        uint8_t acc = 0;
        for (size_t i = 0; i < 32; i++)
            acc |= shared[i];
        if (acc == 0)
            return 0; /* low-order peer key: the app rejects it too */
    }
    if (derive_key_iv(shared, aes_key, aes_iv) != MFI_OK)
        return 0;

    if (auth->cert_type == MFI_CERT_TYPE_BAA) {
        const uint8_t *leaf = NULL, *intermediate = NULL;
        size_t leaf_len = 0, intermediate_len = 0;
        uint8_t concat[64];
        uint8_t baic[128];
        size_t baic_len;

        if (!auth->baa_certificates)
            return 0;
        if (auth->baa_certificates(auth, &leaf, &leaf_len, &intermediate, &intermediate_len) !=
            MFI_OK)
            return 0;
        memcpy(concat, pub, 32);
        memcpy(concat + 32, peer, 32);
        /* BAA signs the 64-byte concatenation of both public keys. */
        if (auth->sign_challenge(auth, concat, sizeof concat, sig, sizeof sig, &sig_len) != MFI_OK)
            return 0;
        if (sig_len > sizeof encrypted)
            return 0;
        if (mfi_aes128_ctr(aes_key, aes_iv, sig, sig_len, encrypted) != MFI_OK)
            return 0;
        baic_len = mfi_sap_encode_baa_intermediate(intermediate, intermediate_len, baic, sizeof baic);
        if (baic_len == 0)
            return 0;
        return build_baa_response(pub, leaf, leaf_len, encrypted, sig_len, baic, baic_len, out, cap);
    }

    {
        uint8_t *cert = malloc(MFI_MAX_CERTIFICATE);
        size_t cert_len = 0;
        size_t rc = 0;

        if (!cert)
            return 0;
        if (auth->read_certificate(auth, cert, MFI_MAX_CERTIFICATE, &cert_len) != MFI_OK ||
            cert_len == 0 || cert_len > MFI_MAX_CERTIFICATE)
            goto done;

        parts[0] = pub;
        parts[1] = peer;
        lens[0] = 32;
        lens[1] = 32;
        if (auth->protocol_major(auth) == 2) {
            uint8_t d[20];
            if (mfi_sha1(parts, lens, 2, d) != MFI_OK)
                goto done;
            if (auth->sign_challenge(auth, d, sizeof d, sig, sizeof sig, &sig_len) != MFI_OK)
                goto done;
        } else {
            if (mfi_sha256(parts, lens, 2, digest) != MFI_OK)
                goto done;
            if (auth->sign_challenge(auth, digest, sizeof digest, sig, sizeof sig, &sig_len) !=
                MFI_OK)
                goto done;
        }
        if (sig_len > sizeof encrypted)
            goto done;
        if (mfi_aes128_ctr(aes_key, aes_iv, sig, sig_len, encrypted) != MFI_OK)
            goto done;
        rc = build_mfi_response(pub, cert, cert_len, encrypted, sig_len, out, cap);
    done:
        free(cert);
        return rc;
    }
}

size_t mfi_sap_handle(mfi_auth *auth, const uint8_t *body, size_t len, uint8_t *out, size_t cap)
{
    return sap_handle_impl(auth, body, len, out, cap, NULL);
}

size_t mfi_sap_handle_deterministic(mfi_auth *auth, const uint8_t *body, size_t len, uint8_t *out,
                                    size_t cap, const uint8_t fixed_priv[32])
{
    return sap_handle_impl(auth, body, len, out, cap, fixed_priv);
}
