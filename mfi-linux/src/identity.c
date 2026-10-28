#include "mfi_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

static int pkey_is_prime256(EVP_PKEY *pkey)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    char group[80];
    size_t len = 0;
    if (EVP_PKEY_get_group_name(pkey, group, sizeof group, &len) != 1)
        return 0;
    return strcmp(group, "prime256v1") == 0 || strcmp(group, "P-256") == 0;
#else
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_GROUP *g = ec ? EC_KEY_get0_group(ec) : NULL;
    int nid = g ? EC_GROUP_get_curve_name(g) : NID_undef;
    EC_KEY_free(ec);
    return nid == NID_X9_62_prime256v1;
#endif
}

void mfi_log(mfi_log_fn log, void *ctx, const char *fmt, ...)
{
    va_list ap;
    if (!log)
        return;
    va_start(ap, fmt);
    char buf[512];
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    log(ctx, "%s", buf);
}

/* Extract the first certificate from a PKCS#7 container without relying on
 * signerInfo (MFi certificate containers carry certificates only). */
static X509 *first_pkcs7_cert(const uint8_t *der, size_t len)
{
    X509 *out = NULL;
    STACK_OF(X509) *signers = NULL;
    PKCS7 *p7 = NULL;
    const uint8_t *p = der;

    p7 = d2i_PKCS7(NULL, &p, (long)len);
    if (p7) {
        signers = PKCS7_get0_signers(p7, NULL, 0);
        if (signers && sk_X509_num(signers) > 0) {
            out = X509_dup(sk_X509_value(signers, 0));
        } else if (PKCS7_type_is_signed(p7) && p7->d.sign && p7->d.sign->cert &&
                   sk_X509_num(p7->d.sign->cert) > 0) {
            out = X509_dup(sk_X509_value(p7->d.sign->cert, 0));
        }
        sk_X509_free(signers);
        PKCS7_free(p7);
        if (out)
            return out;
    }

    /* Last resort: scan for an embedded X.509 SEQUENCE.  A certificate parses
     * as X509; the surrounding CMS structures and public-key SEQUENCEs do not. */
    for (size_t i = 0; i + 4 < len; i++) {
        if (der[i] != 0x30)
            continue;
        const uint8_t *q = der + i;
        X509 *x = d2i_X509(NULL, &q, (long)(len - i));
        if (x) {
            out = x;
            break;
        }
        ERR_clear_error();
    }
    return out;
}

int mfi_identity_create_from_memory(mfi_identity **out, const uint8_t *pk8, size_t pk8_len,
                                    const uint8_t *cert, size_t cert_len, char *err, size_t errlen)
{
    mfi_identity *id;
    const uint8_t *p;
    EVP_PKEY *key;
    X509 *leaf;
    char detail[256];

    if (err && errlen)
        err[0] = '\0';
    if (!out || !pk8 || !cert) {
        if (err)
            snprintf(err, errlen, "missing key or certificate");
        return MFI_ERR_ARG;
    }

    p = pk8;
    key = d2i_AutoPrivateKey(NULL, &p, (long)pk8_len);
    if (!key) {
        ERR_clear_error();
        if (err)
            snprintf(err, errlen, "PKCS#8 private key does not parse (%zu bytes)", pk8_len);
        return MFI_ERR_FORMAT;
    }
    if (EVP_PKEY_base_id(key) != EVP_PKEY_EC || !pkey_is_prime256(key)) {
        EVP_PKEY_free(key);
        if (err)
            snprintf(err, errlen, "identity key is not an EC P-256 key");
        return MFI_ERR_UNSUPPORTED;
    }

    leaf = first_pkcs7_cert(cert, cert_len);
    if (!leaf) {
        p = cert;
        leaf = d2i_X509(NULL, &p, (long)cert_len);
    }
    if (!leaf) {
        EVP_PKEY_free(key);
        ERR_clear_error();
        if (err)
            snprintf(err, errlen, "certificate container has no X.509 certificate (%zu bytes)",
                     cert_len);
        return MFI_ERR_FORMAT;
    }

    /* Key and certificate must agree; otherwise signing produces garbage the
     * phone rejects after a full exchange. */
    if (X509_check_private_key(leaf, key) != 1) {
        ERR_clear_error();
        X509_free(leaf);
        EVP_PKEY_free(key);
        if (err)
            snprintf(err, errlen, "private key does not match the certificate public key");
        return MFI_ERR_AUTH_FAILED;
    }
    {
        EVP_PKEY *pub = X509_get_pubkey(leaf);
        int ok = pub && EVP_PKEY_base_id(pub) == EVP_PKEY_EC && pkey_is_prime256(pub);
        EVP_PKEY_free(pub);
        if (!ok) {
            X509_free(leaf);
            EVP_PKEY_free(key);
            if (err)
                snprintf(err, errlen, "certificate public key is not EC P-256");
            return MFI_ERR_UNSUPPORTED;
        }
    }

    id = calloc(1, sizeof *id);
    if (!id) {
        X509_free(leaf);
        EVP_PKEY_free(key);
        return MFI_ERR_NOMEM;
    }
    id->cert = malloc(cert_len ? cert_len : 1);
    if (!id->cert) {
        free(id);
        X509_free(leaf);
        EVP_PKEY_free(key);
        return MFI_ERR_NOMEM;
    }
    memcpy(id->cert, cert, cert_len);
    id->cert_len = cert_len;
    id->key = key;
    id->leaf = leaf;

    (void)detail;
    *out = id;
    return MFI_OK;
}

int mfi_identity_load_memory(mfi_identity **out, const uint8_t *pk8, size_t pk8_len,
                             const uint8_t *cert, size_t cert_len, char *err, size_t errlen)
{
    if (cert_len > MFI_MAX_CERTIFICATE) {
        if (err)
            snprintf(err, errlen, "certificate is %zu bytes; iAP2 limit is %d", cert_len,
                     MFI_MAX_CERTIFICATE);
        return MFI_ERR_FORMAT;
    }
    return mfi_identity_create_from_memory(out, pk8, pk8_len, cert, cert_len, err, errlen);
}

int mfi_identity_load_files(mfi_identity **out, const char *key_path, const char *cert_path,
                            char *err, size_t errlen)
{
    uint8_t *key = NULL, *cert = NULL;
    size_t key_len = 0, cert_len = 0;
    int rc;

    if (mfi_read_file(key_path, &key, &key_len, 16384, err, errlen) != MFI_OK)
        return MFI_ERR_IO;
    if (mfi_read_file(cert_path, &cert, &cert_len, 16384, err, errlen) != MFI_OK) {
        free(key);
        return MFI_ERR_IO;
    }
    rc = mfi_identity_load_memory(out, key, key_len, cert, cert_len, err, errlen);
    free(key);
    free(cert);
    return rc;
}

int mfi_identity_load_dir(mfi_identity **out, const char *dir, char *err, size_t errlen)
{
    char key_path[1024];
    char cert_path[1024];
    snprintf(key_path, sizeof key_path, "%s/identity.pk8", dir);
    snprintf(cert_path, sizeof cert_path, "%s/certificate.p7b", dir);
    return mfi_identity_load_files(out, key_path, cert_path, err, errlen);
}

void mfi_identity_free(mfi_identity *id)
{
    if (!id)
        return;
    EVP_PKEY_free(id->key);
    X509_free(id->leaf);
    free(id->cert);
    free(id);
}

int mfi_identity_certificate(mfi_identity *id, const uint8_t **data, size_t *len)
{
    if (!id || !data || !len)
        return MFI_ERR_ARG;
    *data = id->cert;
    *len = id->cert_len;
    return MFI_OK;
}

int mfi_identity_is_p256(mfi_identity *id)
{
    return id && id->key && EVP_PKEY_base_id(id->key) == EVP_PKEY_EC;
}

int mfi_identity_self_test(mfi_identity *id, char *err, size_t errlen)
{
    uint8_t digest[32];
    uint8_t der[128];
    size_t der_len = 0;

    if (!id) {
        if (err)
            snprintf(err, errlen, "no identity");
        return MFI_ERR_ARG;
    }
    if (mfi_random(digest, sizeof digest) != MFI_OK) {
        if (err)
            snprintf(err, errlen, "no random source");
        return MFI_ERR_IO;
    }
    if (mfi_ecdsa_sign_digest(id->key, digest, sizeof digest, der, sizeof der, &der_len) != MFI_OK) {
        if (err)
            snprintf(err, errlen, "identity failed to sign a 32-byte digest");
        return MFI_ERR_CRYPTO;
    }
    {
        EVP_PKEY *pub = X509_get_pubkey(id->leaf);
        int rc = pub ? mfi_ecdsa_verify_digest(pub, digest, sizeof digest, der, der_len)
                     : MFI_ERR_CRYPTO;
        EVP_PKEY_free(pub);
        if (rc != MFI_OK) {
            if (err)
                snprintf(err, errlen, "signature does not verify with the certificate key");
            return MFI_ERR_AUTH_FAILED;
        }
    }
    return MFI_OK;
}

static int raw_to_der(const uint8_t raw[64], uint8_t *der, size_t cap, size_t *der_len)
{
    /* Minimal DER SEQUENCE { INTEGER r, INTEGER s } encoder (P-256 sizes). */
    uint8_t body[72];
    size_t off = 0;

    body[off++] = 0x02;
    {
        const uint8_t *r = raw;
        size_t len = 32;
        while (len > 1 && r[0] == 0) {
            r++;
            len--;
        }
        if (r[0] & 0x80) {
            body[off++] = (uint8_t)(len + 1);
            body[off++] = 0x00;
        } else {
            body[off++] = (uint8_t)len;
        }
        memcpy(body + off, r, len);
        off += len;
    }
    body[off++] = 0x02;
    {
        const uint8_t *s = raw + 32;
        size_t len = 32;
        while (len > 1 && s[0] == 0) {
            s++;
            len--;
        }
        if (s[0] & 0x80) {
            body[off++] = (uint8_t)(len + 1);
            body[off++] = 0x00;
        } else {
            body[off++] = (uint8_t)len;
        }
        memcpy(body + off, s, len);
        off += len;
    }
    if (off + 2 > cap)
        return MFI_ERR_ARG;
    der[0] = 0x30;
    der[1] = (uint8_t)off;
    memcpy(der + 2, body, off);
    *der_len = off + 2;
    return MFI_OK;
}

int mfi_identity_sign_digest(mfi_identity *id, const uint8_t *digest, size_t digest_len,
                             uint8_t *der, size_t der_cap, size_t *der_len)
{
    if (!id || !id->key)
        return MFI_ERR_ARG;
    return mfi_ecdsa_sign_digest(id->key, digest, digest_len, der, der_cap, der_len);
}

int mfi_identity_verify_digest(mfi_identity *id, const uint8_t *digest, size_t digest_len,
                               const uint8_t raw_sig[64])
{
    uint8_t der[80];
    size_t der_len = 0;
    EVP_PKEY *pub;
    int rc;

    if (!id || !digest || !raw_sig)
        return MFI_ERR_ARG;
    if (raw_to_der(raw_sig, der, sizeof der, &der_len) != MFI_OK)
        return MFI_ERR_ARG;
    pub = X509_get_pubkey(id->leaf);
    if (!pub)
        return MFI_ERR_CRYPTO;
    rc = mfi_ecdsa_verify_digest(pub, digest, digest_len, der, der_len);
    EVP_PKEY_free(pub);
    return rc;
}

int mfi_identity_describe(mfi_identity *id, char *buf, size_t cap)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char subject[256] = "?";
    char issuer[256] = "?";
    char serial[80] = "?";
    ASN1_INTEGER *asn1_serial;

    if (!id || !buf || cap == 0)
        return MFI_ERR_ARG;

    X509_NAME_oneline(X509_get_subject_name(id->leaf), subject, sizeof subject);
    X509_NAME_oneline(X509_get_issuer_name(id->leaf), issuer, sizeof issuer);
    asn1_serial = X509_get_serialNumber(id->leaf);
    if (asn1_serial) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(asn1_serial, NULL);
        char *str = bn ? BN_bn2hex(bn) : NULL;
        if (str) {
            snprintf(serial, sizeof serial, "%s", str);
            OPENSSL_free(str);
        }
        BN_free(bn);
    }
    X509_digest(id->leaf, EVP_sha256(), digest, NULL);
    mfi_hex_encode(digest, sizeof digest, hex, sizeof hex);

    snprintf(buf, cap,
             "subject: %s\nissuer:  %s\nserial:  %s\nsha256:  %s\ncontainer-bytes: %zu\n",
             subject, issuer, serial, hex, id->cert_len);
    return MFI_OK;
}
