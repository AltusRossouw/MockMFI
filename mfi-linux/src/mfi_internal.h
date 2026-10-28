#ifndef MFI_INTERNAL_H
#define MFI_INTERNAL_H

#include "mfi/mfi.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

struct mfi_identity {
    EVP_PKEY *key;
    X509 *leaf;
    uint8_t *cert; /* container bytes presented on the wire */
    size_t cert_len;
};

/* Logging is optional everywhere; this keeps the format uniform. */
void mfi_log(mfi_log_fn log, void *ctx, const char *fmt, ...);

/* Internal link wrapper (opaque in the public header). */
struct mfi_link {
    mfi_link_ops ops;
};

/* Shared helpers used by several translation units. */
int mfi_identity_create_from_memory(mfi_identity **out, const uint8_t *pk8, size_t pk8_len,
                                    const uint8_t *cert, size_t cert_len, char *err, size_t errlen);

#endif /* MFI_INTERNAL_H */
