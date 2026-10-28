/*
 * libmfi — MFi accessory authentication for Linux vehicle hosts.
 *
 * This is an independent implementation of the accessory side of the two
 * authentication exchanges a CarPlay/iAP2 accessory must answer, plus the
 * register-level driver for an MFi authentication coprocessor:
 *
 *   - iAP2 AccAuthentication   0xAA00 .. 0xAA06  (CSM framed)
 *   - AirPlay /auth-setup      MFiSAP v1, X25519 + AES-128-CTR
 *   - MFi coprocessor          register map over an I2C transaction backend
 *
 * Wire formats follow the shipped DiPlay 0.2.22 code (classes3.dex), recorded
 * in spec/05-rea-shipped-dex.md.  The library is transport agnostic: the host
 * supplies either an identity directory (software signer), an I2C backend
 * (hardware coprocessor) or its own mfi_auth implementation.
 */
#ifndef MFI_MFI_H
#define MFI_MFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MFI_VERSION_STRING "1.0.0"

#define MFI_MAX_CERTIFICATE 65525
#define MFI_MAX_CHALLENGE 128
#define MFI_MAX_SIGNATURE 128
#define MFI_MAX_CSM_FRAME 65535

/* iAP2 AccAuthentication message ids. */
#define MFI_IAP2_REQUEST_CERTIFICATE 0xAA00u
#define MFI_IAP2_CERTIFICATE 0xAA01u
#define MFI_IAP2_REQUEST_CHALLENGE 0xAA02u
#define MFI_IAP2_RESPONSE 0xAA03u
#define MFI_IAP2_AUTHENTICATION_FAILED 0xAA04u
#define MFI_IAP2_AUTHENTICATION_SUCCEEDED 0xAA05u
#define MFI_IAP2_CERTIFICATE_SERIAL 0xAA06u

/* Defaults observed in the shipped app. */
#define MFI_IAP2_DEFAULT_TIMEOUT_MS 30000
#define MFI_IAP2_MAX_TIMEOUT_MS 300000
#define MFI_SAP_VERSION 1
#define MFI_SAP_BODY_BYTES 33 /* version + 32-byte X25519 public key */
#define MFI_SAP_PUBLIC_KEY_BYTES 32

/* Error codes.  All functions that can fail return 0 on success. */
enum {
    MFI_OK = 0,
    MFI_ERR_ARG = -1,
    MFI_ERR_IO = -2,
    MFI_ERR_CRYPTO = -3,
    MFI_ERR_FORMAT = -4,
    MFI_ERR_STATE = -5,
    MFI_ERR_TIMEOUT = -6,
    MFI_ERR_NOMEM = -7,
    MFI_ERR_UNSUPPORTED = -8,
    MFI_ERR_AUTH_FAILED = -9
};

typedef enum {
    MFI_CERT_TYPE_MFI = 0,
    MFI_CERT_TYPE_BAA = 1
} mfi_cert_type;

typedef void (*mfi_log_fn)(void *ctx, const char *fmt, ...);

/* ------------------------------------------------------------------ */
/* Authenticator contract (DiPlay: com.shilapi.xcertplay.mfi.MfiAuthenticator) */
/* ------------------------------------------------------------------ */

typedef struct mfi_auth mfi_auth;

struct mfi_auth {
    const char *name;
    mfi_cert_type cert_type;

    /* Raw protocol major byte reported to the phone (2, 3, ...).  The local
     * software identity reports 3; a coprocessor reports its own value. */
    int (*protocol_major)(mfi_auth *self);

    /* Copy the certificate container presented in iAP2 0xAA01 / MFiSAP.
     * For an MFi identity this is the PKCS#7 blob exactly as shipped. */
    int (*read_certificate)(mfi_auth *self, uint8_t *out, size_t cap, size_t *len);

    /* Sign a challenge.  The software and coprocessor paths take the input as
     * an already-computed digest (OpenSSL "NONEwithECDSA" semantics) and return
     * a 64-byte raw r||s for a P-256 identity. */
    int (*sign_challenge)(mfi_auth *self, const uint8_t *challenge, size_t len,
                          uint8_t *sig, size_t cap, size_t *sig_len);

    /* BAA only: leaf + intermediate DER certificates. */
    int (*baa_certificates)(mfi_auth *self, const uint8_t **leaf, size_t *leaf_len,
                            const uint8_t **intermediate, size_t *intermediate_len);

    void (*destroy)(mfi_auth *self);
    void *ctx;
};

/* ------------------------------------------------------------------ */
/* Identity: PKCS#8 P-256 key + MFi certificate container              */
/* ------------------------------------------------------------------ */

typedef struct mfi_identity mfi_identity;

/* Load identity.pk8 + certificate.p7b from a directory (DiPlay layout). */
int mfi_identity_load_dir(mfi_identity **out, const char *dir, char *err, size_t errlen);
int mfi_identity_load_files(mfi_identity **out, const char *key_path, const char *cert_path,
                            char *err, size_t errlen);
int mfi_identity_load_memory(mfi_identity **out, const uint8_t *pk8, size_t pk8_len,
                             const uint8_t *cert, size_t cert_len, char *err, size_t errlen);
void mfi_identity_free(mfi_identity *id);

/* Sign a random 32-byte digest and verify it with the certificate public key.
 * Fails closed when the key and certificate do not match. */
int mfi_identity_self_test(mfi_identity *id, char *err, size_t errlen);

/* Certificate container exactly as it will be presented on the wire. */
int mfi_identity_certificate(mfi_identity *id, const uint8_t **data, size_t *len);

/* Human readable certificate summary (subject/issuer/serial/SHA-256). */
int mfi_identity_describe(mfi_identity *id, char *buf, size_t cap);

/* True when the leaf key is a P-256 key. */
int mfi_identity_is_p256(mfi_identity *id);

/* Sign a digest directly with the identity key (DER ECDSA, no re-hash). */
int mfi_identity_sign_digest(mfi_identity *id, const uint8_t *digest, size_t digest_len,
                             uint8_t *der, size_t der_cap, size_t *der_len);

/* Verify a 64-byte raw r||s signature over a 32-byte digest with the
 * certificate public key.  Useful for conformance checks on a host. */
int mfi_identity_verify_digest(mfi_identity *id, const uint8_t *digest, size_t digest_len,
                               const uint8_t raw_sig[64]);

/* ------------------------------------------------------------------ */
/* Local software authenticator                                        */
/* ------------------------------------------------------------------ */

/* Takes ownership of id on success and on failure (always freed). */
int mfi_auth_local_create(mfi_auth **out, mfi_identity *id, char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* ECDSA / X25519 / hashes                                             */
/* ------------------------------------------------------------------ */

int mfi_ecdsa_sign_digest(const void *pkey, const uint8_t *digest, size_t digest_len,
                          uint8_t *der, size_t der_cap, size_t *der_len);
int mfi_ecdsa_verify_digest(const void *pkey, const uint8_t *digest, size_t digest_len,
                            const uint8_t *der, size_t der_len);
/* DER ECDSA signature -> fixed 64-byte r||s (P-256). */
int mfi_ecdsa_der_to_raw(const uint8_t *der, size_t der_len, uint8_t out[64],
                         char *err, size_t errlen);

int mfi_x25519_keypair(uint8_t priv[32], uint8_t pub[32]);
int mfi_x25519_public(const uint8_t priv[32], uint8_t pub[32]);
int mfi_x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t shared[32]);

int mfi_sha1(const uint8_t *const *parts, const size_t *lens, size_t count, uint8_t out[20]);
int mfi_sha256(const uint8_t *const *parts, const size_t *lens, size_t count, uint8_t out[32]);
int mfi_aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                   const uint8_t *in, size_t len, uint8_t *out);

int mfi_random(uint8_t *buf, size_t len);
int mfi_const_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* ------------------------------------------------------------------ */
/* CSM framing (iAP2 control session multiplexer)                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t id;
    const uint8_t *data;
    size_t len;
} mfi_csm_param;

#define MFI_CSM_MAX_PARAMS 16

typedef struct {
    uint16_t msgid;
    size_t param_count;
    mfi_csm_param params[MFI_CSM_MAX_PARAMS];
} mfi_csm_message;

/* Encode one parameter body: u16 length | u16 parameter id | payload. */
size_t mfi_csm_encode_param(uint8_t *out, size_t cap, uint16_t id,
                            const uint8_t *payload, size_t len);

/* Encode a full frame: 0x4040 | u16 total length | u16 message id | params. */
size_t mfi_csm_encode_frame(uint8_t *out, size_t cap, uint16_t msgid,
                            const uint8_t *params, size_t params_len);

/* Decode exactly one complete frame.  *param_data points into frame. */
int mfi_csm_decode(const uint8_t *frame, size_t len, mfi_csm_message *out,
                   char *err, size_t errlen);

/* Incremental stream parser: tolerates garbage, chunking and concatenation. */
typedef int (*mfi_csm_frame_fn)(void *ctx, const uint8_t *frame, size_t len);

typedef struct {
    uint8_t buf[MFI_MAX_CSM_FRAME];
    size_t len;
} mfi_csm_parser;

void mfi_csm_parser_init(mfi_csm_parser *p);
/* Returns MFI_OK; check *frames_delivered.  The callback may return non-zero
 * to stop delivery (that value is returned with MFI_ERR_STATE). */
int mfi_csm_parser_feed(mfi_csm_parser *p, const uint8_t *data, size_t len,
                        mfi_csm_frame_fn cb, void *ctx, size_t *frames_delivered);

/* ------------------------------------------------------------------ */
/* iAP2 AccAuthentication responder                                    */
/* ------------------------------------------------------------------ */

/* Link: a byte stream carrying CSM frames (USB/BLE/UART/socket/PTY). */
typedef struct {
    /* Read at most cap bytes, waiting up to timeout_ms.  Returns MFI_OK and
     * sets *got (0 means the deadline expired), or an error. */
    int (*read)(void *ctx, uint8_t *buf, size_t cap, int timeout_ms, size_t *got);
    int (*write)(void *ctx, const uint8_t *buf, size_t len);
    void (*destroy)(void *ctx);
    void *ctx;
} mfi_link_ops;

typedef struct mfi_link mfi_link;

mfi_link *mfi_link_create(const mfi_link_ops *ops);
void mfi_link_free(mfi_link *link);

/* Run the accessory side of AccAuthentication to completion. */
int mfi_iap2_authenticate(mfi_auth *auth, mfi_link *link, int timeout_ms,
                          mfi_log_fn log, void *logctx, char *err, size_t errlen);

/* Frame builders (also used by tests/vector dumps). */
size_t mfi_iap2_build_certificate(uint8_t *out, size_t cap, const uint8_t *cert, size_t cert_len);
size_t mfi_iap2_build_certificate_baa(uint8_t *out, size_t cap, const uint8_t *leaf, size_t leaf_len,
                                      const uint8_t *intermediate, size_t intermediate_len);
size_t mfi_iap2_build_response(uint8_t *out, size_t cap, const uint8_t *sig, size_t sig_len);
size_t mfi_iap2_build_success(uint8_t *out, size_t cap);
size_t mfi_iap2_build_failure(uint8_t *out, size_t cap);
size_t mfi_iap2_build_request_certificate(uint8_t *out, size_t cap);
size_t mfi_iap2_build_request_challenge(uint8_t *out, size_t cap, const uint8_t *ch, size_t len);

/* Parameter 0 of a 0xAA02 frame; MFI_ERR_FORMAT when absent. */
int mfi_iap2_challenge(const mfi_csm_message *msg, const uint8_t **data, size_t *len);

/* ------------------------------------------------------------------ */
/* AirPlay /auth-setup (MFiSAP v1)                                     */
/* ------------------------------------------------------------------ */

/* Returns the response length, or 0 when the body must be rejected (the
 * caller should answer with an empty error response). */
size_t mfi_sap_handle(mfi_auth *auth, const uint8_t *body, size_t len,
                      uint8_t *out, size_t cap);
/* Deterministic variant used by tests: fixed X25519 private key. */
size_t mfi_sap_handle_deterministic(mfi_auth *auth, const uint8_t *body, size_t len,
                                    uint8_t *out, size_t cap, const uint8_t fixed_priv[32]);

/* OPACK object {"baIC": intermediate} used by the BAA response. */
size_t mfi_sap_encode_baa_intermediate(const uint8_t *intermediate, size_t len,
                                       uint8_t *out, size_t cap);

/* ------------------------------------------------------------------ */
/* Coprocessor register driver                                         */
/* ------------------------------------------------------------------ */

/* One I2C-style transaction: write wlen bytes, then read rlen bytes.
 * Returns MFI_OK, MFI_ERR_IO (NACK/timeout/ioctl failure) or MFI_ERR_ARG. */
typedef struct mfi_i2c_io mfi_i2c_io;

struct mfi_i2c_io {
    int (*transaction)(void *ctx, uint8_t addr7, const uint8_t *write_data, size_t write_len,
                       uint8_t *read_data, size_t read_len);
    void (*destroy)(void *ctx);
    void *ctx;
};

/* Hardware coprocessor behind an mfi_i2c_io.  addr7 may be -1 to discover. */
int mfi_cp_create(mfi_auth **out, mfi_i2c_io *io, int addr7, char *err, size_t errlen);

/* Discovery: probes 0x10 then 0x11, retried until timeout_ms. */
int mfi_cp_discover(mfi_i2c_io *io, int timeout_ms, int *addr7, uint8_t *version,
                    char *err, size_t errlen);

/* Linux /dev/i2c-N backend (10-bit unsafe, 7-bit addressing, no clock stretch
 * handling beyond the ioctl). */
int mfi_i2c_linux_open(mfi_i2c_io **out, const char *device, char *err, size_t errlen);

/* Software coprocessor that speaks the same register protocol, backed by an
 * identity directory.  Lets an accessory without a hardware CP exercise the
 * identical driver path, and is the fixture used by the test suite. */
int mfi_cp_sim_create(mfi_i2c_io **out, const char *identity_dir, char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* MFI-over-TCP coprocessor service (LIVI "mfid" protocol)             */
/* ------------------------------------------------------------------ */

/* LIVI's helperd talks to an MFi coprocessor over a small TCP protocol
 * (native/crates/iap2-mfi/src/{server,ncm}.rs):
 *
 *   request   1 byte op | for SIGN: u16 BE length | challenge
 *   response  1 byte status (0 ok, 1 error) | u16 BE length | payload
 *
 * ops: 0x01 get certificate, 0x02 sign, 0x03 protocol major.
 * Serving this turns a Linux box with libmfi into a network MFi
 * coprocessor for a head unit that has no I2C chip. */
#define MFI_MFID_OP_GET_CERT 0x01
#define MFI_MFID_OP_SIGN 0x02
#define MFI_MFID_OP_PROTOCOL_MAJOR 0x03
#define MFI_MFID_STATUS_OK 0x00
#define MFI_MFID_STATUS_ERR 0x01
#define MFI_MFID_DEFAULT_PORT 5000

/* One connection, until the peer closes it. */
int mfi_mfid_handle_connection(mfi_auth *auth, int fd);

/* Accept loop on bind_addr:port; returns when *stop becomes non-zero or the
 * listener fails.  Each connection is served on its own thread. */
int mfi_mfid_serve(mfi_auth *auth, const char *bind_addr, int port, volatile int *stop,
                   mfi_log_fn log, void *logctx, char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* Transports                                                          */
/* ------------------------------------------------------------------ */

int mfi_link_fd(mfi_link **out, int fd, int owns_fd, char *err, size_t errlen);
int mfi_link_serial(mfi_link **out, const char *path, int baud, char *err, size_t errlen);
/* Creates a PTY pair; writes the slave path the peer should open. */
int mfi_link_pty(mfi_link **out, char *slave_path, size_t path_len, char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

size_t mfi_hex_decode(const char *hex, uint8_t *out, size_t cap);
void mfi_hex_encode(const uint8_t *data, size_t len, char *out, size_t cap);
int mfi_read_file(const char *path, uint8_t **out, size_t *len, size_t max_len,
                  char *err, size_t errlen);
const char *mfi_strerror(int code);

#ifdef __cplusplus
}
#endif

#endif /* MFI_MFI_H */
