/*
 * mfid — MFi accessory authentication daemon / diagnostic tool.
 *
 *   mfid [options] selftest
 *   mfid [options] cert
 *   mfid [options] sign <32-byte-digest-hex>
 *   mfid [options] sap <body-hex>
 *   mfid [options] vectors
 *   mfid [options] discover
 *   mfid [options] serve --serial /dev/ttyUSB0 --baud 115200
 *   mfid [options] serve --pty
 *   mfid [options] serve --fd 3
 */
#include "mfi/mfi.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verbose;

static void log_line(void *ctx, const char *fmt, ...)
{
    va_list ap;
    (void)ctx;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    (void)verbose;
}

static void usage(FILE *out)
{
    fprintf(out,
            "mfid %s — MFi accessory authentication for Linux vehicle hosts\n"
            "\n"
            "Usage: mfid [options] <command> [args]\n"
            "\n"
            "Options:\n"
            "  --identity DIR   identity directory with identity.pk8 + certificate.p7b\n"
            "                   (default: ./identity, then /etc/mfi)\n"
            "  --target T       local (software signer, default), i2c, or sim\n"
            "  --i2c DEV        I2C device for --target i2c (default /dev/i2c-1)\n"
            "  --addr N         coprocessor address (decimal or 0x..; default: discover)\n"
            "  -v, --verbose    log protocol progress\n"
            "\n"
            "Commands:\n"
            "  selftest         sign/verify, CSM round trip, SAP round trip, coprocessor path\n"
            "  cert             print the certificate that will be presented\n"
            "  sign HEX          sign a 32-byte digest (returns 64-byte r||s hex)\n"
            "  sap HEX          process an /auth-setup body (33 bytes) and print the reply\n"
            "  verify DIGEST SIG verify a 64-byte raw signature over a 32-byte digest\n"
            "  vectors          print deterministic wire vectors\n"
            "  discover         probe a coprocessor at 0x10 / 0x11\n"
            "  net              serve the LIVI mfid TCP coprocessor protocol\n"
            "      --bind ADDR --port N     listen address (default 0.0.0.0:5000)\n"
            "  serve            answer iAP2 AccAuthentication on a link\n"
            "      --serial PATH --baud N   open a UART\n"
            "      --pty                    create a PTY and print the slave path\n"
            "      --fd N                   use an inherited descriptor\n"
            "      --timeout MS             per-exchange budget (default 30000)\n"
            "      --once                   exit after one completed exchange\n",
            MFI_VERSION_STRING);
}

typedef struct {
    const char *identity_dir;
    const char *target;
    const char *i2c_device;
    int addr;
    const char *serial;
    const char *bind_addr;
    int port;
    int baud;
    int use_pty;
    int fd;
    int timeout_ms;
    int once;
    int verbose;
} options;

static int build_auth(options *o, mfi_auth **auth, mfi_i2c_io **io_out, char *err, size_t errlen)
{
    *auth = NULL;
    if (io_out)
        *io_out = NULL;

    if (strcmp(o->target, "local") == 0) {
        mfi_identity *id = NULL;
        if (mfi_identity_load_dir(&id, o->identity_dir, err, errlen) != MFI_OK) {
            /* A bare DER certificate next to a .key is also accepted. */
            char key[1024], cert[1024];
            snprintf(key, sizeof key, "%s/identity.pk8", o->identity_dir);
            snprintf(cert, sizeof cert, "%s/certificate.der", o->identity_dir);
            if (mfi_identity_load_files(&id, key, cert, err, errlen) != MFI_OK)
                return MFI_ERR_IO;
        }
        return mfi_auth_local_create(auth, id, err, errlen);
    }

    if (strcmp(o->target, "sim") == 0) {
        mfi_i2c_io *io = NULL;
        if (mfi_cp_sim_create(&io, o->identity_dir, err, errlen) != MFI_OK)
            return MFI_ERR_IO;
        if (io_out) {
            *io_out = io;
            return MFI_OK;
        }
        mfi_auth *cp = NULL;
        int rc = mfi_cp_create(&cp, io, o->addr, err, errlen);
        if (rc != MFI_OK) {
            if (io->destroy)
                io->destroy(io->ctx);
            free(io);
            return rc;
        }
        *auth = cp;
        return MFI_OK;
    }

    if (strcmp(o->target, "i2c") == 0) {
        mfi_i2c_io *io = NULL;
        if (mfi_i2c_linux_open(&io, o->i2c_device, err, errlen) != MFI_OK)
            return MFI_ERR_IO;
        if (io_out) {
            *io_out = io;
            return MFI_OK;
        }
        {
            mfi_auth *cp = NULL;
            int rc = mfi_cp_create(&cp, io, o->addr, err, errlen);
            if (rc != MFI_OK) {
                if (io->destroy)
                    io->destroy(io->ctx);
                free(io);
                return rc;
            }
            *auth = cp;
        }
        return MFI_OK;
    }

    snprintf(err, errlen, "unknown target '%s' (local, i2c, sim)", o->target);
    return MFI_ERR_ARG;
}

static int cmd_selftest(options *o)
{
    char err[256];
    mfi_auth *auth = NULL;
    uint8_t cert[MFI_MAX_CERTIFICATE];
    size_t cert_len = 0;
    uint8_t digest[32], sig[128];
    size_t sig_len = 0;
    int failures = 0;

    if (build_auth(o, &auth, NULL, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "build authenticator: %s\n", err);
        return 1;
    }

    printf("authenticator: %s\n", auth->name);
    printf("protocol major: %d\n", auth->protocol_major(auth));

    if (auth->read_certificate(auth, cert, sizeof cert, &cert_len) == MFI_OK && cert_len) {
        printf("certificate: %zu bytes (sha256 ", cert_len);
        {
            const uint8_t *parts[1] = {cert};
            size_t lens[1] = {cert_len};
            uint8_t d[32];
            char hex[65];
            if (mfi_sha256(parts, lens, 1, d) == MFI_OK) {
                mfi_hex_encode(d, sizeof d, hex, sizeof hex);
                printf("%s", hex);
            }
        }
        printf(")\n");
    } else {
        printf("certificate: FAILED\n");
        failures++;
    }

    if (mfi_random(digest, sizeof digest) != MFI_OK) {
        printf("random: FAILED\n");
        failures++;
    } else if (auth->sign_challenge(auth, digest, sizeof digest, sig, sizeof sig, &sig_len) !=
               MFI_OK) {
        printf("sign: FAILED\n");
        failures++;
    } else {
        char hex[129];
        mfi_hex_encode(sig, sig_len, hex, sizeof hex);
        printf("sign: %zu bytes r||s %s\n", sig_len, hex);
        if (sig_len != 64)
            failures++;
    }

    /* CSM round trip. */
    {
        uint8_t frame[128];
        size_t n = mfi_iap2_build_request_challenge(frame, sizeof frame, digest, sizeof digest);
        mfi_csm_message msg;
        if (!n || mfi_csm_decode(frame, n, &msg, err, sizeof err) != MFI_OK) {
            printf("csm: FAILED (%s)\n", err);
            failures++;
        } else if (msg.msgid != MFI_IAP2_REQUEST_CHALLENGE || msg.param_count != 1) {
            printf("csm: FAILED (unexpected shape)\n");
            failures++;
        } else {
            printf("csm: frame %zu bytes, message 0x%04x, 1 parameter\n", n, msg.msgid);
        }
    }

    /* /auth-setup round trip: simulate the phone with the same X25519 and
     * AES-CTR derivations, then verify the decrypted signature. */
    {
        uint8_t phone_priv[32], phone_pub[32];
        uint8_t body[33];
        uint8_t reply[MFI_MAX_CERTIFICATE + 256];
        size_t reply_len;
        for (size_t i = 0; i < 32; i++)
            phone_priv[i] = (uint8_t)(0x40 + i);
        if (mfi_x25519_public(phone_priv, phone_pub) != MFI_OK) {
            printf("sap: FAILED (x25519)\n");
            failures++;
        } else {
            body[0] = MFI_SAP_VERSION;
            memcpy(body + 1, phone_pub, 32);
            reply_len = mfi_sap_handle(auth, body, sizeof body, reply, sizeof reply);
            if (!reply_len) {
                printf("sap: FAILED (no reply)\n");
                failures++;
            } else {
                uint8_t shared[32], key[16], iv[16], plain[128];
                const uint8_t *kp[2];
                size_t kl[2];
                uint8_t h[20];
                size_t off = 32;
                uint32_t cert_n = ((uint32_t)reply[off] << 24) | ((uint32_t)reply[off + 1] << 16) |
                                  ((uint32_t)reply[off + 2] << 8) | reply[off + 3];
                uint32_t enc_n;
                off += 4 + cert_n;
                enc_n = ((uint32_t)reply[off] << 24) | ((uint32_t)reply[off + 1] << 16) |
                        ((uint32_t)reply[off + 2] << 8) | reply[off + 3];
                off += 4;
                if (cert_n == cert_len && enc_n == sig_len &&
                    mfi_x25519_shared(phone_priv, reply, shared) == MFI_OK) {
                    uint8_t digest2[32];
                    const uint8_t *dp[2] = {reply, phone_pub};
                    size_t dl[2] = {32, 32};
                    kp[0] = (const uint8_t *)"AES-KEY";
                    kp[1] = shared;
                    kl[0] = 7;
                    kl[1] = 32;
                    mfi_sha1(kp, kl, 2, h);
                    memcpy(key, h, 16);
                    kp[0] = (const uint8_t *)"AES-IV";
                    kl[0] = 6;
                    mfi_sha1(kp, kl, 2, h);
                    memcpy(iv, h, 16);
                    mfi_aes128_ctr(key, iv, reply + off, enc_n, plain);
                    mfi_sha256(dp, dl, 2, digest2);
                    {
                        mfi_identity *vid = NULL;
                        int verified = 0;
                        if (mfi_identity_load_dir(&vid, o->identity_dir, err, sizeof err) == MFI_OK) {
                            verified = mfi_identity_verify_digest(vid, digest2, sizeof digest2,
                                                                  plain) == MFI_OK;
                            mfi_identity_free(vid);
                        }
                        printf("sap: reply %zu bytes, cert %u, signature %u (%s)\n", reply_len,
                               cert_n, enc_n, verified ? "verified" : "NOT verified");
                        if (!verified)
                            failures++;
                    }
                } else {
                    printf("sap: FAILED (reply layout)\n");
                    failures++;
                }
            }
        }
    }

    /* Coprocessor register path against the software coprocessor. */
    {
        mfi_i2c_io *io = NULL;
        if (mfi_cp_sim_create(&io, o->identity_dir, err, sizeof err) == MFI_OK) {
            mfi_auth *cp = NULL;
            if (mfi_cp_create(&cp, io, -1, err, sizeof err) == MFI_OK) {
                uint8_t cp_cert[MFI_MAX_CERTIFICATE];
                size_t cp_len = 0;
                uint8_t cp_sig[128];
                size_t cp_sig_len = 0;
                if (cp->read_certificate(cp, cp_cert, sizeof cp_cert, &cp_len) == MFI_OK &&
                    cp_len == cert_len && cp->protocol_major(cp) == 3 &&
                    cp->sign_challenge(cp, digest, 32, cp_sig, sizeof cp_sig, &cp_sig_len) ==
                        MFI_OK &&
                    cp_sig_len == 64) {
                    printf("coprocessor: discovery + certificate + sign OK\n");
                } else {
                    printf("coprocessor: FAILED\n");
                    failures++;
                }
                cp->destroy(cp);
            } else {
                printf("coprocessor: FAILED (%s)\n", err);
                failures++;
            }
        } else {
            printf("coprocessor: FAILED (%s)\n", err);
            failures++;
        }
    }

    auth->destroy(auth);
    printf("%s\n", failures ? "FAILED" : "PASS");
    return failures ? 1 : 0;
}

static int cmd_cert(options *o)
{
    char err[256];
    mfi_identity *id = NULL;
    char text[2048];

    if (mfi_identity_load_dir(&id, o->identity_dir, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "load identity: %s\n", err);
        return 1;
    }
    if (mfi_identity_describe(id, text, sizeof text) != MFI_OK) {
        mfi_identity_free(id);
        return 1;
    }
    printf("%s", text);
    mfi_identity_free(id);
    return 0;
}

static int cmd_sign(options *o, const char *hex)
{
    char err[256];
    uint8_t digest[64];
    size_t digest_len = mfi_hex_decode(hex, digest, sizeof digest);
    mfi_auth *auth = NULL;
    uint8_t sig[128];
    size_t sig_len = 0;
    char out[257];

    if (digest_len != 32) {
        fprintf(stderr, "sign takes a 32-byte digest in hex (%zu bytes given)\n", digest_len);
        return 1;
    }
    if (build_auth(o, &auth, NULL, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "build authenticator: %s\n", err);
        return 1;
    }
    if (auth->sign_challenge(auth, digest, digest_len, sig, sizeof sig, &sig_len) != MFI_OK) {
        fprintf(stderr, "sign failed\n");
        auth->destroy(auth);
        return 1;
    }
    mfi_hex_encode(sig, sig_len, out, sizeof out);
    printf("%s\n", out);
    auth->destroy(auth);
    return 0;
}

static int cmd_verify(options *o, const char *digest_hex, const char *sig_hex)
{
    char err[256];
    uint8_t digest[64], sig[64];
    size_t digest_len = mfi_hex_decode(digest_hex, digest, sizeof digest);
    size_t sig_len = mfi_hex_decode(sig_hex, sig, sizeof sig);
    mfi_identity *id = NULL;
    int rc;

    if (digest_len != 32 || sig_len != 64) {
        fprintf(stderr, "verify takes a 32-byte digest and a 64-byte raw signature in hex\n");
        return 1;
    }
    if (mfi_identity_load_dir(&id, o->identity_dir, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "load identity: %s\n", err);
        return 1;
    }
    rc = mfi_identity_verify_digest(id, digest, digest_len, sig);
    mfi_identity_free(id);
    if (rc == MFI_OK) {
        printf("valid\n");
        return 0;
    }
    printf("invalid\n");
    return 1;
}

static int cmd_sap(options *o, const char *hex)
{
    char err[256];
    uint8_t body[256];
    size_t body_len = mfi_hex_decode(hex, body, sizeof body);
    mfi_auth *auth = NULL;
    uint8_t *reply;
    size_t reply_len;
    char *out;
    size_t out_cap = (MFI_MAX_CERTIFICATE + 256) * 2 + 16;

    if (body_len == 0) {
        fprintf(stderr, "sap takes the /auth-setup body as hex\n");
        return 1;
    }
    if (build_auth(o, &auth, NULL, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "build authenticator: %s\n", err);
        return 1;
    }
    reply = malloc(MFI_MAX_CERTIFICATE + 256);
    out = malloc(out_cap);
    if (!reply || !out) {
        free(reply);
        free(out);
        auth->destroy(auth);
        return 1;
    }
    reply_len = mfi_sap_handle(auth, body, body_len, reply, MFI_MAX_CERTIFICATE + 256);
    if (!reply_len) {
        printf("rejected\n");
        free(reply);
        free(out);
        auth->destroy(auth);
        return 2;
    }
    mfi_hex_encode(reply, reply_len, out, out_cap);
    printf("%s\n", out);
    free(reply);
    free(out);
    auth->destroy(auth);
    return 0;
}

static int cmd_vectors(void)
{
    uint8_t frame[512];
    uint8_t digest[32];
    uint8_t peer_priv[32], peer_pub[32];
    char hex[2048];

    for (size_t i = 0; i < 32; i++) {
        digest[i] = (uint8_t)i;
        peer_priv[i] = (uint8_t)(0x80 + i);
    }
    mfi_x25519_public(peer_priv, peer_pub);

    printf("# iAP2 AccAuthentication frames (CSM 0x4040)\n");
    {
        size_t n = mfi_iap2_build_request_certificate(frame, sizeof frame);
        mfi_hex_encode(frame, n, hex, sizeof hex);
        printf("aa00.request-certificate  %s\n", hex);
    }
    {
        uint8_t cert[4] = {0xde, 0xad, 0xbe, 0xef};
        size_t n = mfi_iap2_build_certificate(frame, sizeof frame, cert, sizeof cert);
        mfi_hex_encode(frame, n, hex, sizeof hex);
        printf("aa01.certificate(4B)     %s\n", hex);
    }
    {
        size_t n = mfi_iap2_build_request_challenge(frame, sizeof frame, digest, sizeof digest);
        mfi_hex_encode(frame, n, hex, sizeof hex);
        printf("aa02.request-challenge   %s\n", hex);
    }
    {
        uint8_t sig[64];
        for (size_t i = 0; i < 64; i++)
            sig[i] = (uint8_t)(0xa0 + i);
        size_t n = mfi_iap2_build_response(frame, sizeof frame, sig, sizeof sig);
        mfi_hex_encode(frame, n, hex, sizeof hex);
        printf("aa03.response(64B)       %s\n", hex);
    }
    {
        size_t n = mfi_iap2_build_success(frame, sizeof frame);
        mfi_hex_encode(frame, n, hex, sizeof hex);
        printf("aa05.succeeded           %s\n", hex);
    }
    {
        uint8_t body[33];
        body[0] = 1;
        memcpy(body + 1, peer_pub, 32);
        mfi_hex_encode(body, sizeof body, hex, sizeof hex);
        printf("sap.body                 %s\n", hex);
    }
    printf("# /auth-setup replies depend on the identity certificate; use `mfid sap`.\n");
    return 0;
}

static int cmd_discover(options *o)
{
    char err[256];
    mfi_i2c_io *io = NULL;
    int addr = -1;
    uint8_t version = 0;

    if (build_auth(o, NULL, &io, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "open transport: %s\n", err);
        return 1;
    }
    if (mfi_cp_discover(io, 2000, &addr, &version, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "discover: %s\n", err);
        if (io->destroy)
            io->destroy(io->ctx);
        free(io);
        return 1;
    }
    printf("coprocessor at 0x%02x, device version 0x%02x\n", addr, version);
    if (io->destroy)
        io->destroy(io->ctx);
    free(io);
    return 0;
}

static int cmd_serve(options *o)
{
    char err[256];
    mfi_auth *auth = NULL;
    mfi_link *link = NULL;
    int rc;

    if (build_auth(o, &auth, NULL, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "build authenticator: %s\n", err);
        return 1;
    }
    if (o->use_pty) {
        char slave[256];
        if (mfi_link_pty(&link, slave, sizeof slave, err, sizeof err) != MFI_OK) {
            fprintf(stderr, "pty: %s\n", err);
            auth->destroy(auth);
            return 1;
        }
        printf("%s\n", slave);
        fflush(stdout);
    } else if (o->serial) {
        if (mfi_link_serial(&link, o->serial, o->baud, err, sizeof err) != MFI_OK) {
            fprintf(stderr, "serial: %s\n", err);
            auth->destroy(auth);
            return 1;
        }
    } else if (o->fd >= 0) {
        if (mfi_link_fd(&link, o->fd, 0, err, sizeof err) != MFI_OK) {
            fprintf(stderr, "fd: %s\n", err);
            auth->destroy(auth);
            return 1;
        }
    } else {
        fprintf(stderr, "serve needs --serial PATH, --pty or --fd N\n");
        auth->destroy(auth);
        return 1;
    }

    do {
        rc = mfi_iap2_authenticate(auth, link, o->timeout_ms, o->verbose ? log_line : NULL, NULL,
                                   err, sizeof err);
        if (rc == MFI_OK) {
            fprintf(stderr, "authentication succeeded\n");
        } else {
            fprintf(stderr, "authentication: %s\n", err);
        }
    } while (!o->once && rc != MFI_ERR_IO);

    mfi_link_free(link);
    auth->destroy(auth);
    return rc == MFI_OK ? 0 : 1;
}

static volatile int g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int cmd_net(options *o)
{
    char err[256];
    mfi_auth *auth = NULL;

    if (build_auth(o, &auth, NULL, err, sizeof err) != MFI_OK) {
        fprintf(stderr, "build authenticator: %s\n", err);
        return 1;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    if (mfi_mfid_serve(auth, o->bind_addr, o->port, &g_stop, o->verbose ? log_line : NULL, NULL, err,
                       sizeof err) != MFI_OK) {
        fprintf(stderr, "mfid service: %s\n", err);
        auth->destroy(auth);
        return 1;
    }
    auth->destroy(auth);
    return 0;
}

int main(int argc, char **argv)
{
    options o;
    const char *command = NULL;
    const char *rest[4] = {0};
    int nrest = 0;
    char err[256];

    memset(&o, 0, sizeof o);
    o.target = "local";
    o.i2c_device = "/dev/i2c-1";
    o.addr = -1;
    o.baud = 115200;
    o.fd = -1;
    o.timeout_ms = MFI_IAP2_DEFAULT_TIMEOUT_MS;
    o.bind_addr = "0.0.0.0";
    o.port = MFI_MFID_DEFAULT_PORT;
    o.identity_dir = getenv("MFI_IDENTITY_DIR");
    if (!o.identity_dir)
        o.identity_dir = "./identity";

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--identity") == 0 && i + 1 < argc) {
            o.identity_dir = argv[++i];
        } else if (strcmp(a, "--target") == 0 && i + 1 < argc) {
            o.target = argv[++i];
        } else if (strcmp(a, "--i2c") == 0 && i + 1 < argc) {
            o.i2c_device = argv[++i];
        } else if (strcmp(a, "--addr") == 0 && i + 1 < argc) {
            o.addr = (int)strtol(argv[++i], NULL, 0);
        } else if (strcmp(a, "--bind") == 0 && i + 1 < argc) {
            o.bind_addr = argv[++i];
        } else if (strcmp(a, "--port") == 0 && i + 1 < argc) {
            o.port = atoi(argv[++i]);
        } else if (strcmp(a, "--serial") == 0 && i + 1 < argc) {
            o.serial = argv[++i];
        } else if (strcmp(a, "--baud") == 0 && i + 1 < argc) {
            o.baud = atoi(argv[++i]);
        } else if (strcmp(a, "--pty") == 0) {
            o.use_pty = 1;
        } else if (strcmp(a, "--fd") == 0 && i + 1 < argc) {
            o.fd = atoi(argv[++i]);
        } else if (strcmp(a, "--timeout") == 0 && i + 1 < argc) {
            o.timeout_ms = atoi(argv[++i]);
        } else if (strcmp(a, "--once") == 0) {
            o.once = 1;
        } else if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) {
            o.verbose = 1;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (!command) {
            command = a;
        } else if (nrest < 4) {
            rest[nrest++] = a;
        } else {
            fprintf(stderr, "unexpected argument '%s'\n", a);
            usage(stderr);
            return 2;
        }
    }

    if (!command) {
        usage(stderr);
        return 2;
    }
    if (strcmp(command, "selftest") == 0)
        return cmd_selftest(&o);
    if (strcmp(command, "cert") == 0)
        return cmd_cert(&o);
    if (strcmp(command, "sign") == 0) {
        if (nrest < 1) {
            usage(stderr);
            return 2;
        }
        return cmd_sign(&o, rest[0]);
    }
    if (strcmp(command, "verify") == 0) {
        if (nrest < 2) {
            usage(stderr);
            return 2;
        }
        return cmd_verify(&o, rest[0], rest[1]);
    }
    if (strcmp(command, "sap") == 0) {
        if (nrest < 1) {
            usage(stderr);
            return 2;
        }
        return cmd_sap(&o, rest[0]);
    }
    if (strcmp(command, "vectors") == 0)
        return cmd_vectors();
    if (strcmp(command, "discover") == 0)
        return cmd_discover(&o);
    if (strcmp(command, "net") == 0)
        return cmd_net(&o);
    if (strcmp(command, "serve") == 0)
        return cmd_serve(&o);

    (void)err;
    fprintf(stderr, "unknown command '%s'\n", command);
    usage(stderr);
    return 2;
}
