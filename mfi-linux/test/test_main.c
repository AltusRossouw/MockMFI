/* Test suite for libmfi.  No framework: each check prints a line and sets a
 * failure flag, so `make test` fails loudly in CI. */
#include "mfi/mfi.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;
static const char *identity_dir;

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            printf("ok   ");                                                                       \
        } else {                                                                                   \
            printf("FAIL ");                                                                       \
            failures++;                                                                            \
        }                                                                                          \
        printf(__VA_ARGS__);                                                                       \
        printf("\n");                                                                              \
    } while (0)

static void test_csm(void)
{
    uint8_t frame[128];
    mfi_csm_message msg;
    char err[128];
    uint8_t digest[32];

    for (size_t i = 0; i < sizeof digest; i++)
        digest[i] = (uint8_t)(i * 7);

    size_t n = mfi_iap2_build_request_certificate(frame, sizeof frame);
    CHECK(n == 6 && frame[0] == 0x40 && frame[1] == 0x40 && frame[4] == 0xaa && frame[5] == 0x00,
          "0xAA00 frame is 6 bytes");
    CHECK(mfi_csm_decode(frame, n, &msg, err, sizeof err) == MFI_OK && msg.msgid == 0xAA00 &&
              msg.param_count == 0,
          "0xAA00 decodes");

    n = mfi_iap2_build_request_challenge(frame, sizeof frame, digest, sizeof digest);
    CHECK(mfi_csm_decode(frame, n, &msg, err, sizeof err) == MFI_OK && msg.msgid == 0xAA02 &&
              msg.param_count == 1 && msg.params[0].id == 0 && msg.params[0].len == 32,
          "0xAA02 carries parameter 0 with 32 bytes");

    /* Truncated frame is rejected, not silently accepted. */
    CHECK(mfi_csm_decode(frame, n - 1, &msg, err, sizeof err) == MFI_ERR_FORMAT,
          "truncated frame rejected");

    /* Parser: garbage prefix, chunked delivery, two frames back to back. */
    {
        mfi_csm_parser p;
        uint8_t stream[160];
        size_t total = 0;
        size_t delivered = 0;
        size_t dummy = 0;

        stream[total++] = 0xde;
        stream[total++] = 0xad;
        stream[total++] = 0xbe;
        memcpy(stream + total, frame, n);
        total += n;
        memcpy(stream + total, frame, n);
        total += n;

        mfi_csm_parser_init(&p);
        for (size_t i = 0; i < total; i++) {
            CHECK(mfi_csm_parser_feed(&p, stream + i, 1, NULL, NULL, &dummy) == MFI_OK,
                  "parser byte %zu accepted", i);
            delivered += dummy;
        }
        CHECK(delivered == 2, "parser delivered 2 frames from %zu bytes (got %zu)", total,
              delivered);
    }
}

static void test_ecdsa(const char *dir)
{
    mfi_identity *id = NULL;
    char err[256];
    uint8_t digest[32], der[128], raw[64];
    size_t der_len = 0;

    CHECK(mfi_identity_load_dir(&id, dir, err, sizeof err) == MFI_OK, "identity loads (%s)", err);
    if (!id)
        return;
    CHECK(mfi_identity_self_test(id, err, sizeof err) == MFI_OK, "identity self test (%s)", err);
    CHECK(mfi_identity_is_p256(id), "identity key is P-256");

    for (size_t i = 0; i < sizeof digest; i++)
        digest[i] = (uint8_t)(0xa0 ^ i);
    CHECK(mfi_identity_sign_digest(id, digest, sizeof digest, der, sizeof der, &der_len) ==
              MFI_OK,
          "sign digest");
    CHECK(mfi_ecdsa_der_to_raw(der, der_len, raw, err, sizeof err) == MFI_OK,
          "DER to raw (%s)", err);
    CHECK(mfi_identity_verify_digest(id, digest, sizeof digest, raw) == MFI_OK,
          "raw signature verifies with the certificate key");

    /* Corruption must not verify. */
    raw[5] ^= 0x01;
    CHECK(mfi_identity_verify_digest(id, digest, sizeof digest, raw) != MFI_OK,
          "corrupted signature rejected");
    mfi_identity_free(id);
}

static void test_local_auth(const char *dir)
{
    mfi_identity *id = NULL;
    mfi_auth *auth = NULL;
    char err[256];
    uint8_t cert[MFI_MAX_CERTIFICATE];
    size_t cert_len = 0;
    uint8_t digest[32], sig[64];
    size_t sig_len = 0;

    CHECK(mfi_identity_load_dir(&id, dir, err, sizeof err) == MFI_OK, "identity reloads");
    if (!id)
        return;
    CHECK(mfi_auth_local_create(&auth, id, err, sizeof err) == MFI_OK, "local authenticator");
    if (!auth)
        return;
    CHECK(auth->protocol_major(auth) == 3, "local protocol major is 3");
    CHECK(auth->read_certificate(auth, cert, sizeof cert, &cert_len) == MFI_OK && cert_len > 0,
          "certificate available (%zu bytes)", cert_len);

    memset(digest, 0x5a, sizeof digest);
    CHECK(auth->sign_challenge(auth, digest, sizeof digest, sig, sizeof sig, &sig_len) == MFI_OK &&
              sig_len == 64,
          "sign returns 64-byte r||s");

    {
        uint8_t wrong[31];
        memset(wrong, 0, sizeof wrong);
        CHECK(auth->sign_challenge(auth, wrong, sizeof wrong, sig, sizeof sig, &sig_len) ==
                  MFI_ERR_FORMAT,
              "non-32-byte digest rejected");
    }
    auth->destroy(auth);
}

static void test_sap(const char *dir)
{
    mfi_identity *id = NULL, *verify_id = NULL;
    mfi_auth *auth = NULL;
    char err[256];
    uint8_t phone_priv[32], phone_pub[32];
    uint8_t fixed_priv[32];
    uint8_t body[33];
    uint8_t *reply;
    size_t reply_len;
    const size_t cap = MFI_MAX_CERTIFICATE + 256;

    CHECK(mfi_identity_load_dir(&id, dir, err, sizeof err) == MFI_OK, "identity for SAP");
    CHECK(mfi_identity_load_dir(&verify_id, dir, err, sizeof err) == MFI_OK, "verifier identity");
    if (!id || !verify_id)
        return;
    CHECK(mfi_auth_local_create(&auth, id, err, sizeof err) == MFI_OK, "SAP authenticator");
    if (!auth)
        return;

    for (size_t i = 0; i < 32; i++) {
        phone_priv[i] = (uint8_t)(0x11 * i + 3);
        fixed_priv[i] = (uint8_t)(0x20 + i);
    }
    CHECK(mfi_x25519_public(phone_priv, phone_pub) == MFI_OK, "phone X25519 key pair");

    body[0] = MFI_SAP_VERSION;
    memcpy(body + 1, phone_pub, 32);

    reply = malloc(cap);
    reply_len = mfi_sap_handle_deterministic(auth, body, sizeof body, reply, cap, fixed_priv);
    CHECK(reply_len > 64, "SAP reply produced (%zu bytes)", reply_len);

    if (reply_len) {
        uint8_t shared[32], key[16], iv[16], plain[128];
        const uint8_t *parts[2];
        size_t lens[2];
        uint8_t h[20];
        uint32_t cert_n, enc_n;
        size_t off = 32;

        cert_n = ((uint32_t)reply[off] << 24) | ((uint32_t)reply[off + 1] << 16) |
                 ((uint32_t)reply[off + 2] << 8) | reply[off + 3];
        off += 4;
        CHECK(reply_len == 40 + cert_n + 64 || cert_n > 0, "SAP reply carries certificate");
        off += cert_n;
        enc_n = ((uint32_t)reply[off] << 24) | ((uint32_t)reply[off + 1] << 16) |
                ((uint32_t)reply[off + 2] << 8) | reply[off + 3];
        off += 4;
        CHECK(enc_n == 64, "SAP reply carries a 64-byte encrypted signature");

        CHECK(mfi_x25519_shared(phone_priv, reply, shared) == MFI_OK, "phone derives shared secret");
        parts[0] = (const uint8_t *)"AES-KEY";
        parts[1] = shared;
        lens[0] = 7;
        lens[1] = 32;
        mfi_sha1(parts, lens, 2, h);
        memcpy(key, h, 16);
        parts[0] = (const uint8_t *)"AES-IV";
        lens[0] = 6;
        mfi_sha1(parts, lens, 2, h);
        memcpy(iv, h, 16);
        CHECK(mfi_aes128_ctr(key, iv, reply + off, enc_n, plain) == MFI_OK, "phone decrypts reply");

        {
            /* The digest the accessory signed: SHA-256(accessory pub || phone pub). */
            uint8_t digest[32];
            const uint8_t *dp[2];
            size_t dl[2];
            dp[0] = reply; /* accessory ephemeral public key */
            dp[1] = phone_pub;
            dl[0] = 32;
            dl[1] = 32;
            CHECK(mfi_sha256(dp, dl, 2, digest) == MFI_OK, "SAP digest computed");
            CHECK(mfi_identity_verify_digest(verify_id, digest, sizeof digest, plain) == MFI_OK,
                  "decrypted SAP signature verifies (protocol major 3 path)");
        }
    }

    /* Rejections. */
    {
        uint8_t bad[33];
        memcpy(bad, body, sizeof bad);
        bad[0] = 2;
        CHECK(mfi_sap_handle(auth, bad, sizeof bad, reply, cap) == 0, "SAP rejects version != 1");
        CHECK(mfi_sap_handle(auth, body, 32, reply, cap) == 0, "SAP rejects wrong length");
    }

    /* BAA intermediate encoding. */
    {
        uint8_t inter[300];
        uint8_t out[360];
        memset(inter, 0x31, sizeof inter);
        CHECK(mfi_sap_encode_baa_intermediate(inter, 32, out, sizeof out) == 7 + 32 &&
                  out[6] == (0x70 + 32),
              "baIC header for <=0x20 bytes");
        CHECK(mfi_sap_encode_baa_intermediate(inter, 200, out, sizeof out) == 8 + 200 &&
                  out[6] == 0x91 && out[7] == 200,
              "baIC header for <=0xff bytes");
        CHECK(mfi_sap_encode_baa_intermediate(inter, 300, out, sizeof out) == 9 + 300 &&
                  out[6] == 0x92 && out[7] == (300 & 0xff) && out[8] == (300 >> 8),
              "baIC header for <=0xffff bytes");
    }

    free(reply);
    auth->destroy(auth);
    mfi_identity_free(verify_id);
}

static void test_coprocessor(const char *dir)
{
    mfi_i2c_io *io = NULL;
    mfi_auth *cp = NULL;
    mfi_identity *id = NULL;
    char err[256];
    uint8_t cert[MFI_MAX_CERTIFICATE];
    size_t cert_len = 0;
    uint8_t expected[MFI_MAX_CERTIFICATE];
    size_t expected_len = 0;
    uint8_t digest[32], sig[64];
    size_t sig_len = 0;

    CHECK(mfi_cp_sim_create(&io, dir, err, sizeof err) == MFI_OK, "software coprocessor created");
    if (!io)
        return;
    CHECK(mfi_cp_create(&cp, io, -1, err, sizeof err) == MFI_OK, "coprocessor client (discovery)");
    if (!cp)
        return;
    CHECK(cp->protocol_major(cp) == 3, "coprocessor protocol major");
    CHECK(cp->read_certificate(cp, cert, sizeof cert, &cert_len) == MFI_OK, "coprocessor certificate");

    CHECK(mfi_identity_load_dir(&id, dir, err, sizeof err) == MFI_OK, "identity for comparison");
    if (id) {
        const uint8_t *bytes = NULL;
        if (mfi_identity_certificate(id, &bytes, &expected_len) == MFI_OK && expected_len) {
            memcpy(expected, bytes, expected_len);
            CHECK(cert_len == expected_len && memcmp(cert, expected, expected_len) == 0,
                  "coprocessor serves the same certificate container (%zu bytes)", cert_len);
        }
    }

    memset(digest, 0x33, sizeof digest);
    CHECK(cp->sign_challenge(cp, digest, sizeof digest, sig, sizeof sig, &sig_len) == MFI_OK &&
              sig_len == 64,
          "coprocessor signs a 32-byte digest");
    if (id)
        CHECK(mfi_identity_verify_digest(id, digest, sizeof digest, sig) == MFI_OK,
              "coprocessor signature verifies");

    {
        uint8_t bad[129];
        memset(bad, 0, sizeof bad);
        CHECK(cp->sign_challenge(cp, bad, sizeof bad, sig, sizeof sig, &sig_len) == MFI_ERR_FORMAT,
              "coprocessor rejects 129-byte challenge");
    }

    cp->destroy(cp); /* owns io */
    if (id)
        mfi_identity_free(id);
}

/* --- iAP2 end to end over a socket pair ------------------------------ */

typedef struct {
    mfi_auth *auth;
    mfi_link *link;
    int rc;
    char err[256];
} server_args;

static void *server_thread(void *arg)
{
    server_args *a = arg;
    a->rc = mfi_iap2_authenticate(a->auth, a->link, 5000, NULL, NULL, a->err, sizeof a->err);
    return NULL;
}

static int read_frame(int fd, mfi_csm_message *msg, uint8_t *buf, size_t cap)
{
    size_t have = 0;
    size_t total = 0;
    char err[128];

    while (have < 4 || have < total) {
        ssize_t n = read(fd, buf + have, cap - have);
        if (n <= 0)
            return -1;
        have += (size_t)n;
        if (have >= 4) {
            total = ((size_t)buf[2] << 8) | buf[3];
            if (total < 6 || total > cap)
                return -1;
        }
    }
    return mfi_csm_decode(buf, total, msg, err, sizeof err);
}

static int write_all_fd(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static void test_iap2_end_to_end(const char *dir)
{
    int sv[2];
    mfi_identity *id = NULL, *verify_id = NULL;
    mfi_auth *auth = NULL;
    mfi_link *link = NULL;
    char err[256];
    server_args args;
    pthread_t th;
    uint8_t frame[2048];
    mfi_csm_message msg;
    uint8_t digest[32];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socket pair");
    CHECK(mfi_identity_load_dir(&id, dir, err, sizeof err) == MFI_OK, "identity for iAP2");
    CHECK(mfi_identity_load_dir(&verify_id, dir, err, sizeof err) == MFI_OK, "verifier for iAP2");
    if (!id || !verify_id) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    CHECK(mfi_auth_local_create(&auth, id, err, sizeof err) == MFI_OK, "authenticator for iAP2");
    CHECK(mfi_link_fd(&link, sv[0], 1, err, sizeof err) == MFI_OK, "/fd link");
    if (!auth || !link)
        return;

    memset(&args, 0, sizeof args);
    args.auth = auth;
    args.link = link;
    pthread_create(&th, NULL, server_thread, &args);

    /* Phone: request certificate, read 0xAA01, request challenge, read 0xAA03. */
    {
        size_t n = mfi_iap2_build_request_certificate(frame, sizeof frame);
        CHECK(write_all_fd(sv[1], frame, n) == 0, "phone sends 0xAA00");
    }
    CHECK(read_frame(sv[1], &msg, frame, sizeof frame) == MFI_OK && msg.msgid == 0xAA01,
          "accessory answers 0xAA01");
    CHECK(msg.param_count == 1 && msg.params[0].id == 0 && msg.params[0].len > 0,
          "certificate parameter 0 present (%zu bytes)",
          msg.param_count ? msg.params[0].len : (size_t)0);

    for (size_t i = 0; i < sizeof digest; i++)
        digest[i] = (uint8_t)(0x77 + i);
    {
        size_t n = mfi_iap2_build_request_challenge(frame, sizeof frame, digest, sizeof digest);
        CHECK(write_all_fd(sv[1], frame, n) == 0, "phone sends 0xAA02");
    }
    CHECK(read_frame(sv[1], &msg, frame, sizeof frame) == MFI_OK && msg.msgid == 0xAA03,
          "accessory answers 0xAA03");
    CHECK(msg.param_count == 1 && msg.params[0].len == 64, "signature is 64 bytes");
    if (msg.param_count == 1 && msg.params[0].len == 64)
        CHECK(mfi_identity_verify_digest(verify_id, digest, sizeof digest, msg.params[0].data) ==
                  MFI_OK,
              "iAP2 signature verifies");

    {
        size_t n = mfi_iap2_build_success(frame, sizeof frame);
        CHECK(write_all_fd(sv[1], frame, n) == 0, "phone sends 0xAA05");
    }

    pthread_join(th, NULL);
    CHECK(args.rc == MFI_OK, "accessory reports success (%s)", args.err);

    mfi_link_free(link);
    auth->destroy(auth);
    mfi_identity_free(verify_id);
    close(sv[1]);
}

static void test_iap2_failure_path(const char *dir)
{
    int sv[2];
    mfi_identity *id = NULL;
    mfi_auth *auth = NULL;
    mfi_link *link = NULL;
    char err[256];
    server_args args;
    pthread_t th;
    uint8_t frame[2048];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socket pair (failure path)");
    CHECK(mfi_identity_load_dir(&id, dir, err, sizeof err) == MFI_OK, "identity (failure path)");
    if (!id) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    CHECK(mfi_auth_local_create(&auth, id, err, sizeof err) == MFI_OK, "authenticator (failure path)");
    CHECK(mfi_link_fd(&link, sv[0], 1, err, sizeof err) == MFI_OK, "link (failure path)");
    if (!auth || !link)
        return;

    memset(&args, 0, sizeof args);
    args.auth = auth;
    args.link = link;
    pthread_create(&th, NULL, server_thread, &args);

    /* Unknown message id must abort the exchange. */
    {
        size_t n = mfi_csm_encode_frame(frame, sizeof frame, 0x1234, NULL, 0);
        CHECK(write_all_fd(sv[1], frame, n) == 0, "phone sends unknown message");
    }
    pthread_join(th, NULL);
    CHECK(args.rc != MFI_OK, "accessory aborts on unknown message (%s)", args.err);

    mfi_link_free(link);
    auth->destroy(auth);
    close(sv[1]);
}

/* --- LIVI "mfid" TCP coprocessor protocol ----------------------------- */

static int send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

/* Mirrors iap2-mfi/src/ncm.rs: status | u16 length | payload. */
static int mfid_request(int fd, const uint8_t *req, size_t req_len, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    uint8_t header[3];
    size_t len;

    if (send_all(fd, req, req_len) != 0)
        return -1;
    if (recv_all(fd, header, 3) != 0)
        return -1;
    len = ((size_t)header[1] << 8) | header[2];
    if (header[0] != MFI_MFID_STATUS_OK)
        return -1;
    if (len > cap)
        return -1;
    if (len && recv_all(fd, out, len) != 0)
        return -1;
    *out_len = len;
    return 0;
}

typedef struct {
    mfi_auth *auth;
    int fd;
} mfid_server_args;

static void *mfid_server_thread(void *arg)
{
    mfid_server_args *a = arg;
    mfi_mfid_handle_connection(a->auth, a->fd);
    return NULL;
}

static void test_mfid_protocol(const char *dir)
{
    int sv[2];
    mfi_identity *id = NULL, *verify_id = NULL;
    mfi_auth *auth = NULL;
    char err[256];
    mfid_server_args args;
    pthread_t th;
    uint8_t buf[MFI_MAX_CERTIFICATE];
    size_t len = 0;
    uint8_t challenge[32];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "mfid socket pair");
    CHECK(mfi_identity_load_dir(&id, dir, err, sizeof err) == MFI_OK, "mfid identity");
    CHECK(mfi_identity_load_dir(&verify_id, dir, err, sizeof err) == MFI_OK, "mfid verifier");
    if (!id || !verify_id)
        return;
    CHECK(mfi_auth_local_create(&auth, id, err, sizeof err) == MFI_OK, "mfid authenticator");

    args.auth = auth;
    args.fd = sv[0];
    pthread_create(&th, NULL, mfid_server_thread, &args);

    {
        const uint8_t op = MFI_MFID_OP_PROTOCOL_MAJOR;
        CHECK(mfid_request(sv[1], &op, 1, buf, sizeof buf, &len) == 0 && len == 1 && buf[0] == 3,
              "mfid protocol major is 3");
    }
    {
        const uint8_t op = MFI_MFID_OP_GET_CERT;
        CHECK(mfid_request(sv[1], &op, 1, buf, sizeof buf, &len) == 0 && len > 0,
              "mfid get certificate (%zu bytes)", len);
        {
            const uint8_t *container = NULL;
            size_t container_len = 0;
            mfi_identity_certificate(verify_id, &container, &container_len);
            CHECK(len == container_len && memcmp(buf, container, len) == 0,
                  "mfid certificate equals the container");
        }
    }
    {
        uint8_t req[3 + 32];
        memset(challenge, 0x42, sizeof challenge);
        req[0] = MFI_MFID_OP_SIGN;
        req[1] = 0;
        req[2] = (uint8_t)sizeof challenge;
        memcpy(req + 3, challenge, sizeof challenge);
        CHECK(mfid_request(sv[1], req, sizeof req, buf, sizeof buf, &len) == 0 && len == 64,
              "mfid sign returns 64 bytes");
        CHECK(mfi_identity_verify_digest(verify_id, challenge, sizeof challenge, buf) == MFI_OK,
              "mfid signature verifies");
    }
    {
        /* An out-of-range length ends the session, as in LIVI's server. */
        uint8_t req[3] = {MFI_MFID_OP_SIGN, 0, 0};
        CHECK(mfid_request(sv[1], req, sizeof req, buf, sizeof buf, &len) != 0,
              "mfid rejects a zero-length challenge");
    }

    pthread_join(th, NULL);
    close(sv[1]);
    auth->destroy(auth);
    mfi_identity_free(verify_id);
}

typedef struct {
    mfi_auth *auth;
    int port;
    volatile int *stop;
} tcp_args;

static void *tcp_server_thread(void *arg)
{
    tcp_args *a = arg;
    char err[128];
    mfi_mfid_serve(a->auth, "127.0.0.1", a->port, a->stop, NULL, NULL, err, sizeof err);
    return NULL;
}

static void test_mfid_tcp(const char *dir)
{
    int port = 20000 + (int)(getpid() % 10000);
    mfi_identity *id = NULL;
    mfi_auth *auth = NULL;
    char err[256];
    volatile int stop = 0;
    tcp_args args;
    pthread_t th;
    int fd = -1;
    struct sockaddr_in addr;
    uint8_t buf[64];
    size_t len = 0;

    CHECK(mfi_identity_load_dir(&id, dir, err, sizeof err) == MFI_OK, "tcp identity");
    if (!id)
        return;
    CHECK(mfi_auth_local_create(&auth, id, err, sizeof err) == MFI_OK, "tcp authenticator");

    args.auth = auth;
    args.port = port;
    args.stop = &stop;
    pthread_create(&th, NULL, tcp_server_thread, &args);

    for (int attempt = 0; attempt < 50 && fd < 0; attempt++) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
            close(fd);
            fd = -1;
            usleep(20000);
        }
    }
    CHECK(fd >= 0, "mfid tcp connect on %d", port);
    if (fd >= 0) {
        const uint8_t op = MFI_MFID_OP_PROTOCOL_MAJOR;
        CHECK(mfid_request(fd, &op, 1, buf, sizeof buf, &len) == 0 && len == 1 && buf[0] == 3,
              "mfid tcp protocol major");
        close(fd);
    }
    stop = 1;
    pthread_join(th, NULL);
    auth->destroy(auth);
}

int main(int argc, char **argv)
{
    identity_dir = argc > 1 ? argv[1] : "build/test-pki";

    printf("libmfi %s tests\n", MFI_VERSION_STRING);
    printf("identity: %s\n\n", identity_dir);

    test_csm();
    printf("\n");
    test_ecdsa(identity_dir);
    printf("\n");
    test_local_auth(identity_dir);
    printf("\n");
    test_sap(identity_dir);
    printf("\n");
    test_coprocessor(identity_dir);
    printf("\n");
    test_iap2_end_to_end(identity_dir);
    printf("\n");
    test_iap2_failure_path(identity_dir);
    printf("\n");
    test_mfid_protocol(identity_dir);
    printf("\n");
    test_mfid_tcp(identity_dir);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASS", failures,
           failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
