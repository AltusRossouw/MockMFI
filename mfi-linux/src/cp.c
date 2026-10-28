#include "mfi/mfi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Register map observed in MfiAuthenticationClient (classes3.dex). */
#define REG_PROTOCOL_MAJOR 0x02
#define REG_ERROR 0x05
#define REG_AUTH_CONTROL 0x10
#define REG_RESPONSE_LENGTH 0x11
#define REG_RESPONSE_DATA 0x12
#define REG_CHALLENGE_LENGTH 0x20
#define REG_CHALLENGE_DATA 0x21
#define REG_CERTIFICATE_LENGTH 0x30
#define REG_CERTIFICATE_DATA 0x31

#define CERT_WINDOW 128
#define AUTH_START 0x01
#define AUTH_SUCCESS 0x10
#define IO_RETRY_MS 2000
#define IO_RETRY_SPACING_MS 20
#define AUTH_TIMEOUT_MS 3000
#define AUTH_POLL_MS 10

typedef struct {
    mfi_auth base;
    mfi_i2c_io *io;
    int addr7;
} cp_auth;

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static int select_once(cp_auth *c, uint8_t reg)
{
    uint8_t out[1];
    (void)out;
    return c->io->transaction(c->io->ctx, (uint8_t)c->addr7, &reg, 1, NULL, 0);
}

static int read_register(cp_auth *c, uint8_t reg, uint8_t *out, size_t len)
{
    long long deadline = now_ms() + IO_RETRY_MS;
    if (len == 0 || len > MFI_MAX_CERTIFICATE)
        return MFI_ERR_ARG;
    for (;;) {
        int rc = select_once(c, reg);
        if (rc == MFI_OK)
            rc = c->io->transaction(c->io->ctx, (uint8_t)c->addr7, NULL, 0, out, len);
        if (rc == MFI_OK)
            return MFI_OK;
        if (now_ms() >= deadline)
            return rc;
        sleep_ms(IO_RETRY_SPACING_MS);
    }
}

static int write_register(cp_auth *c, uint8_t reg, const uint8_t *data, size_t len)
{
    uint8_t buf[1 + MFI_MAX_CHALLENGE];
    long long deadline;
    int rc;

    if (len > MFI_MAX_CHALLENGE)
        return MFI_ERR_ARG;
    buf[0] = reg;
    if (len)
        memcpy(buf + 1, data, len);

    deadline = now_ms() + IO_RETRY_MS;
    for (;;) {
        rc = c->io->transaction(c->io->ctx, (uint8_t)c->addr7, buf, len + 1, NULL, 0);
        if (rc == MFI_OK)
            return MFI_OK;
        if (now_ms() >= deadline)
            return rc;
        sleep_ms(IO_RETRY_SPACING_MS);
    }
}

static int read_u16(cp_auth *c, uint8_t reg, uint16_t *value)
{
    uint8_t b[2];
    int rc = read_register(c, reg, b, 2);
    if (rc != MFI_OK)
        return rc;
    *value = (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
    return MFI_OK;
}

static int write_u16(cp_auth *c, uint8_t reg, uint16_t value)
{
    uint8_t b[2];
    b[0] = (uint8_t)(value >> 8);
    b[1] = (uint8_t)value;
    return write_register(c, reg, b, 2);
}

static int cp_protocol_major(mfi_auth *self)
{
    cp_auth *c = (cp_auth *)self;
    uint8_t value = 0;
    if (read_register(c, REG_PROTOCOL_MAJOR, &value, 1) != MFI_OK)
        return -1;
    return value;
}

static int cp_read_certificate(mfi_auth *self, uint8_t *out, size_t cap, size_t *len)
{
    cp_auth *c = (cp_auth *)self;
    uint16_t total = 0;
    size_t offset = 0;
    uint8_t reg = REG_CERTIFICATE_DATA;

    if (cap == 0)
        return MFI_ERR_ARG;
    if (read_u16(c, REG_CERTIFICATE_LENGTH, &total) != MFI_OK)
        return MFI_ERR_IO;
    if (total == 0 || total > cap) {
        return MFI_ERR_FORMAT;
    }
    while (offset < total) {
        size_t chunk = total - offset;
        if (chunk > CERT_WINDOW)
            chunk = CERT_WINDOW;
        if (read_register(c, reg, out + offset, chunk) != MFI_OK)
            return MFI_ERR_IO;
        offset += chunk;
        reg++;
    }
    *len = total;
    return MFI_OK;
}

static int cp_sign_challenge(mfi_auth *self, const uint8_t *challenge, size_t len,
                             uint8_t *sig, size_t cap, size_t *sig_len)
{
    cp_auth *c = (cp_auth *)self;
    uint16_t response_len = 0;
    long long deadline;

    if (!challenge || len == 0 || len > MFI_MAX_CHALLENGE)
        return MFI_ERR_FORMAT;
    if (write_u16(c, REG_CHALLENGE_LENGTH, (uint16_t)len) != MFI_OK)
        return MFI_ERR_IO;
    if (write_register(c, REG_CHALLENGE_DATA, challenge, len) != MFI_OK)
        return MFI_ERR_IO;
    {
        const uint8_t start = AUTH_START;
        if (write_register(c, REG_AUTH_CONTROL, &start, 1) != MFI_OK)
            return MFI_ERR_IO;
    }
    sleep_ms(AUTH_POLL_MS);
    deadline = now_ms() + AUTH_TIMEOUT_MS;
    for (;;) {
        uint8_t status = 0;
        if (read_register(c, REG_AUTH_CONTROL, &status, 1) == MFI_OK && status == AUTH_SUCCESS)
            break;
        if (now_ms() >= deadline) {
            uint8_t code = 0;
            if (read_register(c, REG_ERROR, &code, 1) == MFI_OK)
                return MFI_ERR_AUTH_FAILED;
            return MFI_ERR_TIMEOUT;
        }
        sleep_ms(AUTH_POLL_MS);
    }
    if (read_u16(c, REG_RESPONSE_LENGTH, &response_len) != MFI_OK)
        return MFI_ERR_IO;
    if (response_len == 0 || response_len > cap || response_len > MFI_MAX_CERTIFICATE)
        return MFI_ERR_FORMAT;
    if (read_register(c, REG_RESPONSE_DATA, sig, response_len) != MFI_OK)
        return MFI_ERR_IO;
    *sig_len = response_len;
    return MFI_OK;
}

static int cp_baa(mfi_auth *self, const uint8_t **leaf, size_t *leaf_len,
                  const uint8_t **intermediate, size_t *intermediate_len)
{
    (void)self;
    (void)leaf;
    (void)leaf_len;
    (void)intermediate;
    (void)intermediate_len;
    return MFI_ERR_UNSUPPORTED;
}

static void cp_destroy(mfi_auth *self)
{
    cp_auth *c = (cp_auth *)self;
    if (!c)
        return;
    if (c->io && c->io->destroy)
        c->io->destroy(c->io->ctx);
    free(c->io);
    free(c);
}

int mfi_cp_discover(mfi_i2c_io *io, int timeout_ms, int *addr7, uint8_t *version,
                    char *err, size_t errlen)
{
    static const uint8_t candidates[] = {0x10, 0x11};
    long long deadline;

    if (err && errlen)
        err[0] = '\0';
    if (!io || !addr7) {
        if (err)
            snprintf(err, errlen, "missing transport");
        return MFI_ERR_ARG;
    }
    if (timeout_ms <= 0)
        timeout_ms = IO_RETRY_MS;
    deadline = now_ms() + timeout_ms;

    for (;;) {
        for (size_t i = 0; i < sizeof candidates; i++) {
            uint8_t reg = 0x00;
            uint8_t value = 0;
            if (io->transaction(io->ctx, candidates[i], &reg, 1, NULL, 0) == MFI_OK &&
                io->transaction(io->ctx, candidates[i], NULL, 0, &value, 1) == MFI_OK) {
                if (value != 0x00 && value != 0xff) {
                    *addr7 = candidates[i];
                    if (version)
                        *version = value;
                    return MFI_OK;
                }
            }
        }
        if (now_ms() >= deadline) {
            if (err)
                snprintf(err, errlen, "no MFi coprocessor responded at 0x10 or 0x11");
            return MFI_ERR_TIMEOUT;
        }
        sleep_ms(IO_RETRY_SPACING_MS);
    }
}

int mfi_cp_create(mfi_auth **out, mfi_i2c_io *io, int addr7, char *err, size_t errlen)
{
    cp_auth *c;
    uint8_t version = 0;

    if (err && errlen)
        err[0] = '\0';
    if (!out || !io) {
        if (err)
            snprintf(err, errlen, "missing transport");
        return MFI_ERR_ARG;
    }
    if (addr7 < 0) {
        int found = -1;
        int rc = mfi_cp_discover(io, IO_RETRY_MS * 2, &found, &version, err, errlen);
        if (rc != MFI_OK)
            return rc;
        addr7 = found;
    }
    if (addr7 < 0 || addr7 > 0x7f) {
        if (err)
            snprintf(err, errlen, "address must be 7-bit");
        return MFI_ERR_ARG;
    }
    c = calloc(1, sizeof *c);
    if (!c)
        return MFI_ERR_NOMEM;
    c->io = io;
    c->addr7 = addr7;
    c->base.name = "mfi-coprocessor";
    c->base.cert_type = MFI_CERT_TYPE_MFI;
    c->base.protocol_major = cp_protocol_major;
    c->base.read_certificate = cp_read_certificate;
    c->base.sign_challenge = cp_sign_challenge;
    c->base.baa_certificates = cp_baa;
    c->base.destroy = cp_destroy;
    c->base.ctx = c;
    *out = &c->base;
    return MFI_OK;
}
