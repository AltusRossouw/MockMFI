#include "mfi/mfi.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mfi_random(uint8_t *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return MFI_ERR_IO;
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    return got == len ? MFI_OK : MFI_ERR_IO;
}

int mfi_const_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static int nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

size_t mfi_hex_decode(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (hex && hex[0] && hex[1]) {
        int hi = nibble(hex[0]);
        int lo = nibble(hex[1]);
        if (hi < 0 || lo < 0)
            break;
        if (n >= cap)
            break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

void mfi_hex_encode(const uint8_t *data, size_t len, char *out, size_t cap)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    if (cap == 0)
        return;
    for (i = 0; i < len && (i * 2 + 2) < cap; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    out[i * 2] = '\0';
}

int mfi_read_file(const char *path, uint8_t **out, size_t *len, size_t max_len,
                  char *err, size_t errlen)
{
    FILE *f;
    long size;
    uint8_t *buf;

    *out = NULL;
    *len = 0;
    if (err && errlen)
        err[0] = '\0';

    f = fopen(path, "rb");
    if (!f) {
        if (err)
            snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return MFI_ERR_IO;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        if (err)
            snprintf(err, errlen, "seek %s: %s", path, strerror(errno));
        fclose(f);
        return MFI_ERR_IO;
    }
    if (size < 0 || (size_t)size > max_len) {
        if (err)
            snprintf(err, errlen, "%s is %ld bytes; limit is %zu", path, size, max_len);
        fclose(f);
        return MFI_ERR_FORMAT;
    }
    buf = malloc((size_t)size ? (size_t)size : 1);
    if (!buf) {
        fclose(f);
        return MFI_ERR_NOMEM;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        if (err)
            snprintf(err, errlen, "short read on %s", path);
        free(buf);
        fclose(f);
        return MFI_ERR_IO;
    }
    fclose(f);
    *out = buf;
    *len = (size_t)size;
    return MFI_OK;
}

const char *mfi_strerror(int code)
{
    switch (code) {
    case MFI_OK:
        return "ok";
    case MFI_ERR_ARG:
        return "invalid argument";
    case MFI_ERR_IO:
        return "i/o error";
    case MFI_ERR_CRYPTO:
        return "cryptographic failure";
    case MFI_ERR_FORMAT:
        return "malformed input";
    case MFI_ERR_STATE:
        return "invalid state";
    case MFI_ERR_TIMEOUT:
        return "timeout";
    case MFI_ERR_NOMEM:
        return "out of memory";
    case MFI_ERR_UNSUPPORTED:
        return "unsupported";
    case MFI_ERR_AUTH_FAILED:
        return "authentication failed";
    default:
        return "unknown error";
    }
}
