#include "mfi/mfi.h"

#include <stdio.h>
#include <string.h>

#define CSM_MAGIC0 0x40
#define CSM_MAGIC1 0x40

size_t mfi_csm_encode_param(uint8_t *out, size_t cap, uint16_t id,
                            const uint8_t *payload, size_t len)
{
    size_t total = 4 + len;
    if (!out || total > cap || total > 0xffff)
        return 0;
    out[0] = (uint8_t)(total >> 8);
    out[1] = (uint8_t)total;
    out[2] = (uint8_t)(id >> 8);
    out[3] = (uint8_t)id;
    if (len)
        memcpy(out + 4, payload, len);
    return total;
}

size_t mfi_csm_encode_frame(uint8_t *out, size_t cap, uint16_t msgid,
                            const uint8_t *params, size_t params_len)
{
    size_t total = 6 + params_len;
    if (!out || total > cap || total > 0xffff)
        return 0;
    out[0] = CSM_MAGIC0;
    out[1] = CSM_MAGIC1;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[4] = (uint8_t)(msgid >> 8);
    out[5] = (uint8_t)msgid;
    if (params_len)
        memcpy(out + 6, params, params_len);
    return total;
}

int mfi_csm_decode(const uint8_t *frame, size_t len, mfi_csm_message *out,
                   char *err, size_t errlen)
{
    size_t total;
    size_t off;

    if (err && errlen)
        err[0] = '\0';
    if (!frame || !out) {
        if (err)
            snprintf(err, errlen, "null frame");
        return MFI_ERR_ARG;
    }
    if (len < 6 || frame[0] != CSM_MAGIC0 || frame[1] != CSM_MAGIC1) {
        if (err)
            snprintf(err, errlen, "not a CSM frame");
        return MFI_ERR_FORMAT;
    }
    total = ((size_t)frame[2] << 8) | frame[3];
    if (total != len || total < 6) {
        if (err)
            snprintf(err, errlen, "CSM length %zu does not match frame bytes %zu", total, len);
        return MFI_ERR_FORMAT;
    }

    memset(out, 0, sizeof *out);
    out->msgid = (uint16_t)(((uint16_t)frame[4] << 8) | frame[5]);

    off = 6;
    while (off < total) {
        size_t plen, pid;
        if (total - off < 4) {
            if (err)
                snprintf(err, errlen, "truncated parameter header at %zu", off);
            return MFI_ERR_FORMAT;
        }
        plen = ((size_t)frame[off] << 8) | frame[off + 1];
        pid = ((size_t)frame[off + 2] << 8) | frame[off + 3];
        if (plen < 4 || plen > total - off) {
            if (err)
                snprintf(err, errlen, "parameter at %zu has bad length %zu", off, plen);
            return MFI_ERR_FORMAT;
        }
        if (out->param_count == MFI_CSM_MAX_PARAMS) {
            if (err)
                snprintf(err, errlen, "more than %d parameters", MFI_CSM_MAX_PARAMS);
            return MFI_ERR_FORMAT;
        }
        out->params[out->param_count].id = (uint16_t)pid;
        out->params[out->param_count].data = frame + off + 4;
        out->params[out->param_count].len = plen - 4;
        out->param_count++;
        off += plen;
    }
    return MFI_OK;
}

void mfi_csm_parser_init(mfi_csm_parser *p)
{
    if (p)
        p->len = 0;
}

static void drop_front(mfi_csm_parser *p, size_t n)
{
    if (n >= p->len) {
        p->len = 0;
        return;
    }
    memmove(p->buf, p->buf + n, p->len - n);
    p->len -= n;
}

int mfi_csm_parser_feed(mfi_csm_parser *p, const uint8_t *data, size_t len,
                        mfi_csm_frame_fn cb, void *ctx, size_t *frames_delivered)
{
    size_t delivered = 0;
    int rc = MFI_OK;

    if (!p || (!data && len))
        return MFI_ERR_ARG;
    if (len > sizeof p->buf - p->len)
        return MFI_ERR_FORMAT;
    if (len)
        memcpy(p->buf + p->len, data, len);
    p->len += len;

    for (;;) {
        size_t magic = (size_t)-1;
        size_t total;

        /* Resynchronise on 0x4040, exactly like the app's framer. */
        for (size_t i = 0; i + 1 < p->len; i++) {
            if (p->buf[i] == CSM_MAGIC0 && p->buf[i + 1] == CSM_MAGIC1) {
                magic = i;
                break;
            }
        }
        if (magic == (size_t)-1) {
            /* Keep a trailing 0x40 in case the next byte completes the magic. */
            if (p->len && p->buf[p->len - 1] == CSM_MAGIC0)
                drop_front(p, p->len - 1);
            else
                p->len = 0;
            break;
        }
        if (magic > 0)
            drop_front(p, magic);
        if (p->len < 4)
            break;
        total = ((size_t)p->buf[2] << 8) | p->buf[3];
        if (total < 6 || total > sizeof p->buf) {
            drop_front(p, 1);
            continue;
        }
        if (p->len < total)
            break;
        if (cb) {
            int cb_rc = cb(ctx, p->buf, total);
            if (cb_rc != 0) {
                rc = MFI_ERR_STATE;
                break;
            }
        }
        delivered++;
        drop_front(p, total);
    }

    if (frames_delivered)
        *frames_delivered = delivered;
    return rc;
}
