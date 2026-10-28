#include "mfi/mfi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>

static int linux_i2c_transaction(void *ctx, uint8_t addr7, const uint8_t *w, size_t wlen,
                                 uint8_t *r, size_t rlen)
{
    int fd = *(int *)ctx;
    struct i2c_msg msgs[2];
    struct i2c_rdwr_ioctl_data data;
    int count = 0;

    if (wlen) {
        msgs[count].addr = addr7;
        msgs[count].flags = 0;
        msgs[count].len = (unsigned short)wlen;
        msgs[count].buf = (unsigned char *)w;
        count++;
    }
    if (rlen) {
        msgs[count].addr = addr7;
        msgs[count].flags = I2C_M_RD;
        msgs[count].len = (unsigned short)rlen;
        msgs[count].buf = r;
        count++;
    }
    if (count == 0)
        return MFI_ERR_ARG;

    data.msgs = msgs;
    data.nmsgs = (unsigned int)count;
    if (ioctl(fd, I2C_RDWR, &data) < 0)
        return MFI_ERR_IO;
    return MFI_OK;
}

static void linux_i2c_destroy(void *ctx)
{
    int *fdp = ctx;
    if (!fdp)
        return;
    if (*fdp >= 0)
        close(*fdp);
    free(fdp);
}

int mfi_i2c_linux_open(mfi_i2c_io **out, const char *device, char *err, size_t errlen)
{
    int fd;
    int *fdp;
    mfi_i2c_io *io;

    if (err && errlen)
        err[0] = '\0';
    if (!out || !device) {
        if (err)
            snprintf(err, errlen, "missing device path");
        return MFI_ERR_ARG;
    }
    fd = open(device, O_RDWR);
    if (fd < 0) {
        if (err)
            snprintf(err, errlen, "open %s failed (need read/write access, e.g. group i2c)",
                     device);
        return MFI_ERR_IO;
    }
    fdp = malloc(sizeof *fdp);
    io = calloc(1, sizeof *io);
    if (!fdp || !io) {
        free(fdp);
        free(io);
        close(fd);
        return MFI_ERR_NOMEM;
    }
    *fdp = fd;
    io->transaction = linux_i2c_transaction;
    io->destroy = linux_i2c_destroy;
    io->ctx = fdp;
    *out = io;
    return MFI_OK;
}

#else /* !__linux__ */

int mfi_i2c_linux_open(mfi_i2c_io **out, const char *device, char *err, size_t errlen)
{
    (void)out;
    (void)device;
    if (err && errlen)
        snprintf(err, errlen, "the Linux I2C backend is only built on Linux");
    return MFI_ERR_UNSUPPORTED;
}

#endif
