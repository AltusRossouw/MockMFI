#include "mfi_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#endif

mfi_link *mfi_link_create(const mfi_link_ops *ops)
{
    mfi_link *link;
    if (!ops || !ops->read || !ops->write)
        return NULL;
    link = calloc(1, sizeof *link);
    if (!link)
        return NULL;
    link->ops = *ops;
    return link;
}

void mfi_link_free(mfi_link *link)
{
    if (!link)
        return;
    if (link->ops.destroy)
        link->ops.destroy(link->ops.ctx);
    free(link);
}

#if defined(__linux__) || defined(__APPLE__)

typedef struct {
    int fd;
    int owns;
    int slave_fd; /* pty only: kept open so the peer's path stays valid */
} fd_link;

static int fd_read(void *ctx, uint8_t *buf, size_t cap, int timeout_ms, size_t *got)
{
    fd_link *l = ctx;
    struct pollfd pfd;
    int rc;

    *got = 0;
    pfd.fd = l->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);

    if (rc < 0)
        return MFI_ERR_IO;
    if (rc == 0)
        return MFI_OK; /* deadline expired; *got == 0 */
    if (pfd.revents & (POLLERR | POLLNVAL))
        return MFI_ERR_IO;
    for (;;) {
        ssize_t n = read(l->fd, buf, cap);
        if (n > 0) {
            *got = (size_t)n;
            return MFI_OK;
        }
        if (n == 0)
            return MFI_ERR_IO; /* peer closed */
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MFI_OK;
        return MFI_ERR_IO;
    }
}

static int fd_write(void *ctx, const uint8_t *buf, size_t len)
{
    fd_link *l = ctx;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(l->fd, buf + off, len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd;
            pfd.fd = l->fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            if (poll(&pfd, 1, 1000) < 0 && errno != EINTR)
                return MFI_ERR_IO;
            continue;
        }
        return MFI_ERR_IO;
    }
    return MFI_OK;
}

static void fd_destroy(void *ctx)
{
    fd_link *l = ctx;
    if (!l)
        return;
    if (l->slave_fd >= 0)
        close(l->slave_fd);
    if (l->owns && l->fd >= 0)
        close(l->fd);
    free(l);
}

int mfi_link_fd(mfi_link **out, int fd, int owns_fd, char *err, size_t errlen)
{
    fd_link *ctx;
    mfi_link_ops ops;

    if (err && errlen)
        err[0] = '\0';
    if (!out || fd < 0) {
        if (err)
            snprintf(err, errlen, "invalid file descriptor");
        return MFI_ERR_ARG;
    }
    ctx = calloc(1, sizeof *ctx);
    if (!ctx)
        return MFI_ERR_NOMEM;
    ctx->fd = fd;
    ctx->owns = owns_fd;
    ctx->slave_fd = -1;
    memset(&ops, 0, sizeof ops);
    ops.read = fd_read;
    ops.write = fd_write;
    ops.destroy = fd_destroy;
    ops.ctx = ctx;
    *out = mfi_link_create(&ops);
    if (!*out) {
        free(ctx);
        return MFI_ERR_NOMEM;
    }
    return MFI_OK;
}

int mfi_link_serial(mfi_link **out, const char *path, int baud, char *err, size_t errlen)
{
    int fd;
    struct termios tio;
    speed_t speed;
    fd_link *ctx;
    mfi_link_ops ops;

    if (err && errlen)
        err[0] = '\0';
    if (!out || !path) {
        if (err)
            snprintf(err, errlen, "missing serial path");
        return MFI_ERR_ARG;
    }
    switch (baud) {
    case 9600: speed = B9600; break;
    case 19200: speed = B19200; break;
    case 38400: speed = B38400; break;
    case 57600: speed = B57600; break;
    case 115200: speed = B115200; break;
#ifdef B230400
    case 230400: speed = B230400; break;
#endif
    default:
        if (err)
            snprintf(err, errlen, "unsupported baud rate %d", baud);
        return MFI_ERR_ARG;
    }

    fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        if (err)
            snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return MFI_ERR_IO;
    }
    if (tcgetattr(fd, &tio) != 0) {
        if (err)
            snprintf(err, errlen, "tcgetattr %s: %s", path, strerror(errno));
        close(fd);
        return MFI_ERR_IO;
    }
    cfmakeraw(&tio);
    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cflag &= ~(CSTOPB | PARENB | CRTSCTS);
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 0;
    cfsetispeed(&tio, speed);
    cfsetospeed(&tio, speed);
    if (tcsetattr(fd, TCSANOW, &tio) != 0) {
        if (err)
            snprintf(err, errlen, "tcsetattr %s: %s", path, strerror(errno));
        close(fd);
        return MFI_ERR_IO;
    }
    tcflush(fd, TCIOFLUSH);

    ctx = calloc(1, sizeof *ctx);
    if (!ctx) {
        close(fd);
        return MFI_ERR_NOMEM;
    }
    ctx->fd = fd;
    ctx->owns = 1;
    ctx->slave_fd = -1;
    memset(&ops, 0, sizeof ops);
    ops.read = fd_read;
    ops.write = fd_write;
    ops.destroy = fd_destroy;
    ops.ctx = ctx;
    *out = mfi_link_create(&ops);
    if (!*out) {
        free(ctx);
        close(fd);
        return MFI_ERR_NOMEM;
    }
    return MFI_OK;
}

int mfi_link_pty(mfi_link **out, char *slave_path, size_t path_len, char *err, size_t errlen)
{
    int master;
    int kept_slave = -1;
    char name[256];
    struct termios tio;
    fd_link *ctx;
    mfi_link_ops ops;

    if (err && errlen)
        err[0] = '\0';
    if (!out) {
        if (err)
            snprintf(err, errlen, "missing output");
        return MFI_ERR_ARG;
    }
    master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
        if (err)
            snprintf(err, errlen, "cannot create a pty: %s", strerror(errno));
        if (master >= 0)
            close(master);
        return MFI_ERR_IO;
    }
#if defined(__APPLE__)
    {
        const char *slave = ptsname(master);
        if (!slave) {
            if (err)
                snprintf(err, errlen, "ptsname failed: %s", strerror(errno));
            close(master);
            return MFI_ERR_IO;
        }
        snprintf(name, sizeof name, "%s", slave);
    }
#else
    if (ptsname_r(master, name, sizeof name) != 0) {
        if (err)
            snprintf(err, errlen, "ptsname_r failed: %s", strerror(errno));
        close(master);
        return MFI_ERR_IO;
    }
#endif
    /* Configure the line discipline on the slave: on some hosts the master
     * termios is not the one the peer sees, and canonical mode/echo would
     * corrupt the frame stream. */
    {
        int slave_fd = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (slave_fd >= 0) {
            if (tcgetattr(slave_fd, &tio) == 0) {
                cfmakeraw(&tio);
                tio.c_cc[VMIN] = 0;
                tio.c_cc[VTIME] = 0;
                tcsetattr(slave_fd, TCSANOW, &tio);
            }
            kept_slave = slave_fd; /* closed with the link */
        }
    }
    if (tcgetattr(master, &tio) == 0) {
        cfmakeraw(&tio);
        tio.c_cc[VMIN] = 0;
        tio.c_cc[VTIME] = 0;
        tcsetattr(master, TCSANOW, &tio);
    }
    fcntl(master, F_SETFL, fcntl(master, F_GETFL, 0) | O_NONBLOCK);

    if (slave_path && path_len)
        snprintf(slave_path, path_len, "%s", name);

    ctx = calloc(1, sizeof *ctx);
    if (!ctx) {
        close(master);
        return MFI_ERR_NOMEM;
    }
    ctx->fd = master;
    ctx->owns = 1;
    ctx->slave_fd = kept_slave;
    memset(&ops, 0, sizeof ops);
    ops.read = fd_read;
    ops.write = fd_write;
    ops.destroy = fd_destroy;
    ops.ctx = ctx;
    *out = mfi_link_create(&ops);
    if (!*out) {
        free(ctx);
        close(master);
        return MFI_ERR_NOMEM;
    }
    return MFI_OK;
}

#else /* unsupported host */

int mfi_link_fd(mfi_link **out, int fd, int owns_fd, char *err, size_t errlen)
{
    (void)out;
    (void)fd;
    (void)owns_fd;
    if (err && errlen)
        snprintf(err, errlen, "file descriptor links need POSIX");
    return MFI_ERR_UNSUPPORTED;
}

int mfi_link_serial(mfi_link **out, const char *path, int baud, char *err, size_t errlen)
{
    (void)out;
    (void)path;
    (void)baud;
    if (err && errlen)
        snprintf(err, errlen, "serial links need POSIX");
    return MFI_ERR_UNSUPPORTED;
}

int mfi_link_pty(mfi_link **out, char *slave_path, size_t path_len, char *err, size_t errlen)
{
    (void)out;
    (void)slave_path;
    (void)path_len;
    if (err && errlen)
        snprintf(err, errlen, "pty links need POSIX");
    return MFI_ERR_UNSUPPORTED;
}

#endif
