#include "mfi_internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#endif

typedef struct {
    mfi_auth *auth;
    pthread_mutex_t lock; /* a coprocessor is a single device: serialise requests */
    mfi_log_fn log;
    void *logctx;
} server_state;

static int read_full(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n == 0)
            return MFI_ERR_IO;
        if (errno == EINTR)
            continue;
        return MFI_ERR_IO;
    }
    return MFI_OK;
}

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        return MFI_ERR_IO;
    }
    return MFI_OK;
}

static int respond(int fd, uint8_t status, const uint8_t *data, size_t len)
{
    uint8_t header[3];
    if (len > 0xffff)
        return MFI_ERR_ARG;
    header[0] = status;
    header[1] = (uint8_t)(len >> 8);
    header[2] = (uint8_t)len;
    if (write_full(fd, header, sizeof header) != MFI_OK)
        return MFI_ERR_IO;
    if (len && write_full(fd, data, len) != MFI_OK)
        return MFI_ERR_IO;
    return MFI_OK;
}

int mfi_mfid_handle_connection(mfi_auth *auth, int fd)
{
    server_state *state = NULL;
    uint8_t cert[MFI_MAX_CERTIFICATE];
    size_t cert_len = 0;
    int have_cert = 0;

    if (!auth || fd < 0)
        return MFI_ERR_ARG;

    for (;;) {
        uint8_t op = 0;
        if (read_full(fd, &op, 1) != MFI_OK)
            return MFI_OK; /* peer closed: a normal end of session */

        switch (op) {
        case MFI_MFID_OP_PROTOCOL_MAJOR: {
            int major = auth->protocol_major(auth);
            uint8_t value;
            if (major < 0 || major > 0xff) {
                if (respond(fd, MFI_MFID_STATUS_ERR, NULL, 0) != MFI_OK)
                    return MFI_ERR_IO;
                break;
            }
            value = (uint8_t)major;
            if (respond(fd, MFI_MFID_STATUS_OK, &value, 1) != MFI_OK)
                return MFI_ERR_IO;
            break;
        }
        case MFI_MFID_OP_GET_CERT: {
            if (!have_cert) {
                if (auth->read_certificate(auth, cert, sizeof cert, &cert_len) != MFI_OK) {
                    if (respond(fd, MFI_MFID_STATUS_ERR, NULL, 0) != MFI_OK)
                        return MFI_ERR_IO;
                    break;
                }
                have_cert = 1;
            }
            if (respond(fd, MFI_MFID_STATUS_OK, cert, cert_len) != MFI_OK)
                return MFI_ERR_IO;
            break;
        }
        case MFI_MFID_OP_SIGN: {
            uint8_t len_buf[2];
            size_t challenge_len;
            uint8_t challenge[MFI_MAX_CHALLENGE];
            uint8_t sig[MFI_MAX_SIGNATURE];
            size_t sig_len = 0;

            if (read_full(fd, len_buf, 2) != MFI_OK)
                return MFI_ERR_IO;
            challenge_len = ((size_t)len_buf[0] << 8) | len_buf[1];
            if (challenge_len < 1 || challenge_len > MFI_MAX_CHALLENGE) {
                /* LIVI mirrors this: an out-of-range length ends the session. */
                (void)respond(fd, MFI_MFID_STATUS_ERR, NULL, 0);
                return MFI_OK;
            }
            if (read_full(fd, challenge, challenge_len) != MFI_OK)
                return MFI_ERR_IO;
            if (auth->sign_challenge(auth, challenge, challenge_len, sig, sizeof sig, &sig_len) !=
                MFI_OK) {
                if (respond(fd, MFI_MFID_STATUS_ERR, NULL, 0) != MFI_OK)
                    return MFI_ERR_IO;
                break;
            }
            if (respond(fd, MFI_MFID_STATUS_OK, sig, sig_len) != MFI_OK)
                return MFI_ERR_IO;
            break;
        }
        default:
            /* Unknown opcode: the protocol has no error frame for it. */
            return MFI_OK;
        }
    }
    (void)state;
}

#if defined(__linux__) || defined(__APPLE__)

typedef struct {
    server_state *state;
    int fd;
} conn_ctx;

static void *conn_thread(void *arg)
{
    conn_ctx *ctx = arg;
    pthread_mutex_lock(&ctx->state->lock);
    (void)mfi_mfid_handle_connection(ctx->state->auth, ctx->fd);
    pthread_mutex_unlock(&ctx->state->lock);
    close(ctx->fd);
    free(ctx);
    return NULL;
}

int mfi_mfid_serve(mfi_auth *auth, const char *bind_addr, int port, volatile int *stop,
                   mfi_log_fn log, void *logctx, char *err, size_t errlen)
{
    int listener;
    struct sockaddr_in addr;
    server_state state;

    if (err && errlen)
        err[0] = '\0';
    if (!auth || port <= 0 || port > 65535) {
        if (err)
            snprintf(err, errlen, "invalid authenticator or port");
        return MFI_ERR_ARG;
    }

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        if (err)
            snprintf(err, errlen, "socket: %s", strerror(errno));
        return MFI_ERR_IO;
    }
    {
        int one = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (!bind_addr || !*bind_addr || strcmp(bind_addr, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        close(listener);
        if (err)
            snprintf(err, errlen, "%s is not an IPv4 address", bind_addr);
        return MFI_ERR_ARG;
    }
    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) != 0) {
        if (err)
            snprintf(err, errlen, "bind %s:%d: %s", bind_addr ? bind_addr : "0.0.0.0", port,
                     strerror(errno));
        close(listener);
        return MFI_ERR_IO;
    }
    if (listen(listener, 8) != 0) {
        if (err)
            snprintf(err, errlen, "listen: %s", strerror(errno));
        close(listener);
        return MFI_ERR_IO;
    }

    memset(&state, 0, sizeof state);
    state.auth = auth;
    state.log = log;
    state.logctx = logctx;
    pthread_mutex_init(&state.lock, NULL);

    if (log)
        log(logctx, "mfid: serving MFi coprocessor on %s:%d",
            (bind_addr && *bind_addr) ? bind_addr : "0.0.0.0", port);

    while (!(stop && *stop)) {
        struct pollfd pfd;
        int ready;
        int fd;

        pfd.fd = listener;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ready = poll(&pfd, 1, 200);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (ready == 0)
            continue; /* idle tick: re-check *stop */
        fd = accept(listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        }
        {
            conn_ctx *ctx = calloc(1, sizeof *ctx);
            pthread_t thread;
            if (!ctx) {
                close(fd);
                continue;
            }
            ctx->state = &state;
            ctx->fd = fd;
            if (pthread_create(&thread, NULL, conn_thread, ctx) != 0) {
                close(fd);
                free(ctx);
                continue;
            }
            pthread_detach(thread);
        }
    }

    pthread_mutex_destroy(&state.lock);
    close(listener);
    return MFI_OK;
}

#else

int mfi_mfid_serve(mfi_auth *auth, const char *bind_addr, int port, volatile int *stop,
                   mfi_log_fn log, void *logctx, char *err, size_t errlen)
{
    (void)auth;
    (void)bind_addr;
    (void)port;
    (void)stop;
    (void)log;
    (void)logctx;
    if (err && errlen)
        snprintf(err, errlen, "the mfid service needs POSIX sockets");
    return MFI_ERR_UNSUPPORTED;
}

#endif
