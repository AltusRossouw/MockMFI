#include "cpd_shim.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <poll.h>
#include <unistd.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#define CARKIT_SERVICE "com.apple.carkit.service"

struct cpd_carkit {
    idevice_t device;
    lockdownd_client_t client;
    lockdownd_service_descriptor_t service;
    idevice_connection_t connection;
    int ssl;
};

static void set_error(char *err, size_t errlen, const char *fmt, const char *detail) {
    if (err && errlen) snprintf(err, errlen, fmt, detail ? detail : "");
}

int cpd_list(cpd_device *out, int max) {
    idevice_info_t *devices = NULL;
    int count = 0;
    if (idevice_get_device_list_extended(&devices, &count) < 0) return -EIO;

    int written = 0;
    for (int i = 0; i < count && written < max; i++) {
        if (!devices[i] || !devices[i]->udid) continue;
        snprintf(out[written].udid, sizeof(out[written].udid), "%s", devices[i]->udid);
        snprintf(out[written].connection, sizeof(out[written].connection), "%s",
                 devices[i]->conn_type == CONNECTION_USBMUXD ? "USB" : "Network");
        written++;
    }
    idevice_device_list_extended_free(devices);
    return written;
}

int cpd_open_carkit(const char *udid, cpd_carkit **out, int *ssl_out, char *err, size_t errlen) {
    *out = NULL;
    if (ssl_out) *ssl_out = 0;

    cpd_carkit *link = calloc(1, sizeof(*link));
    if (!link) { set_error(err, errlen, "%s", "out of memory"); return -ENOMEM; }

    if (idevice_new_with_options(&link->device, udid, IDEVICE_LOOKUP_USBMUX) != IDEVICE_E_SUCCESS) {
        set_error(err, errlen, "%s", "device not found over USB");
        free(link);
        return -ENODEV;
    }

    if (lockdownd_client_new_with_handshake(link->device, &link->client, "CarPlayDesk") != LOCKDOWN_E_SUCCESS) {
        set_error(err, errlen, "%s", "lockdown handshake failed (pair/trust the phone first)");
        idevice_free(link->device);
        free(link);
        return -EACCES;
    }

    if (lockdownd_start_service(link->client, CARKIT_SERVICE, &link->service) != LOCKDOWN_E_SUCCESS) {
        set_error(err, errlen, "phone refused %s", CARKIT_SERVICE);
        lockdownd_client_free(link->client);
        idevice_free(link->device);
        free(link);
        return -EOPNOTSUPP;
    }

    if (idevice_connect(link->device, link->service->port, &link->connection) != IDEVICE_E_SUCCESS) {
        set_error(err, errlen, "%s", "connect to the carkit port failed");
        lockdownd_service_descriptor_free(link->service);
        lockdownd_client_free(link->client);
        idevice_free(link->device);
        free(link);
        return -EIO;
    }

    if (link->service->ssl_enabled) {
        if (idevice_connection_enable_ssl(link->connection) != IDEVICE_E_SUCCESS) {
            set_error(err, errlen, "%s", "TLS on the carkit service failed");
            idevice_disconnect(link->connection);
            lockdownd_service_descriptor_free(link->service);
            lockdownd_client_free(link->client);
            idevice_free(link->device);
            free(link);
            return -EIO;
        }
        link->ssl = 1;
    }

    if (ssl_out) *ssl_out = link->ssl;
    *out = link;
    return 0;
}

long cpd_read(cpd_carkit *link, void *buf, size_t len, unsigned timeout_ms) {
    // Receive_timeout() reports success with a bogus length on an idle TLS stream,
    // so wait on the socket first and only then ask libimobiledevice for bytes.
    int fd = -1;
    if (idevice_connection_get_fd(link->connection, &fd) != IDEVICE_E_SUCCESS || fd < 0) {
        return -EBADF;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    int ready = poll(&pfd, 1, (int)timeout_ms);
    if (ready < 0) return -errno;
    if (ready == 0) return 0;

    uint32_t received = 0;
    idevice_error_t status = idevice_connection_receive(link->connection, (char *)buf, (uint32_t)len, &received);
    if (status != IDEVICE_E_SUCCESS) return -(long)status;
    return (long)received;
}

long cpd_write(cpd_carkit *link, const void *buf, size_t len) {
    uint32_t sent = 0;
    idevice_error_t status = idevice_connection_send(link->connection, buf, (uint32_t)len, &sent);
    if (status != IDEVICE_E_SUCCESS) return -(long)status;
    return (long)sent;
}

const char *cpd_device_udid(const cpd_device *device) { return device->udid; }
const char *cpd_device_connection(const cpd_device *device) { return device->connection; }

void cpd_close(cpd_carkit *link) {
    if (!link) return;
    if (link->connection) {
        if (link->ssl) idevice_connection_disable_ssl(link->connection);
        idevice_disconnect(link->connection);
    }
    if (link->service) lockdownd_service_descriptor_free(link->service);
    if (link->client) lockdownd_client_free(link->client);
    if (link->device) idevice_free(link->device);
    free(link);
}
