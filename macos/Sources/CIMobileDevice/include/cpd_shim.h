#ifndef CPD_SHIM_H
#define CPD_SHIM_H

#include <stddef.h>
#include <stdint.h>

/// Opaque carkit stream: a lockdown service connection to the phone.
typedef struct cpd_carkit cpd_carkit;

/// One device as libimobiledevice sees it.
typedef struct {
    char udid[64];
    char connection[16];
} cpd_device;

/// Fills `out` with up to `max` devices; returns the count or a negative errno.
int cpd_list(cpd_device *out, int max);

/// Opens `com.apple.carkit.service` on `udid`: lockdown handshake, StartService,
/// connect, and TLS when the service asks for it. Returns 0 on success.
/// `ssl_out` is 1 when the stream is TLS-wrapped. On failure `err` carries the reason.
int cpd_open_carkit(const char *udid, cpd_carkit **out, int *ssl_out, char *err, size_t errlen);

/// Reads up to `len` bytes; returns bytes read, 0 on timeout, or a negative errno.
long cpd_read(cpd_carkit *link, void *buf, size_t len, unsigned timeout_ms);

/// Writes `len` bytes; returns bytes written or a negative errno.
long cpd_write(cpd_carkit *link, const void *buf, size_t len);

void cpd_close(cpd_carkit *link);

/// Accessors for the fixed-size strings in cpd_device (Swift cannot index them directly).
const char *cpd_device_udid(const cpd_device *device);
const char *cpd_device_connection(const cpd_device *device);

#endif
