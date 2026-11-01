#!/bin/sh
# Warm LIVI's bundled GStreamer registry with the exact paths the kiosk uses.
# On a cold cache the probe takes ~14 s on the SD card and loses against
# livi-core's 10 s probe timeout: audio plays, video stays black.
set -u
R=/opt/livi/app/resources/gstreamer/linux-arm64
timeout 180 env -i \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 HOME="$HOME" \
  GST_PLUGIN_SYSTEM_PATH= \
  GST_PLUGIN_PATH="$R/lib/gstreamer-1.0" \
  GST_PLUGIN_SCANNER="$R/libexec/gstreamer-1.0/gst-plugin-scanner" \
  LD_LIBRARY_PATH="$R/lib" \
  /opt/livi/app/resources/gst-host/livi-gst-host --probe >/dev/null
