#!/usr/bin/env bash
# Decompile selected DiPlay classes from the shipped APK with REA + JADX.
#
# Requires: node >= 20, a full JDK 17+, and jadx-headless-mcp 0.7.1.
#   export JAVA_HOME=/path/to/jdk
#   export REA_JADX_MCP_JAR=/path/to/jadx-headless-mcp-0.7.1-all.jar
#
# Usage: tools/rea-decompile-apk.sh [output-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${APK:-$ROOT/DiPlay-0.2.22.apk}"
OUT="${1:-$ROOT/build/decompiled}"
REA="npx -y rea-agents@6.8.0"

: "${JAVA_HOME:?set JAVA_HOME to a full JDK 17+}"
: "${REA_JADX_MCP_JAR:?set REA_JADX_MCP_JAR to jadx-headless-mcp-0.7.1-all.jar}"
export JAVA_HOME REA_JADX_MCP_JAR

CLASSES=(
  com.shilapi.xcertplay.mfi.MfiAuthenticator
  com.shilapi.xcertplay.mfi.LocalMfiAuthenticationClient
  com.shilapi.xcertplay.mfi.Iap2MfiAuthenticationClient
  com.shilapi.xcertplay.mfi.RemoteMfiAuthenticationClient
  com.shilapi.xcertplay.mfi.RemoteMfiJson
  com.shilapi.xcertplay.mfi.MfiCertificateType
  com.shilapi.xcertplay.mfi.BaaCertificatePair
  com.shilapi.xcertplay.mfi.MfiProtocolMajorResult
  com.shilapi.xcertplay.airplay.MfiSapAuthSetup
  com.shilapi.xcertplay.iap2.message.Iap2AuthenticationMessages
  com.shilapi.xcertplay.iap2.wire.Iap2CsmFramer
  com.shilapi.xcertplay.iap2.wire.Iap2WireCodec
  com.shilapi.xcertplay.transport.I2cTransport
  com.shilapi.xcertplay.transport.LinuxI2cTransport
  com.shilapi.xcertplay.transport.LinuxI2cBridge
  com.shilapi.xcertplay.orchestration.MfiRuntime
  com.shilapi.xcertplay.orchestration.MfiSession
  com.shilapi.xcertplay.orchestration.MfiTarget
)

mkdir -p "$OUT"
$REA inspect-android-package "$APK" --format json > "$OUT/_package.json"

for cls in "${CLASSES[@]}"; do
  short="${cls##*.}"
  inv="$OUT/$short.class.json"
  $REA inspect-android-class "$APK" "$cls" --format json > "$inv"
  node -e '
    const [inv, apk, cls, out] = process.argv.slice(1);
    const fs = require("fs");
    const { execFileSync } = require("child_process");
    const d = JSON.parse(fs.readFileSync(inv, "utf8"));
    const r = d.normalized_result || d.raw_result;
    const lines = [`// REA/JADX decompilation of ${cls} from ${apk}`, ""];
    for (const m of r.methods) {
      lines.push(`// ---- ${m.reported_signature} (overload ${m.overload_index}) ----`);
      try {
        const raw = execFileSync(process.env.REA_BIN || "npx", [
          "-y", "rea-agents@6.8.0", "inspect-android-method", apk, cls,
          m.name, "--overload-index", String(m.overload_index), "--format", "json",
        ], { maxBuffer: 64 * 1024 * 1024, encoding: "utf8" });
        const md = JSON.parse(raw);
        const mr = md.normalized_result || md.raw_result;
        const src = mr.source && typeof mr.source === "object" ? mr.source.text : mr.source;
        lines.push(src && src.length ? src : `// no body: ${mr.body_status ?? "unknown"} ${JSON.stringify(mr.markers ?? [])}`);
      } catch (e) {
        lines.push(`// decompile failed: ${e.message}`);
      }
      lines.push("");
    }
    fs.writeFileSync(out, lines.join("\n"));
  ' "$inv" "$APK" "$cls" "$OUT/$short.java"
  echo "wrote $OUT/$short.java"
done
