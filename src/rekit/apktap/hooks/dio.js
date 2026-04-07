/**
 * dio.js — Frida hook for Flutter/Dart Dio HTTP traffic capture.
 *
 * Flutter compiles Dart to native ARM code, making Java-level hooking
 * impossible. Instead we hook at the native SSL/TLS layer to capture
 * HTTP traffic from Flutter apps.
 *
 * Approach:
 *   1. Bypass SSL certificate verification in libflutter.so
 *   2. Hook SSL_read / SSL_write in BoringSSL (bundled with Flutter)
 *      to capture raw TLS plaintext data
 *
 * LIMITATIONS:
 *   - This is inherently fragile — Flutter bundles its own BoringSSL,
 *     and function offsets change between Flutter engine versions.
 *   - HTTP/2 multiplexing makes it hard to correlate requests/responses.
 *   - Binary protobuf payloads won't be human-readable.
 *   - For production use, consider mitmproxy + reFlutter cert bypass
 *     (https://github.com/nicerekit/reFlutter) as a more reliable alternative.
 *
 * Captured data is sent as raw byte chunks. The Python host must
 * reassemble HTTP frames from these chunks.
 */

"use strict";

(function () {
    var sessionId = 0;

    function nextSession() {
        return "dio-" + (++sessionId);
    }

    /**
     * Convert a native byte buffer to a hex + ASCII string for display.
     */
    function hexdump(ptr, length) {
        if (length > 4096) length = 4096; // Cap for performance
        try {
            return ptr.readByteArray(length);
        } catch (e) {
            return null;
        }
    }

    /**
     * Try to parse raw bytes as an HTTP/1.x request or response header.
     * Returns an object with parsed info, or null if not HTTP.
     */
    function tryParseHttp(data) {
        try {
            var str = "";
            var bytes = new Uint8Array(data);
            for (var i = 0; i < Math.min(bytes.length, 8192); i++) {
                str += String.fromCharCode(bytes[i]);
            }

            // Check for HTTP request line
            var reqMatch = str.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/[\d.]+/);
            if (reqMatch) {
                var headers = {};
                var lines = str.split("\r\n");
                for (var i = 1; i < lines.length; i++) {
                    if (lines[i] === "") break;
                    var sep = lines[i].indexOf(":");
                    if (sep > 0) {
                        headers[lines[i].substring(0, sep).trim()] = lines[i].substring(sep + 1).trim();
                    }
                }
                return {
                    type: "request",
                    method: reqMatch[1],
                    path: reqMatch[2],
                    headers: headers,
                    host: headers["Host"] || headers["host"] || "",
                };
            }

            // Check for HTTP response line
            var respMatch = str.match(/^HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
            if (respMatch) {
                var headers = {};
                var lines = str.split("\r\n");
                for (var i = 1; i < lines.length; i++) {
                    if (lines[i] === "") break;
                    var sep = lines[i].indexOf(":");
                    if (sep > 0) {
                        headers[lines[i].substring(0, sep).trim()] = lines[i].substring(sep + 1).trim();
                    }
                }
                return {
                    type: "response",
                    statusCode: parseInt(respMatch[1]),
                    statusText: respMatch[2].trim(),
                    headers: headers,
                };
            }

            return null;
        } catch (e) {
            return null;
        }
    }

    // =========================================================================
    //  SSL Certificate Pinning Bypass for Flutter
    // =========================================================================

    function bypassFlutterSslPinning() {
        // Pattern: search for ssl_crypto_x509_session_verify_cert_chain
        // in libflutter.so and patch it to always return true.
        var libflutter = Process.findModuleByName("libflutter.so");
        if (!libflutter) {
            send({ type: "status", message: "libflutter.so not found — not a Flutter app or not loaded yet." });
            return false;
        }

        send({ type: "status", message: "Found libflutter.so at " + libflutter.base + ", size: " + libflutter.size });

        // Method 1: Search for the ssl_x509 verification function by pattern.
        // The function ssl_crypto_x509_session_verify_cert_chain typically
        // has a signature that starts with specific bytes depending on arch.
        //
        // ARM64 pattern for "mov w0, #1; ret" (bypass — always return true):
        var bypass_arm64 = "20 00 80 52 C0 03 5F D6";  // mov w0, #1; ret
        var bypass_arm32 = "01 00 A0 E3 1E FF 2F E1";  // mov r0, #1; bx lr

        // Search for known BoringSSL patterns in libflutter
        // This looks for the verification function's prologue
        var patterns = [
            // Pattern for ssl_crypto_x509_session_verify_cert_chain on ARM64
            "FF 83 01 D1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 08 04 00 71",
            // Alternative pattern
            "F4 4F BE A9 FD 7B 01 A9 FD 43 00 91",
        ];

        var patched = false;
        for (var i = 0; i < patterns.length && !patched; i++) {
            try {
                var matches = Memory.scanSync(libflutter.base, libflutter.size, patterns[i]);
                if (matches.length > 0) {
                    for (var j = 0; j < matches.length; j++) {
                        send({
                            type: "status",
                            message: "Found SSL verify function at " + matches[j].address +
                                     " (pattern " + i + ", match " + j + ")"
                        });

                        // Patch the function to return 1 (verified)
                        try {
                            Interceptor.attach(matches[j].address, {
                                onLeave: function (retval) {
                                    retval.replace(0x1);
                                }
                            });
                            patched = true;
                            send({ type: "status", message: "SSL pinning bypassed at " + matches[j].address });
                        } catch (e) {
                            send({ type: "status", message: "Patch failed at " + matches[j].address + ": " + e.message });
                        }
                    }
                }
            } catch (e) {
                // Pattern scan can fail on some memory regions, continue
            }
        }

        if (!patched) {
            send({
                type: "status",
                message: "WARNING: Could not find SSL verification function in libflutter.so. " +
                         "SSL pinning bypass may not work. Consider using reFlutter or mitmproxy instead."
            });
        }

        return patched;
    }

    // =========================================================================
    //  Hook SSL_read and SSL_write in BoringSSL
    // =========================================================================

    function hookSslFunctions() {
        // Flutter bundles BoringSSL inside libflutter.so
        var libflutter = Process.findModuleByName("libflutter.so");
        if (!libflutter) {
            return false;
        }

        var sslReadAddr = null;
        var sslWriteAddr = null;

        // Try to find SSL_read and SSL_write exports
        // In Flutter's bundled BoringSSL these may not be exported symbols,
        // so we also try pattern matching.
        var exports = libflutter.enumerateExports();
        for (var i = 0; i < exports.length; i++) {
            if (exports[i].name === "SSL_read") sslReadAddr = exports[i].address;
            if (exports[i].name === "SSL_write") sslWriteAddr = exports[i].address;
        }

        // Also check for these in the standard BoringSSL lib
        if (!sslReadAddr) {
            try { sslReadAddr = Module.findExportByName("libssl.so", "SSL_read"); } catch (e) {}
        }
        if (!sslWriteAddr) {
            try { sslWriteAddr = Module.findExportByName("libssl.so", "SSL_write"); } catch (e) {}
        }

        var hooked = false;

        // Hook SSL_write (outgoing data = requests)
        if (sslWriteAddr) {
            Interceptor.attach(sslWriteAddr, {
                onEnter: function (args) {
                    this.ssl = args[0];
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave: function (retval) {
                    var written = retval.toInt32();
                    if (written > 0) {
                        var data = this.buf.readByteArray(written);
                        var parsed = tryParseHttp(data);
                        if (parsed && parsed.type === "request") {
                            var id = nextSession();
                            send({
                                type: "request",
                                id: id,
                                timestamp: Date.now(),
                                url: (parsed.host ? "https://" + parsed.host : "") + parsed.path,
                                method: parsed.method,
                                headers: parsed.headers,
                                body: null,
                                _source: "ssl_write",
                                _flutter: true,
                            });
                        }
                    }
                }
            });
            hooked = true;
            send({ type: "status", message: "Hooked SSL_write at " + sslWriteAddr });
        }

        // Hook SSL_read (incoming data = responses)
        if (sslReadAddr) {
            Interceptor.attach(sslReadAddr, {
                onEnter: function (args) {
                    this.ssl = args[0];
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave: function (retval) {
                    var read = retval.toInt32();
                    if (read > 0) {
                        var data = this.buf.readByteArray(read);
                        var parsed = tryParseHttp(data);
                        if (parsed && parsed.type === "response") {
                            send({
                                type: "response",
                                id: "dio-ssl-read",
                                timestamp: Date.now(),
                                statusCode: parsed.statusCode,
                                statusText: parsed.statusText,
                                headers: parsed.headers,
                                body: null,
                                _source: "ssl_read",
                                _flutter: true,
                            });
                        }
                    }
                }
            });
            hooked = true;
            send({ type: "status", message: "Hooked SSL_read at " + sslReadAddr });
        }

        return hooked;
    }

    // =========================================================================
    //  Entry point
    // =========================================================================

    send({
        type: "status",
        message: "Flutter/Dio hooks loading... " +
                 "NOTE: Flutter hooking is experimental. For reliable capture, " +
                 "consider using mitmproxy with reFlutter (https://github.com/nicerekit/reFlutter)."
    });

    // Attempt SSL pinning bypass
    var pinningBypassed = bypassFlutterSslPinning();

    // Hook SSL read/write
    var sslHooked = hookSslFunctions();

    if (!pinningBypassed && !sslHooked) {
        send({
            type: "status",
            message: "FALLBACK: Could not hook Flutter SSL functions. " +
                     "Recommended alternatives:\n" +
                     "  1. Use reFlutter to patch the APK and disable SSL pinning\n" +
                     "  2. Use mitmproxy/Burp with a patched APK\n" +
                     "  3. Use Objection: objection -g <package> explore --startup-command 'android sslpinning disable'"
        });
    } else {
        send({
            type: "status",
            message: "Flutter/Dio hooks loaded. " +
                     "SSL pinning bypass: " + (pinningBypassed ? "active" : "failed") + ", " +
                     "SSL capture: " + (sslHooked ? "active" : "failed") + ". " +
                     "Note: request/response correlation is limited for HTTP/2 traffic."
        });
    }
})();
