/**
 * urlconnection.js — Frida hook for java.net.HttpURLConnection traffic capture.
 *
 * Intercepts HTTP requests and responses made through the legacy
 * java.net.HttpURLConnection API, including HTTPS via HttpsURLConnection.
 *
 * Hooked classes:
 *   - java.net.URL                    → openConnection()
 *   - java.net.HttpURLConnection      → getInputStream(), getOutputStream(),
 *                                       connect(), getResponseCode()
 *   - javax.net.ssl.HttpsURLConnection (inherits from above)
 *
 * Strategy: We attach metadata to each connection object and capture
 * request info at connect-time, response info at getInputStream-time.
 */

"use strict";

(function () {
    var correlationId = 0;
    var connectionMap = {};

    function nextId() {
        return "urlconn-" + (++correlationId);
    }

    /**
     * Extract all request headers that have been set on a connection.
     * Uses reflection to access the internal requests field.
     */
    function getRequestHeaders(conn) {
        var headers = {};
        try {
            var props = conn.getRequestProperties();
            var entrySet = props.entrySet();
            var iterator = entrySet.iterator();
            while (iterator.hasNext()) {
                var entry = iterator.next();
                var key = entry.getKey().toString();
                var values = entry.getValue();
                // values is a List<String>
                if (values.size() === 1) {
                    headers[key] = values.get(0).toString();
                } else {
                    var arr = [];
                    for (var i = 0; i < values.size(); i++) {
                        arr.push(values.get(i).toString());
                    }
                    headers[key] = arr;
                }
            }
        } catch (e) {
            // getRequestProperties() may throw if already connected
            headers["_error"] = "Could not read request headers: " + e.message;
        }
        return headers;
    }

    /**
     * Extract all response headers from a connection.
     */
    function getResponseHeaders(conn) {
        var headers = {};
        try {
            var headerFields = conn.getHeaderFields();
            if (headerFields === null) return headers;

            var entrySet = headerFields.entrySet();
            var iterator = entrySet.iterator();
            while (iterator.hasNext()) {
                var entry = iterator.next();
                var key = entry.getKey();
                if (key === null) continue; // Status line has null key
                key = key.toString();
                var values = entry.getValue();
                if (values.size() === 1) {
                    headers[key] = values.get(0).toString();
                } else {
                    var arr = [];
                    for (var i = 0; i < values.size(); i++) {
                        arr.push(values.get(i).toString());
                    }
                    headers[key] = arr;
                }
            }
        } catch (e) {
            headers["_error"] = "Could not read response headers: " + e.message;
        }
        return headers;
    }

    /**
     * Read an InputStream fully into a byte array, then return a string or base64.
     * IMPORTANT: We re-create the stream so the app can still read it.
     */
    function readInputStream(stream, contentType) {
        try {
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            var baos = ByteArrayOutputStream.$new();
            var buf = Java.array("byte", new Array(4096).fill(0));
            var n;

            while ((n = stream.read(buf)) !== -1) {
                baos.write(buf, 0, n);
            }

            var bytes = baos.toByteArray();
            baos.close();

            if (bytes.length === 0) return "";

            // Cap at 5 MB
            if (bytes.length > 5 * 1024 * 1024) {
                return { _truncated: true, size: bytes.length };
            }

            var ct = (contentType || "").toLowerCase();
            if (ct.indexOf("json") !== -1 || ct.indexOf("text") !== -1 ||
                ct.indexOf("xml") !== -1 || ct.indexOf("html") !== -1 ||
                ct.indexOf("javascript") !== -1 || ct === "") {
                var JavaString = Java.use("java.lang.String");
                return JavaString.$new(bytes, "UTF-8").toString();
            }

            var Base64 = Java.use("android.util.Base64");
            return { _base64: true, data: Base64.encodeToString(bytes, 2), size: bytes.length };
        } catch (e) {
            return { _error: "Failed to read stream: " + e.message };
        }
    }

    /**
     * Get or create a correlation ID for a connection object.
     */
    function getConnId(conn) {
        var hash = conn.hashCode().toString();
        if (!connectionMap[hash]) {
            connectionMap[hash] = {
                id: nextId(),
                requestSent: false,
            };
        }
        return connectionMap[hash];
    }

    // =========================================================================
    //  Main hooks
    // =========================================================================

    Java.perform(function () {
        send({ type: "status", message: "HttpURLConnection hooks loading..." });

        var HttpURLConnection = Java.use("java.net.HttpURLConnection");

        // ------------------------------------------------------------------
        //  Hook setRequestProperty — track headers being set
        // ------------------------------------------------------------------
        try {
            HttpURLConnection.setRequestProperty.implementation = function (key, value) {
                var info = getConnId(this);
                if (!info.customHeaders) info.customHeaders = {};
                info.customHeaders[key.toString()] = value.toString();
                return this.setRequestProperty(key, value);
            };
            send({ type: "status", message: "Hooked setRequestProperty()" });
        } catch (e) {
            send({ type: "status", message: "Could not hook setRequestProperty: " + e.message });
        }

        // ------------------------------------------------------------------
        //  Hook addRequestProperty — track multi-value headers
        // ------------------------------------------------------------------
        try {
            HttpURLConnection.addRequestProperty.implementation = function (key, value) {
                var info = getConnId(this);
                if (!info.customHeaders) info.customHeaders = {};
                var k = key.toString();
                if (info.customHeaders[k]) {
                    if (Array.isArray(info.customHeaders[k])) {
                        info.customHeaders[k].push(value.toString());
                    } else {
                        info.customHeaders[k] = [info.customHeaders[k], value.toString()];
                    }
                } else {
                    info.customHeaders[k] = value.toString();
                }
                return this.addRequestProperty(key, value);
            };
            send({ type: "status", message: "Hooked addRequestProperty()" });
        } catch (e) {
            // Not critical
        }

        // ------------------------------------------------------------------
        //  Hook getOutputStream — capture request body for POST/PUT
        // ------------------------------------------------------------------
        try {
            HttpURLConnection.getOutputStream.implementation = function () {
                var info = getConnId(this);
                var originalStream = this.getOutputStream();

                // We can't easily intercept what's written to the OutputStream
                // without replacing it. Send request metadata now.
                if (!info.requestSent) {
                    info.requestSent = true;
                    try {
                        send({
                            type: "request",
                            id: info.id,
                            timestamp: Date.now(),
                            url: this.getURL().toString(),
                            method: this.getRequestMethod().toString(),
                            headers: info.customHeaders || getRequestHeaders(this),
                            body: null, // Body written to OutputStream — hard to intercept
                            _note: "Request body written via OutputStream; body capture limited.",
                        });
                    } catch (e) {
                        send({ type: "error", id: info.id, message: "getOutputStream request capture: " + e.message });
                    }
                }

                return originalStream;
            };
            send({ type: "status", message: "Hooked getOutputStream()" });
        } catch (e) {
            send({ type: "status", message: "Could not hook getOutputStream: " + e.message });
        }

        // ------------------------------------------------------------------
        //  Hook getInputStream — capture response
        // ------------------------------------------------------------------
        try {
            HttpURLConnection.getInputStream.implementation = function () {
                var info = getConnId(this);

                // Send request if not already sent (GET requests don't call getOutputStream)
                if (!info.requestSent) {
                    info.requestSent = true;
                    try {
                        send({
                            type: "request",
                            id: info.id,
                            timestamp: Date.now(),
                            url: this.getURL().toString(),
                            method: this.getRequestMethod().toString(),
                            headers: info.customHeaders || getRequestHeaders(this),
                            body: null,
                        });
                    } catch (e) { /* non-fatal */ }
                }

                // Get the original input stream
                var originalStream = this.getInputStream();

                // Read the response body
                var contentType = this.getContentType() ? this.getContentType().toString() : "";
                var responseBody = null;

                try {
                    // Read the stream into a byte array
                    var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                    var baos = ByteArrayOutputStream.$new();
                    var buf = Java.array("byte", new Array(4096).fill(0));
                    var n;
                    while ((n = originalStream.read(buf)) !== -1) {
                        baos.write(buf, 0, n);
                    }
                    originalStream.close();

                    var bytes = baos.toByteArray();
                    baos.close();

                    // Decode body
                    if (bytes.length > 5 * 1024 * 1024) {
                        responseBody = { _truncated: true, size: bytes.length };
                    } else if (bytes.length > 0) {
                        var ct = contentType.toLowerCase();
                        if (ct.indexOf("json") !== -1 || ct.indexOf("text") !== -1 ||
                            ct.indexOf("xml") !== -1 || ct.indexOf("html") !== -1 || ct === "") {
                            var JavaString = Java.use("java.lang.String");
                            responseBody = JavaString.$new(bytes, "UTF-8").toString();
                        } else {
                            var Base64 = Java.use("android.util.Base64");
                            responseBody = { _base64: true, data: Base64.encodeToString(bytes, 2), size: bytes.length };
                        }
                    }

                    // Send response data
                    send({
                        type: "response",
                        id: info.id,
                        timestamp: Date.now(),
                        statusCode: this.getResponseCode(),
                        statusText: this.getResponseMessage() ? this.getResponseMessage().toString() : "",
                        headers: getResponseHeaders(this),
                        body: responseBody,
                    });

                    // Return a new InputStream from the buffered bytes so the app can still read
                    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                    return ByteArrayInputStream.$new(bytes);

                } catch (e) {
                    send({ type: "error", id: info.id, message: "getInputStream capture failed: " + e.message });
                    // Return original stream if we can; otherwise re-open
                    try {
                        return this.getInputStream();
                    } catch (e2) {
                        throw e;
                    }
                }
            };
            send({ type: "status", message: "Hooked getInputStream()" });
        } catch (e) {
            send({ type: "status", message: "Could not hook getInputStream: " + e.message });
        }

        // ------------------------------------------------------------------
        //  Hook getErrorStream — capture error responses (4xx, 5xx)
        // ------------------------------------------------------------------
        try {
            HttpURLConnection.getErrorStream.implementation = function () {
                var info = getConnId(this);
                var errorStream = this.getErrorStream();

                if (errorStream !== null) {
                    try {
                        var contentType = this.getContentType() ? this.getContentType().toString() : "";
                        var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                        var baos = ByteArrayOutputStream.$new();
                        var buf = Java.array("byte", new Array(4096).fill(0));
                        var n;
                        while ((n = errorStream.read(buf)) !== -1) {
                            baos.write(buf, 0, n);
                        }
                        errorStream.close();
                        var bytes = baos.toByteArray();
                        baos.close();

                        var bodyStr = null;
                        if (bytes.length > 0 && bytes.length < 5 * 1024 * 1024) {
                            var JavaString = Java.use("java.lang.String");
                            bodyStr = JavaString.$new(bytes, "UTF-8").toString();
                        }

                        send({
                            type: "response",
                            id: info.id,
                            timestamp: Date.now(),
                            statusCode: this.getResponseCode(),
                            statusText: this.getResponseMessage() ? this.getResponseMessage().toString() : "",
                            headers: getResponseHeaders(this),
                            body: bodyStr,
                            _isError: true,
                        });

                        var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                        return ByteArrayInputStream.$new(bytes);
                    } catch (e) {
                        send({ type: "error", id: info.id, message: "getErrorStream capture: " + e.message });
                    }
                }

                return errorStream;
            };
            send({ type: "status", message: "Hooked getErrorStream()" });
        } catch (e) {
            // Not critical
        }

        // Cleanup stale entries periodically
        setInterval(function () {
            var now = Date.now();
            var keys = Object.keys(connectionMap);
            if (keys.length > 1000) {
                // Drop oldest half
                var sorted = keys.sort(function (a, b) {
                    return (connectionMap[a].id > connectionMap[b].id) ? 1 : -1;
                });
                for (var i = 0; i < sorted.length / 2; i++) {
                    delete connectionMap[sorted[i]];
                }
            }
        }, 30000);

        send({ type: "status", message: "HttpURLConnection hooks loaded successfully." });
    });
})();
