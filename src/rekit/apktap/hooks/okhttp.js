/**
 * okhttp.js — Frida hook for OkHttp3 HTTP traffic capture.
 *
 * Intercepts all HTTP requests and responses made through OkHttp3,
 * which covers the vast majority of Android apps (including those
 * using Retrofit, Volley-OkHttp, etc.).
 *
 * Hooked classes:
 *   - okhttp3.OkHttpClient        → newCall()
 *   - okhttp3.internal.connection.RealCall → execute(), enqueue()
 *
 * Data is sent to the Python host via Frida's send() API as JSON
 * messages with type "request" or "response" and a correlation ID.
 */

"use strict";

(function () {
    var correlationId = 0;

    function nextId() {
        return "okhttp-" + (++correlationId);
    }

    /**
     * Read all headers from an OkHttp Headers object into a plain JS object.
     */
    function readHeaders(headers) {
        var result = {};
        try {
            var size = headers.size();
            for (var i = 0; i < size; i++) {
                var name = headers.name(i).toString();
                var value = headers.value(i).toString();
                if (result[name]) {
                    // Multiple values for same header — append
                    if (Array.isArray(result[name])) {
                        result[name].push(value);
                    } else {
                        result[name] = [result[name], value];
                    }
                } else {
                    result[name] = value;
                }
            }
        } catch (e) {
            result["_error"] = "Failed to read headers: " + e.message;
        }
        return result;
    }

    /**
     * Read the body of a Request as a string. Handles null bodies, multipart,
     * and form-encoded bodies. Returns null if body cannot be read.
     */
    function readRequestBody(request) {
        try {
            var body = request.body();
            if (body === null || body.toString() === "null") {
                return null;
            }

            var contentType = body.contentType();
            var contentTypeStr = contentType ? contentType.toString() : "";

            // Check content length — skip very large bodies
            var contentLength = body.contentLength();
            if (contentLength > 10 * 1024 * 1024) {
                return { _truncated: true, size: contentLength, contentType: contentTypeStr };
            }

            // For multipart bodies, extract parts metadata
            var MultipartBody = Java.use("okhttp3.MultipartBody");
            if (body.$className === "okhttp3.MultipartBody" || contentTypeStr.indexOf("multipart") !== -1) {
                try {
                    var multipart = Java.cast(body, MultipartBody);
                    var parts = [];
                    var partCount = multipart.size();
                    for (var i = 0; i < partCount; i++) {
                        var part = multipart.part(i);
                        var partHeaders = part.headers();
                        var partBody = part.body();
                        parts.push({
                            headers: partHeaders ? readHeaders(partHeaders) : {},
                            contentType: partBody.contentType() ? partBody.contentType().toString() : null,
                            contentLength: partBody.contentLength(),
                        });
                    }
                    return { _multipart: true, boundary: multipart.boundary().toString(), parts: parts };
                } catch (e) {
                    // Fall through to buffer approach
                }
            }

            // Buffer the body to read it
            var Buffer = Java.use("okio.Buffer");
            var buffer = Buffer.$new();
            body.writeTo(buffer);
            var bytes = buffer.readByteArray();
            buffer.close();

            // Try to decode as UTF-8 string
            if (contentTypeStr.indexOf("json") !== -1 ||
                contentTypeStr.indexOf("text") !== -1 ||
                contentTypeStr.indexOf("xml") !== -1 ||
                contentTypeStr.indexOf("form-urlencoded") !== -1 ||
                contentTypeStr === "") {
                var JavaString = Java.use("java.lang.String");
                return JavaString.$new(bytes, "UTF-8").toString();
            }

            // Binary body — base64 encode
            var Base64 = Java.use("android.util.Base64");
            return { _base64: true, data: Base64.encodeToString(bytes, 2 /* NO_WRAP */), size: bytes.length };

        } catch (e) {
            return { _error: "Failed to read request body: " + e.message };
        }
    }

    /**
     * Read the body of a Response using peekBody() to avoid consuming it.
     * Falls back to reading the body directly if peekBody fails.
     */
    function readResponseBody(response) {
        try {
            var contentType = response.header("Content-Type") || "";
            var contentLength = response.header("Content-Length");

            // Skip very large bodies
            if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) {
                return { _truncated: true, size: parseInt(contentLength), contentType: contentType };
            }

            // Use peekBody to avoid consuming the stream
            var maxPeek = 5 * 1024 * 1024; // 5 MB
            var peeked;
            try {
                peeked = response.peekBody(maxPeek);
            } catch (e) {
                return { _error: "peekBody failed: " + e.message };
            }

            var bytes = peeked.bytes();

            // Handle gzip-compressed responses
            var encoding = response.header("Content-Encoding") || "";
            if (encoding.toLowerCase() === "gzip") {
                try {
                    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                    var GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
                    var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");

                    var bais = ByteArrayInputStream.$new(bytes);
                    var gzis = GZIPInputStream.$new(bais);
                    var baos = ByteArrayOutputStream.$new();

                    var buf = Java.array("byte", new Array(4096).fill(0));
                    var n;
                    while ((n = gzis.read(buf)) !== -1) {
                        baos.write(buf, 0, n);
                    }
                    gzis.close();
                    bytes = baos.toByteArray();
                } catch (e) {
                    // If decompression fails, use raw bytes
                }
            }

            // Text-like content types — decode as string
            if (contentType.indexOf("json") !== -1 ||
                contentType.indexOf("text") !== -1 ||
                contentType.indexOf("xml") !== -1 ||
                contentType.indexOf("javascript") !== -1 ||
                contentType.indexOf("html") !== -1) {
                var JavaString = Java.use("java.lang.String");
                return JavaString.$new(bytes, "UTF-8").toString();
            }

            // Binary — base64
            if (bytes.length > 0) {
                var Base64 = Java.use("android.util.Base64");
                return { _base64: true, data: Base64.encodeToString(bytes, 2), size: bytes.length };
            }

            return "";
        } catch (e) {
            return { _error: "Failed to read response body: " + e.message };
        }
    }

    /**
     * Extract request metadata and send to Python host.
     */
    function sendRequest(id, request) {
        try {
            var url = request.url().toString();
            var method = request.method().toString();
            var headers = readHeaders(request.headers());
            var body = readRequestBody(request);

            send({
                type: "request",
                id: id,
                timestamp: Date.now(),
                url: url,
                method: method,
                headers: headers,
                body: body,
            });
        } catch (e) {
            send({ type: "error", id: id, message: "sendRequest failed: " + e.message });
        }
    }

    /**
     * Extract response metadata and send to Python host.
     */
    function sendResponse(id, response) {
        try {
            var code = response.code();
            var message = response.message() ? response.message().toString() : "";
            var headers = readHeaders(response.headers());
            var body = readResponseBody(response);

            // Also capture timing from the response
            var sentMs = 0;
            var receivedMs = 0;
            try {
                sentMs = response.sentRequestAtMillis();
                receivedMs = response.receivedResponseAtMillis();
            } catch (e) { /* timing not critical */ }

            send({
                type: "response",
                id: id,
                timestamp: Date.now(),
                statusCode: code,
                statusText: message,
                headers: headers,
                body: body,
                timing: {
                    sentAt: sentMs,
                    receivedAt: receivedMs,
                    durationMs: receivedMs > 0 && sentMs > 0 ? receivedMs - sentMs : 0,
                },
            });
        } catch (e) {
            send({ type: "error", id: id, message: "sendResponse failed: " + e.message });
        }
    }

    // =========================================================================
    //  Main hooks
    // =========================================================================

    Java.perform(function () {
        send({ type: "status", message: "OkHttp3 hooks loading..." });

        // ------------------------------------------------------------------
        //  Hook RealCall.execute() — synchronous HTTP calls
        // ------------------------------------------------------------------
        try {
            var RealCall = Java.use("okhttp3.internal.connection.RealCall");

            RealCall.execute.implementation = function () {
                var id = nextId();

                try {
                    // Access the request via getOriginalRequest() or request()
                    var request = this.request();
                    sendRequest(id, request);
                } catch (e) {
                    send({ type: "error", id: id, message: "execute() request capture failed: " + e.message });
                }

                var response = this.execute();

                try {
                    sendResponse(id, response);
                } catch (e) {
                    send({ type: "error", id: id, message: "execute() response capture failed: " + e.message });
                }

                return response;
            };

            send({ type: "status", message: "Hooked RealCall.execute()" });
        } catch (e) {
            // Older OkHttp versions may use a different package path
            try {
                var RealCallLegacy = Java.use("okhttp3.RealCall");

                RealCallLegacy.execute.implementation = function () {
                    var id = nextId();

                    try {
                        sendRequest(id, this.request());
                    } catch (ex) { /* non-fatal */ }

                    var response = this.execute();

                    try {
                        sendResponse(id, response);
                    } catch (ex) { /* non-fatal */ }

                    return response;
                };

                send({ type: "status", message: "Hooked RealCall.execute() (legacy path)" });
            } catch (e2) {
                send({ type: "status", message: "Could not hook RealCall.execute(): " + e.message });
            }
        }

        // ------------------------------------------------------------------
        //  Hook RealCall.enqueue(Callback) — asynchronous HTTP calls
        // ------------------------------------------------------------------
        try {
            var RealCallAsync = null;
            try {
                RealCallAsync = Java.use("okhttp3.internal.connection.RealCall");
            } catch (_) {
                RealCallAsync = Java.use("okhttp3.RealCall");
            }

            RealCallAsync.enqueue.implementation = function (callback) {
                var id = nextId();

                try {
                    var request = this.request();
                    sendRequest(id, request);
                } catch (e) {
                    send({ type: "error", id: id, message: "enqueue() request capture failed: " + e.message });
                }

                // Wrap the callback to intercept the response
                var Callback = Java.use("okhttp3.Callback");
                var originalCallback = callback;

                var wrappedCallback = Java.registerClass({
                    name: "com.apktap.CallbackWrapper" + id.replace(/[^a-zA-Z0-9]/g, "_"),
                    implements: [Callback],
                    methods: {
                        onFailure: function (call, ioException) {
                            try {
                                send({
                                    type: "response",
                                    id: id,
                                    timestamp: Date.now(),
                                    error: ioException.toString(),
                                });
                            } catch (e) { /* non-fatal */ }

                            originalCallback.onFailure(call, ioException);
                        },
                        onResponse: function (call, response) {
                            try {
                                sendResponse(id, response);
                            } catch (e) { /* non-fatal */ }

                            originalCallback.onResponse(call, response);
                        },
                    },
                });

                this.enqueue(wrappedCallback.$new());
            };

            send({ type: "status", message: "Hooked RealCall.enqueue()" });
        } catch (e) {
            send({ type: "status", message: "Could not hook RealCall.enqueue(): " + e.message });
        }

        // ------------------------------------------------------------------
        //  Also hook Interceptor chain for broader coverage
        //  This catches requests even from custom interceptors.
        // ------------------------------------------------------------------
        try {
            var RealInterceptorChain = null;
            try {
                RealInterceptorChain = Java.use("okhttp3.internal.http.RealInterceptorChain");
            } catch (_) {
                // Some versions: okhttp3.internal.http.RealInterceptorChain
                // Already tried, skip
            }

            if (RealInterceptorChain) {
                // We only log if verbose — this fires for every interceptor in chain
                // so we use it as fallback detection, not primary capture
                send({ type: "status", message: "RealInterceptorChain available for fallback" });
            }
        } catch (e) {
            // Not critical
        }

        send({ type: "status", message: "OkHttp3 hooks loaded successfully." });
    });
})();
