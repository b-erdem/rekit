/**
 * webview.js — Frida hook for Android WebView HTTP traffic capture.
 *
 * Intercepts HTTP requests made through Android WebView components
 * by hooking WebViewClient.shouldInterceptRequest().
 *
 * Hooked classes:
 *   - android.webkit.WebViewClient → shouldInterceptRequest()
 *
 * This captures navigation requests, XHR/fetch from JS in the WebView,
 * and resource loads (images, scripts, etc.).
 */

"use strict";

(function () {
    var correlationId = 0;

    function nextId() {
        return "webview-" + (++correlationId);
    }

    /**
     * Extract headers from a WebResourceRequest object.
     */
    function extractHeaders(webResourceRequest) {
        var headers = {};
        try {
            var headerMap = webResourceRequest.getRequestHeaders();
            if (headerMap !== null) {
                var entrySet = headerMap.entrySet();
                var iterator = entrySet.iterator();
                while (iterator.hasNext()) {
                    var entry = iterator.next();
                    headers[entry.getKey().toString()] = entry.getValue().toString();
                }
            }
        } catch (e) {
            headers["_error"] = "Failed to read headers: " + e.message;
        }
        return headers;
    }

    /**
     * Read a WebResourceResponse body if available.
     */
    function readWebResourceResponseBody(response) {
        try {
            if (response === null) return null;
            var stream = response.getData();
            if (stream === null) return null;

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
            if (bytes.length > 2 * 1024 * 1024) {
                return { _truncated: true, size: bytes.length };
            }

            var mimeType = response.getMimeType();
            var mt = mimeType ? mimeType.toString().toLowerCase() : "";
            if (mt.indexOf("json") !== -1 || mt.indexOf("text") !== -1 ||
                mt.indexOf("xml") !== -1 || mt.indexOf("html") !== -1 ||
                mt.indexOf("javascript") !== -1) {
                var JavaString = Java.use("java.lang.String");
                return JavaString.$new(bytes, "UTF-8").toString();
            }

            var Base64 = Java.use("android.util.Base64");
            return { _base64: true, data: Base64.encodeToString(bytes, 2), size: bytes.length };
        } catch (e) {
            return { _error: "Failed to read response: " + e.message };
        }
    }

    // =========================================================================
    //  Main hooks
    // =========================================================================

    Java.perform(function () {
        send({ type: "status", message: "WebView hooks loading..." });

        var WebViewClient = Java.use("android.webkit.WebViewClient");

        // ------------------------------------------------------------------
        //  Hook shouldInterceptRequest (API 21+, with WebResourceRequest)
        // ------------------------------------------------------------------
        try {
            // Overload with WebResourceRequest (API 21+)
            WebViewClient.shouldInterceptRequest.overload(
                "android.webkit.WebView",
                "android.webkit.WebResourceRequest"
            ).implementation = function (webView, request) {
                var id = nextId();

                try {
                    var url = request.getUrl().toString();
                    var method = request.getMethod() ? request.getMethod().toString() : "GET";
                    var headers = extractHeaders(request);
                    var isForMainFrame = request.isForMainFrame();

                    send({
                        type: "request",
                        id: id,
                        timestamp: Date.now(),
                        url: url,
                        method: method,
                        headers: headers,
                        body: null,
                        _source: "webview",
                        _isMainFrame: isForMainFrame,
                    });
                } catch (e) {
                    send({ type: "error", id: id, message: "WebView request capture: " + e.message });
                }

                // Call original
                var response = this.shouldInterceptRequest(webView, request);

                // If the WebViewClient returns a custom response, try to capture it
                if (response !== null) {
                    try {
                        var statusCode = 200;
                        try {
                            statusCode = response.getStatusCode();
                        } catch (e) { /* API 21 doesn't have getStatusCode */ }

                        var responseHeaders = {};
                        try {
                            var rHeaders = response.getResponseHeaders();
                            if (rHeaders !== null) {
                                var entrySet = rHeaders.entrySet();
                                var iter = entrySet.iterator();
                                while (iter.hasNext()) {
                                    var entry = iter.next();
                                    responseHeaders[entry.getKey().toString()] = entry.getValue().toString();
                                }
                            }
                        } catch (e) { /* non-fatal */ }

                        send({
                            type: "response",
                            id: id,
                            timestamp: Date.now(),
                            statusCode: statusCode,
                            statusText: "",
                            headers: responseHeaders,
                            body: null, // Reading the stream would consume it
                            _source: "webview",
                            _intercepted: true,
                        });
                    } catch (e) {
                        send({ type: "error", id: id, message: "WebView response capture: " + e.message });
                    }
                }

                return response;
            };

            send({ type: "status", message: "Hooked shouldInterceptRequest(WebView, WebResourceRequest)" });
        } catch (e) {
            send({ type: "status", message: "Could not hook shouldInterceptRequest (API 21+): " + e.message });
        }

        // ------------------------------------------------------------------
        //  Hook shouldInterceptRequest (legacy, URL string only)
        // ------------------------------------------------------------------
        try {
            WebViewClient.shouldInterceptRequest.overload(
                "android.webkit.WebView",
                "java.lang.String"
            ).implementation = function (webView, urlString) {
                var id = nextId();

                try {
                    send({
                        type: "request",
                        id: id,
                        timestamp: Date.now(),
                        url: urlString.toString(),
                        method: "GET",
                        headers: {},
                        body: null,
                        _source: "webview_legacy",
                    });
                } catch (e) { /* non-fatal */ }

                return this.shouldInterceptRequest(webView, urlString);
            };

            send({ type: "status", message: "Hooked shouldInterceptRequest(WebView, String)" });
        } catch (e) {
            // Legacy overload may not exist — that's fine
        }

        // ------------------------------------------------------------------
        //  Hook WebView.loadUrl to track navigation
        // ------------------------------------------------------------------
        try {
            var WebView = Java.use("android.webkit.WebView");

            WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
                send({
                    type: "request",
                    id: nextId(),
                    timestamp: Date.now(),
                    url: url.toString(),
                    method: "GET",
                    headers: {},
                    body: null,
                    _source: "webview_loadUrl",
                });
                return this.loadUrl(url);
            };

            // loadUrl with extra headers
            try {
                WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, additionalHeaders) {
                    var headers = {};
                    try {
                        if (additionalHeaders !== null) {
                            var entrySet = additionalHeaders.entrySet();
                            var iter = entrySet.iterator();
                            while (iter.hasNext()) {
                                var entry = iter.next();
                                headers[entry.getKey().toString()] = entry.getValue().toString();
                            }
                        }
                    } catch (e) { /* non-fatal */ }

                    send({
                        type: "request",
                        id: nextId(),
                        timestamp: Date.now(),
                        url: url.toString(),
                        method: "GET",
                        headers: headers,
                        body: null,
                        _source: "webview_loadUrl",
                    });
                    return this.loadUrl(url, additionalHeaders);
                };
            } catch (e) { /* overload may not exist */ }

            send({ type: "status", message: "Hooked WebView.loadUrl()" });
        } catch (e) {
            send({ type: "status", message: "Could not hook WebView.loadUrl: " + e.message });
        }

        // ------------------------------------------------------------------
        //  Hook WebView.postUrl for POST requests via WebView
        // ------------------------------------------------------------------
        try {
            var WebView = Java.use("android.webkit.WebView");
            WebView.postUrl.implementation = function (url, postData) {
                var body = null;
                try {
                    if (postData !== null) {
                        var JavaString = Java.use("java.lang.String");
                        body = JavaString.$new(postData, "UTF-8").toString();
                    }
                } catch (e) { /* non-fatal */ }

                send({
                    type: "request",
                    id: nextId(),
                    timestamp: Date.now(),
                    url: url.toString(),
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    body: body,
                    _source: "webview_postUrl",
                });

                return this.postUrl(url, postData);
            };
            send({ type: "status", message: "Hooked WebView.postUrl()" });
        } catch (e) {
            // Not all apps use postUrl
        }

        send({ type: "status", message: "WebView hooks loaded successfully." });
    });
})();
