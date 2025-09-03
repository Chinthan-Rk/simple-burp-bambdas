/*
 * Content-Type vs Body Mismatch — JSON focus (HTTP history filter, Bambda)
 *
 * Purpose:
 *   Show only responses where the body "looks like JSON"
 *   but the Content-Type header does NOT say "application/json".
 *
 * Placement:
 *   Burp → Proxy → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show row, false = hide row)
 *
 * Why:
 *   - Misconfigured APIs sometimes serve JSON as text/html or text/plain.
 *   - This can cause client/proxy parsing confusion or bypass protections.
 */

if (!requestResponse.hasResponse()) {
    return false; // nothing to check
}

var resp = requestResponse.response();

// 1) Get Content-Type header
String ct = resp.headerValue("Content-Type");
String ctLower = (ct == null) ? "" : ct.toLowerCase();

// 2) Get body as string (be careful with large bodies)
String body = resp.bodyToString();
if (body == null || body.isEmpty()) {
    return false; // empty body, skip
}

String trimmed = body.trim();

// 3) Check if body "looks like JSON"
boolean looksJson = trimmed.startsWith("{") || trimmed.startsWith("[");

// 4) Mismatch condition: looks like JSON, but header not application/json
if (looksJson && !ctLower.contains("application/json")) {
    return true;
}

return false;
