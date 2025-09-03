/*
 * Reflection Detector — HEADERS only (HTTP history filter, Bambda)
 *
 * Purpose:
 *   Show only rows where a value from any REQUEST HEADER
 *   is reflected in the RESPONSE (either body or header values).
 *
 * Placement:
 *   Burp → Proxy → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show row, false = hide row)
 *
 * Heuristics:
 *   - Skip noisy/common headers via a stoplist.
 *   - Ignore very short values (length < MIN_LEN).
 *   - Case-sensitive match for precision; switch to lower-case if needed.
 */

if (!requestResponse.hasResponse()) {
    return false;
}

// ---------- Tunables ----------
final int MIN_LEN = 6; // ignore too-short header values

java.util.Set<String> headerStoplist = new java.util.HashSet<>(
    java.util.Arrays.asList(
        "host", "connection", "accept", "accept-encoding", "accept-language",
        "user-agent", "upgrade-insecure-requests", "pragma", "cache-control",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site",
        "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "referer", "origin"
    )
);

// ---------- Collect candidate header values from the REQUEST ----------
java.util.List<String> candidates = new java.util.ArrayList<>();

var req = requestResponse.request();
for (var h : req.headers()) {
    String name = h.name();
    if (name == null) continue;

    // skip noisy/common headers
    if (headerStoplist.contains(name.toLowerCase())) continue;

    String val = h.value();
    if (val != null && val.length() >= MIN_LEN) {
        candidates.add(val);
    }
}

if (candidates.isEmpty()) {
    return false;
}

// ---------- Check reflection in the RESPONSE (body + headers) ----------
var resp = requestResponse.response();

// (A) Response body
String respBody = resp.bodyToString();
if (respBody != null && !respBody.isEmpty()) {
    for (String c : candidates) {
        if (respBody.contains(c)) {
            return true;
        }
    }
}

// (B) Response headers (values)
for (var h : resp.headers()) {
    String v = h.value();
    if (v == null || v.length() < MIN_LEN) continue;
    for (String c : candidates) {
        if (v.contains(c)) {
            return true;
        }
    }
}

return false;
