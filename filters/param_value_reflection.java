/*
 * Reflection Detector — PARAMS only (HTTP history filter, Bambda)
 *
 * Purpose:
 *   Show only rows where a value from any REQUEST PARAMETER
 *   (URL/query, body/form, or cookie params) is reflected in the RESPONSE
 *   (either body or header values).
 *
 * Placement:
 *   Burp → Proxy → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show row, false = hide row)
 *
 * Notes:
 *   - Uses Montoya's req.parameters() which includes URL, BODY, COOKIE, etc.
 *   - Skips very short values to reduce noise (MIN_LEN).
 *   - Exact substring match; tighten MIN_LEN if you see noise.
 */

if (!requestResponse.hasResponse()) {
    return false; // nothing to analyze
}

// ---------- Tunables ----------
final int MIN_LEN = 6; // ignore too-short parameter values (raise to 12–20 if noisy)

// ---------- Collect candidate PARAMETER values from the REQUEST ----------
java.util.Set<String> candidates = new java.util.HashSet<>(); // de-dupe

var req = requestResponse.request();
for (var p : req.parameters()) {
    String v = p.value();
    if (v != null && v.length() >= MIN_LEN) {
        candidates.add(v);
    }
}

if (candidates.isEmpty()) {
    return false; // no param values to check
}

// ---------- Check reflection in the RESPONSE (body + headers) ----------
var resp = requestResponse.response();

// (A) Response body
String respBody = resp.bodyToString();
if (respBody != null && !respBody.isEmpty()) {
    for (String c : candidates) {
        if (respBody.contains(c)) {
            return true; // param value reflected in body
        }
    }
}

// (B) Response headers (values)
for (var h : resp.headers()) {
    String v = h.value();
    if (v == null || v.length() < MIN_LEN) continue;
    for (String c : candidates) {
        if (v.contains(c)) {
            return true; // param value reflected in header
        }
    }
}

return false; // no reflection detected
