/*
 * Sensitive Response Cacheability — HTTP history filter (Bambda)
 *
 * Purpose:
 *   Show only responses that:
 *     (A) set what looks like a sensitive/session cookie, AND
 *     (B) have weak or missing cache controls (i.e., might be cached by browser/CDN).
 *
 * Why this matters:
 *   - Private pages that set session/jwt cookies should generally be non-cacheable.
 *   - Weak cache headers can leak user data via shared proxies/CDNs or shared browsers.
 *
 * Placement:
 *   Burp → Proxy → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show row, false = hide row)
 *
 * Heuristics:
 *   - We treat cookies whose names include: session, jwt, token, auth, sid as "sensitive".
 *   - We consider a response "safe" if Cache-Control contains any of:
 *       no-store, no-cache, private, must-revalidate
 *     or if Pragma: no-cache is present (legacy).
 *   - We flag as risky when:
 *       - Cache-Control is missing, OR
 *       - It contains "public" or explicit caching (max-age/s-maxage) WITHOUT also having a protective directive.
 *
 * Tuning:
 *   - Adjust SENSITIVE_KEYS to your target app conventions.
 *   - If noise appears, narrow the match (e.g., require cookie attributes like HttpOnly/Secure),
 *     or require certain paths/methods.
 */

if (!requestResponse.hasResponse()) {
    return false; // nothing to analyze
}

var resp = requestResponse.response();

// ---------- (A) Detect if the response sets a "sensitive" cookie ----------
String[] SENSITIVE_KEYS = new String[] { "session", "jwt", "token", "auth", "sid" };
boolean setsSensitiveCookie = false;

for (var h : resp.headers()) {
    if (!"Set-Cookie".equalsIgnoreCase(h.name())) continue;

    String v = h.value();
    if (v == null || v.isEmpty()) continue;

    String vLow = v.toLowerCase();
    // Quick name hit (before first ';' is cookie name/value)
    int semi = vLow.indexOf(';');
    String firstPart = (semi >= 0 ? vLow.substring(0, semi) : vLow);

    for (String key : SENSITIVE_KEYS) {
        if (firstPart.contains(key)) {
            setsSensitiveCookie = true;
            break;
        }
    }
    if (setsSensitiveCookie) break;
}

if (!setsSensitiveCookie) {
    return false; // no sensitive cookie => not our target
}

// ---------- (B) Evaluate cache directives ----------
String cc = resp.headerValue("Cache-Control");
String pragma = resp.headerValue("Pragma");

String ccLow = (cc == null ? "" : cc.toLowerCase());
String pragmaLow = (pragma == null ? "" : pragma.toLowerCase());

// Protective directives (any of these is considered acceptable hardening)
boolean hasNoStore        = ccLow.contains("no-store");
boolean hasNoCache        = ccLow.contains("no-cache");
boolean hasPrivate        = ccLow.contains("private");
boolean hasMustRevalidate = ccLow.contains("must-revalidate");
boolean pragmaNoCache     = pragmaLow.contains("no-cache");

// Risky/public caching signals
boolean hasPublic   = ccLow.contains("public");
boolean hasMaxAge   = ccLow.contains("max-age");   // includes s-maxage as substring check
boolean hasSMaxAge  = ccLow.contains("s-maxage");

// If there is NO Cache-Control and NO Pragma: no-cache => risky
if (ccLow.isEmpty() && !pragmaNoCache) {
    return true;
}

// If there are protective directives, we consider it fine (don’t show)
// (You can tighten this to require no-store if you want stricter checks.)
boolean hasProtective = hasNoStore || hasNoCache || hasPrivate || hasMustRevalidate || pragmaNoCache;
if (hasProtective) {
    return false; // looks sufficiently protected
}

// If explicitly public or cacheable with max-age/s-maxage (and no protective flag) => risky
if (hasPublic || hasMaxAge || hasSMaxAge) {
    return true;
}

// Otherwise, no explicit protection + some other Cache-Control present => still risky
// (e.g., "Cache-Control: immutable" without private/no-store)
if (!ccLow.isEmpty() && !hasProtective) {
    return true;
}

return false;
