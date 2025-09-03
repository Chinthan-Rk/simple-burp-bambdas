/*
 * Secrets Pattern Finder — HTTP history filter (Bambda)
 *
 * Purpose:
 *   Show only responses whose BODY (and optionally headers) look like they
 *   contain secrets: API keys, access tokens, basic auth, private key blocks,
 *   AWS-style credentials, etc.
 *
 * Placement:
 *   Burp → Proxy → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show row, false = hide row)
 *
 * Notes:
 *   - Heuristics, not proof. Tune PATTERNS to your environment.
 *   - Keeps it body-focused by default to avoid header noise; flip BODY_ONLY=false
 *     to also scan response headers.
 */

if (!requestResponse.hasResponse()) {
    return false;
}

final boolean BODY_ONLY = true; // set to false if you also want to scan response headers

// ---------- Patterns (tune as needed) ----------
// Keep them relatively specific and long to reduce noise.
java.util.regex.Pattern[] PATTERNS = new java.util.regex.Pattern[] {
    // Generic bearer/JWT-like tokens
    java.util.regex.Pattern.compile("\\bBearer\\s+[A-Za-z0-9\\-_=]+\\.[A-Za-z0-9\\-_=]+\\.[A-Za-z0-9\\-_=]+"),
    // Generic API key/value hints
    java.util.regex.Pattern.compile("(?i)api[_-]?key\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{16,}['\\\"]"),
    java.util.regex.Pattern.compile("(?i)access[_-]?token\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{16,}['\\\"]"),
    java.util.regex.Pattern.compile("(?i)secret\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{12,}['\\\"]"),
    // Basic auth in URLs (rare but useful)
    java.util.regex.Pattern.compile("https?://[A-Za-z0-9._%+-]{3,}:[^@\\s]{6,}@"),
    // AWS access key id (AKIA/ASIA) – rough heuristic
    java.util.regex.Pattern.compile("\\b(AKIA|ASIA)[A-Z0-9]{16}\\b"),
    // AWS secret access key – 40 base64-like chars
    java.util.regex.Pattern.compile("(?i)aws(.{0,15})secret(.{0,15})[:=]\\s*['\\\"][A-Za-z0-9/+=]{35,}['\\\"]"),
    // Private key blocks
    java.util.regex.Pattern.compile("-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    // OAuth client secrets (generic)
    java.util.regex.Pattern.compile("(?i)client[_-]?secret\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{10,}['\\\"]")
};

var resp = requestResponse.response();

// ---------- Check body ----------
String body = resp.bodyToString();
if (body != null && !body.isEmpty()) {
    for (var pat : PATTERNS) {
        if (pat.matcher(body).find()) {
            return true;
        }
    }
}

// ---------- (Optional) check headers too ----------
if (!BODY_ONLY) {
    for (var h : resp.headers()) {
        String v = h.value();
        if (v == null || v.isEmpty()) continue;
        for (var pat : PATTERNS) {
            if (pat.matcher(v).find()) {
                return true;
            }
        }
    }
}

return false;
