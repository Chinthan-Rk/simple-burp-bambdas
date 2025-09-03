/*
 * Missing / Weak Security Headers — HTTP history filter (Bambda)
 *
 * Purpose:
 *   Show only responses that are missing or weakening common security headers.
 *
 * Placement:
 *   Burp → Proxy → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show row, false = hide row)
 *
 * Heuristics:
 *   - Flags if ANY of these is missing/weak:
 *     * Content-Security-Policy            (missing)
 *     * X-Frame-Options                    (missing or not DENY/SAMEORIGIN)
 *     * X-Content-Type-Options             (missing or not "nosniff")
 *     * Referrer-Policy                    (missing or weak)
 *     * Permissions-Policy                 (missing)  // presence-only check
 *     * Strict-Transport-Security          (missing when request is HTTPS)
 *
 * Tuning:
 *   - ONLY_HTML: if true, only analyze responses that look like HTML (to reduce noise).
 *   - RP_ALLOWED: adjust acceptable Referrer-Policy values for your org.
 *   - Logs the first reason found to the Output tab.
 */

if (!requestResponse.hasResponse()) {
    return false;
}

final boolean ONLY_HTML = true; // analyze only HTML-ish responses

var req  = requestResponse.request();
var resp = requestResponse.response();

// ---------- Content-Type gate (optional) ----------
String ct = resp.headerValue("Content-Type");
String ctLow = (ct == null ? "" : ct.toLowerCase());

// If ONLY_HTML: require text/html or no explicit CT but body looks like HTML
if (ONLY_HTML) {
    boolean ctHtml = (ctLow.contains("text/html"));
    if (!ctHtml) {
        // fallback: sniff simple HTML markers
        String body = resp.bodyToString();
        boolean looksHtml = body != null && (body.contains("<html") || body.contains("<script") || body.contains("<!DOCTYPE html"));
        if (!looksHtml) {
            return false;
        }
    }
}

// ---------- Fetch headers ----------
String csp = resp.headerValue("Content-Security-Policy");
String xfo = resp.headerValue("X-Frame-Options");
String xcto = resp.headerValue("X-Content-Type-Options");
String rp  = resp.headerValue("Referrer-Policy");
String pp  = resp.headerValue("Permissions-Policy");  // aka Feature-Policy (deprecated)
String hsts= resp.headerValue("Strict-Transport-Security");

// Lowercased helpers
String xfoLow  = (xfo  == null ? "" : xfo.toLowerCase().trim());
String xctoLow = (xcto == null ? "" : xcto.toLowerCase().trim());
String rpLow   = (rp   == null ? "" : rp.toLowerCase().trim());

// ---------- Rule: CSP present ----------
if (csp == null || csp.trim().isEmpty()) {
    logging.logToOutput("[SEC-HDR] Missing Content-Security-Policy");
    return true;
}

// ---------- Rule: X-Frame-Options strong ----------
if (xfoLow.isEmpty() || !(xfoLow.equals("deny") || xfoLow.equals("sameorigin"))) {
    logging.logToOutput("[SEC-HDR] X-Frame-Options missing/weak: " + xfo);
    return true;
}

// ---------- Rule: X-Content-Type-Options must be 'nosniff' ----------
if (!xctoLow.equals("nosniff")) {
    logging.logToOutput("[SEC-HDR] X-Content-Type-Options missing/!= nosniff: " + xcto);
    return true;
}

// ---------- Rule: Referrer-Policy acceptable ----------
String[] RP_ALLOWED = new String[] {
    "no-referrer", "same-origin",
    "strict-origin", "strict-origin-when-cross-origin",
    "no-referrer-when-downgrade"  // keep if you want to allow this; remove to be stricter
};
boolean rpOk = false;
for (String v : RP_ALLOWED) {
    if (rpLow.equals(v)) { rpOk = true; break; }
}
if (!rpOk) {
    logging.logToOutput("[SEC-HDR] Referrer-Policy missing/weak: " + rp);
    return true;
}

// ---------- Rule: Permissions-Policy presence-only check ----------
if (pp == null || pp.trim().isEmpty()) {
    logging.logToOutput("[SEC-HDR] Permissions-Policy missing");
    return true;
}

// ---------- Rule: HSTS required when request is HTTPS ----------
boolean reqIsHttps = req.httpService().secure(); // Montoya tells if scheme is https
if (reqIsHttps) {
    if (hsts == null || hsts.trim().isEmpty()) {
        logging.logToOutput("[SEC-HDR] Strict-Transport-Security missing on HTTPS response");
        return true;
    }
}

// If none of the rules tripped, hide the row
return false;
