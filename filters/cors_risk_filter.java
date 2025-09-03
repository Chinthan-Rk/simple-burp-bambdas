/*
 * CORS Risk Highlighter — HTTP history filter (Bambda)
 *
 * Purpose:
 *   Show only responses that likely have risky CORS behavior.
 *   We flag three common high-signal cases:
 *
 *   [HIGH]  ACAO: *   AND  ACC: true
 *   [HIGH]  ACAO echoes request Origin   AND  ACC: true
 *   [MED]   ACAO echoes request Origin   AND  missing/weak Vary: Origin
 *
 * Placement:
 *   Burp → Proxy → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show row, false = hide row)
 *
 * Notes:
 *   - ACAO  = Access-Control-Allow-Origin
 *   - ACC   = Access-Control-Allow-Credentials
 *   - We do exact string checks; adjust toLowerCase() as needed.
 */

if (!requestResponse.hasResponse()) {
    return false; // nothing to analyze
}

var req  = requestResponse.request();
var resp = requestResponse.response();

// --------- Fetch headers (trimmed + lower-cased for safer checks) ---------
String acao = resp.headerValue("Access-Control-Allow-Origin");
String acc  = resp.headerValue("Access-Control-Allow-Credentials");
String vary = resp.headerValue("Vary");
String originReq = req.headerValue("Origin");

// Normalize
String acaoVal = (acao == null ? "" : acao.trim());
String accVal  = (acc  == null ? "" : acc.trim());
String varyVal = (vary == null ? "" : vary.trim());
String origin  = (originReq == null ? "" : originReq.trim());

// Lower-case helpers
String acaoLC = acaoVal.toLowerCase();
String accLC  = accVal.toLowerCase();
String varyLC = varyVal.toLowerCase();

// --------- Case 1: wildcard + credentials (always bad) ---------
if (!acaoVal.isEmpty() && acaoLC.equals("*") && accLC.equals("true")) {
    return true; // [HIGH] ACAO:* with credentials
}

// --------- Case 2: echo of Origin + credentials ---------
if (!acaoVal.isEmpty() && !origin.isEmpty() && acaoVal.equals(origin) && accLC.equals("true")) {
    return true; // [HIGH] reflected origin with credentials
}

// --------- Case 3: echo of Origin but missing/weak Vary: Origin ---------
// When the server reflects the request Origin, you generally want Vary: Origin
// to avoid caches serving one origin's response to others.
if (!acaoVal.isEmpty() && !origin.isEmpty() && acaoVal.equals(origin)) {
    // Vary must include "origin" (case-insensitive). If Vary missing or doesn't include it -> risk.
    boolean varyHasOrigin = !varyVal.isEmpty() && varyLC.contains("origin");
    if (!varyHasOrigin) {
        return true; // [MED] reflected origin without Vary: Origin
    }
}

// Otherwise, not flagged as risky by our heuristics
return false;
