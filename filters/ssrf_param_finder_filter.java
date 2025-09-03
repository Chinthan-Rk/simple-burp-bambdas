/*
 * SSRF Parameter Finder — HTTP history filter (Bambda, with debug)
 *
 * Purpose:
 *   Show only requests that look interesting for SSRF testing.
 *   Match if:
 *     (A) any PARAMETER NAME suggests SSRF (url, redirect, dest, next, return, image, file, callback, feed, link, domain, host, endpoint, api, ref, continue), OR
 *     (B) any PARAMETER VALUE looks like an external locator (http/https/ftp/file/gs/s3).
 *
 * Debug:
 *   Logs the exact reason (param name/value) when a row matches.
 *
 * Placement:
 *   Burp → Proxy → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show row, false = hide row)
 */

if (!requestResponse.hasResponse()) {
    return false;
}

var req = requestResponse.request();

// --- Tunables ---
String[] NAME_KEYWORDS = new String[] {
    "url","uri","redirect","return","next","dest","destination","target","to",
    "callback","cb","forward","fetch","load","link","image","img","file","path",
    "resource","endpoint","feed","rss","atom","proxy","upstream","uploadurl",
    "domain","host","hostname","port","scheme","proto","api","ref","reference",
    "continue","external","avatar","webhook"
};

String[] VALUE_PROTOCOLS = new String[] { "http://","https://","ftp://","file://","s3://","gs://" };

final int MIN_VAL_LEN = 6; // raise to 10–12 if noisy

// --- Check parameters ---
for (var p : req.parameters()) {
    // Optional: skip cookies (reduce noise)
    if (p.type() == burp.api.montoya.http.message.params.HttpParameterType.COOKIE) {
        continue;
    }

    String name = p.name();
    String value = p.value();

    // (A) Name-based
    if (name != null && !name.isEmpty()) {
        String n = name.toLowerCase();
        for (String kw : NAME_KEYWORDS) {
            if (n.equals(kw) || n.contains(kw)) {
                    logging.logToOutput(req.url().toString());
                logging.logToOutput("[SSRF-FINDER] Matched by NAME: " + name);
                return true;
            }
        }
    }

    // (B) Value-based (protocol prefixes)
    if (value != null && value.length() >= MIN_VAL_LEN) {
        String v = value.toLowerCase().trim();
        for (String proto : VALUE_PROTOCOLS) {
            if (v.startsWith(proto)) {
                    logging.logToOutput(req.url().toString());
                logging.logToOutput("[SSRF-FINDER] Matched by VALUE (proto): " + name + "=" + value);
                return true;
            }
        }
    }
}

return false;
