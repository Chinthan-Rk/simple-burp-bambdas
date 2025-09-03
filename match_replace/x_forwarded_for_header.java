/*
 * Auto “X-Forwarded-For” — Match & Replace (Bambda)
 *
 * Purpose:
 *   Add or overwrite the X-Forwarded-For header on every outbound request
 *   to test IP-based trust/allow-lists or origin checks.
 *
 * Placement:
 *   Burp → Proxy → Match and replace → Add → Script mode.
 *
 * Return:
 *   HttpRequest (the modified request)
 *
 * Notes:
 *   - If the header already exists, we overwrite it.
 *   - Keep a single source-of-truth for the spoofed IP below.
 *   - To rotate a list of IPs per request, see the optional section.
 */

// --- configuration: set the spoofed IP here ---
final String SPOOF_IP = "127.0.0.1";

// Get the current request
var req = requestResponse.request();

// If header exists, update; else, add
String current = req.headerValue("X-Forwarded-For");
if (current != null) {
    req = req.withUpdatedHeader("X-Forwarded-For", SPOOF_IP);
} else {
    req = req.withAddedHeader("X-Forwarded-For", SPOOF_IP);
}

// Return the modified request (required in Match & Replace scripts)
return req;

/* ------------------ OPTIONAL: simple rotation ------------------
 * Replace the config + update block above with this if you want to
 * rotate a small set of IPs. Burp Bambda scripts are stateless, so
 * we choose deterministically based on the path hash.
 *
final String[] POOL = new String[] { "127.0.0.1", "10.0.0.7", "172.16.9.33", "192.168.50.5" };
var r = requestResponse.request();
int idx = Math.abs(r.path().hashCode()) % POOL.length;
String ip = POOL[idx];
String cur = r.headerValue("X-Forwarded-For");
if (cur != null) r = r.withUpdatedHeader("X-Forwarded-For", ip);
else             r = r.withAddedHeader("X-Forwarded-For", ip);
return r;
 * --------------------------------------------------------------- */
