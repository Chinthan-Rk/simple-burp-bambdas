/*
 * Insecure Cookie Filter
 *
 * Purpose:
 *   Show only responses that set cookies without the "Secure" or "HttpOnly" flag.
 *
 * Placement:
 *   Burp → HTTP history → Filter → Script mode.
 *
 * Return:
 *   boolean (true = show request, false = hide).
 */

if (!requestResponse.hasResponse()) {
    return false;
}

for (var h : requestResponse.response().headers()) {
    if (h.name().equalsIgnoreCase("Set-Cookie")) {
        String v = h.value().toLowerCase();
        if (!v.contains("secure") || !v.contains("httponly")) {
            return true;
        }
    }
}
return false;
