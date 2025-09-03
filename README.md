# simple-burp-bambdas

A small, practical collection of **Burp Suite Bambdas** (script-mode snippets) I use during web app pentests.  
These are lightweight Java snippets you paste into Burp’s **Filter**, **Custom column**, or **Match & replace** editors.

> This repository is a **public mirror** of my private working repo. Development happens privately; `main` here is mirrored on release.

---

## Contents

### Filters (HTTP history → Filter → Script mode)

- **insecure_cookie_filter.java** – Show responses that set cookies missing `Secure` / `HttpOnly`.
- **token/reflection filters**
  - `header_value_reflection.java` – Show rows where a request _header value_ is reflected in response (body/headers).
  - `param_value_reflection.java` – Show rows where a request _param value_ is reflected in response (body/headers).
- **content_type_json_mismatch_filter.java** – JSON-looking body but non-JSON `Content-Type`.
- **cors_risk_filter.java** – Flags risky CORS (e.g., `ACAO:*` + `ACC:true`, origin echo w/o `Vary: Origin`).
- **sensitive_cacheability_filter.java** – Sets “sensitive” cookies but weak/missing cache headers.
- **ssrf_param_finder_filter.java** – Surfaces likely SSRF params (strict name/value heuristics).
- **secrets_pattern_filter.java** – Finds common secrets/keys/tokens in response bodies.
- **missing_security_headers_filter.java** – Flags missing/weak CSP, XFO, XCTO, RP, PP, HSTS.

### Match & Replace (Proxy → Match & replace → Script mode)

- **x_forwarded_for_header.java** – Adds/overwrites `X-Forwarded-For` with a spoofed IP on every request.

---

## How to use (quick)

1. Open the target Burp tool (e.g., **Proxy → HTTP history**).
2. Click the filter / column / match & replace **“Script mode”** editor.
3. Paste the snippet and **Apply**.
4. For filters: `true` = row shown, `false` = hidden.  
   For match & replace: return the modified `HttpRequest`.

> Tested with Burp Suite Professional (Montoya API). Some features require Pro.

---

## Notes

- **Heuristics, not proof.** Filters are designed to _surface interesting traffic_. Expect some false positives.
- Tune thresholds (e.g., minimum length) or keyword lists per target to reduce noise.
- Avoid running noisy match/replace rules against production unless you know what you’re doing.

---

## License

MIT – see [LICENSE](LICENSE).
