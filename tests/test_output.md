# Security Audit Report — github.com

**Date:** 2026-11-13  
**Target:** `https://github.com`  
**Tools:** DNS Lookup · HTTP Header Inspector

---

## 🔍 DNS Lookup

No A/AAAA/MX records returned (network-filtered in scan environment). TXT records resolved successfully.

### TXT Records

| TTL (s) | Value / Service |
| :--- | :--- |
| 299 | `v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all` (**SPF**) |
| 299 | `TAILSCALE-xOzoDvFUzZr5YYVCQFuD` — Tailscale |
| 299 | `anthropic-domain-verification-4az7qn=if8YWuRRqwLycGJDooumzHtxm` — Anthropic |
| 299 | `openai-domain-verification=dv-3nh33eQwdkotMIAzLrIDVZo1` — OpenAI |
| 299 | `stripe-verification=f88ef17321660a01bab1660454192e014defa29ba7b8de9633c69d6b4912217f` — Stripe |
| 299 | `docusign=087098e3-3d46-47b7-9b4e-8a23028154cd` — DocuSign |
| 299 | `adobe-idp-site-verification=b92c9e999aef825edc36e0a3d847d2dbad5b2fc0e05c79ddd7a16139b48ecf4b` — Adobe IDP |
| 299 | `facebook-domain-verification=39xu4jzl7roi7x0n93ldkxjiaarx50` — Meta |
| 299 | `atlassian-domain-verification=jjgw98AKv2aeoYFxiL/VFaoyPkn3undEssTRuMg6C/3Fp/iqhkV4HVV7WjYlVeF8` — Atlassian |
| 299 | `google-site-verification=82Le34Flgtd15ojYhHlGF_6g72muSjamlMVThBOJpks` — Google (1) |
| 299 | `google-site-verification=UTM-3akMgubp6tQtgEuAkYNYLyYAvpTnnSrDMWoDR3o` — Google (2) |
| 299 | `MS=ms58704441` — Microsoft 365 (1) |
| 299 | `MS=6BF03E6AF5CB689E315FB6199603BABF2C88D805` — Microsoft 365 (2) |
| 299 | `MS=ms44452932` — Microsoft 365 (3) |
| 299 | `shopify-verification-code=t1YPwcmvnxZyBycaCpk1MPyWoFs72o` — Shopify |
| 299 | `loom-site-verification=f3787154f1154b7880e720a511ea664d` — Loom |
| 299 | `miro-verification=d2e174fdb00c71e0bcf58f8e58c3da2dd80dcfa9` — Miro |
| 299 | `krisp-domain-verification=ZlyiK7XLhnaoUQb2hpak1PLY7dFkl1WE` — Krisp |
| 299 | `calendly-site-verification=at0DQARi7IZvJtXQAWhMqpmIzpvoBNF7aam5VKKxP` — Calendly |
| 299 | `jamf-site-verification=XtaPNIYghF_e_xRDI8CjgQ` — Jamf |
| 299 | `cursor-domain-verification-gtfwmt=1rfLOtiTngX5QSxD5HvNKTvm3` — Cursor IDE |
| 299 | `serval-domain-verification-ydryhj=qbkiEakpwEpTvHh5fIiCqtaue` — Serval |
| 299 | `00Dd0000000hHE0=1TBKg000000TN2r` — Salesforce |

### DNS Findings

> **⚠️ SPF Softfail (`~all`):** SPF record ends with `~all` instead of `-all`. Spoofed email from unauthorized senders may pass recipient filters. Recommend tightening to `-all`.

---

## 🛡️ HTTP Header Security Audit

**URL:** `https://github.com`  
**Status:** `HTTP/2 200 OK`

### Header Results

| Header | Status | Value |
| :--- | :---: | :--- |
| `strict-transport-security` (HSTS) | ✅ PRESENT | `max-age=31536000; includeSubdomains; preload` |
| `content-security-policy` (CSP) | ✅ PRESENT | `default-src 'none'; base-uri 'self'; ...` *(see full value below)* |
| `x-frame-options` | ✅ PRESENT | `deny` |
| `x-content-type-options` | ✅ PRESENT | `nosniff` |
| `referrer-policy` | ✅ PRESENT | `origin-when-cross-origin, strict-origin-when-cross-origin` |
| `permissions-policy` | ❌ MISSING | — |
| Server Header | ⚠️ EXPOSED | `github.com` |
| X-Powered-By | ✅ HIDDEN | — |

### Full CSP Value

```
default-src 'none';
base-uri 'self';
child-src github.githubassets.com github.com/assets-cdn/worker/ github.com/assets/ gist.github.com/assets-cdn/worker/;
connect-src 'self' uploads.github.com www.githubstatus.com collector.github.com raw.githubusercontent.com api.github.com github-cloud.s3.amazonaws.com ... (truncated for brevity);
font-src github.githubassets.com;
form-action 'self' github.com gist.github.com copilot-workspace.githubnext.com objects-origin.githubusercontent.com;
frame-ancestors 'none';
frame-src viewscreen.githubusercontent.com notebooks.githubusercontent.com www.youtube-nocookie.com;
img-src 'self' data: blob: github.githubassets.com ...;
manifest-src 'self';
media-src github.com user-images.githubusercontent.com ...;
script-src github.githubassets.com 'sha256-6AKuI+cDd1MoUL1u4eqrA9PXmnPAkOB4h7421hPUUm0=';
style-src 'unsafe-inline' github.githubassets.com;
upgrade-insecure-requests;
worker-src github.githubassets.com github.com/assets-cdn/worker/ github.com/assets/ gist.github.com/assets-cdn/worker/;
```

---

## 📋 Summary & Recommendations

| # | Severity | Finding | Recommendation |
| :--- | :---: | :--- | :--- |
| 1 | 🟡 Low | SPF uses `~all` (softfail) | Change to `-all` to enforce hard rejection of unauthorized senders |
| 2 | 🟡 Low | `Permissions-Policy` header missing | Add policy restricting camera, microphone, geolocation, etc. |
| 3 | 🟢 Info | Server header leaks `github.com` | Suppress or genericize server header to reduce fingerprinting |

### Positives

- ✅ HSTS with `preload` and `includeSubdomains` — full HTTPS enforcement
- ✅ Strong CSP with `default-src 'none'` baseline
- ✅ `frame-ancestors 'none'` — prevents all framing/clickjacking
- ✅ `nosniff` — MIME type sniffing blocked
- ✅ Strict referrer policy on cross-origin requests
- ✅ No `X-Powered-By` leakage

---

*Report generated by security-osint MCP tools.*
