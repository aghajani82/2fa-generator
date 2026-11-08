# 2FA Code Generator

A small **public**, privacy-oriented, responsive TOTP code generator that can be hosted at **GitHub Pages** with no build process and no backend. Includes a locally generated, scannable authenticator provisioning QR code.

## Features

- TOTP according to [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html): SHA-1, SHA-256, SHA-512; 6, 7, or 8 digits; 5–300 second periods.
- Default: **SHA-1 / 6 digits / 30 seconds**, the common authenticator configuration (including typical Hetzner 2FA setup).
- Base32 secrets (spaces, hyphens, and optional RFC padding accepted), or import an `otpauth://totp/` provisioning link.
- Generates a scannable **`otpauth://totp/` QR** locally with configurable issuer and account label; optional show/hide with a warning about the sensitive QR.
- Responsive, dark UI, countdown indicator, copy button, show/hide secret, and clear button.
- No account, no server, no API, no cookies, no localStorage, no analytics, no CDN, and no external script/font dependencies.
- Web Crypto (`crypto.subtle`) for HMAC. Works over HTTPS or a secure local origin.

## Compatibility and limitations

This tool generates standard **time-based one-time passwords (TOTP)**. It does **not** generate SMS codes, passkeys, hardware security key challenges, email codes, recovery codes, challenge/response codes, or proprietary Steam Guard codes. The phone/computer clock must be accurate. The same secret and TOTP parameters must be used by the service and generator. SHA-1 / six digits / 30 seconds is the default unless a service specifies otherwise.

To scan the displayed QR, open an authenticator app on another device. QR contains the **secret itself**, not the transient 6-digit code. Treat the QR as sensitive. Never paste a secret into GitHub issues, public code, screenshots, or shareable links.

## Publish with GitHub Pages

1. Create a **public** repository named `2fa-generator` under your account (e.g. `aghajani82`).
2. Upload **the contents of this folder** to the root of the repository (keep `index.html`, `styles.css`, `app.mjs`, `totp.mjs`, and the `vendor/` subfolder). Set the default branch to `main`.
3. In your repository, open **Settings → Pages → Build and deployment** and select **Deploy from a branch**, branch **main**, folder **/(root)**. Save.
4. When deployment succeeds, visit `https://YOUR-USERNAME.github.io/2fa-generator/`.

**Important:** Merely creating the repository or pushing files does *not* automatically enable Pages on every account. You must activate the Pages publishing source. Only publish the reviewed files; don't put your actual secret in code or test data.

Local preview: run `python3 -m http.server 8000` in the repository directory and open `http://localhost:8000` (or use any simple static web server). No install or npm build is needed.

## Test

With Node.js 22 or newer:

```bash
node --test tests/*.test.mjs
```

Includes all **18 RFC 6238 Appendix B official test vectors** spanning SHA-1, SHA-256, and SHA-512, along with Base32, `otpauth`, and zero-padding tests. CI runs the tests on each push and PR.

## Security notes

- Input secrets and generated codes are held only in the browser's active page memory. Reload or Clear removes the displayed values; browser extensions, copied clipboard values, or the user's device are not under this application's control.
- TOTP input secret never appears in the page's URL or is sent via HTTP by JavaScript. `connect-src 'none'` CSP forbids browser requests from app code. Local QR encoder is vendored with license attribution.
- Hosting still provides code/HTML to visitors, and a hosting provider can observe ordinary page visits. **Only use a trusted deployed revision** of any public generator for sensitive accounts. Dedicated authenticator apps generally provide safer long-term credential storage; this tool intentionally does not store secrets.
- GitHub Pages cannot set custom HTTP security headers. The HTML supplies a restrictive CSP meta tag, but some directives such as `frame-ancestors` only function as HTTP response headers. For stronger header control, choose a host where you can set security headers.

## Licenses

Project: [MIT License](LICENSE). QR code encoder: see [`vendor/THIRD-PARTY-NOTICES.md`](vendor/THIRD-PARTY-NOTICES.md) (MIT licensed QRCode.js).