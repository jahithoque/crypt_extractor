# CryptoLens

A browser-only CSV filter for Prisma Cloud host and image reports. Choose one or both report types, select cryptography/encryption and cryptocurrency mining indicators, then download the matching rows.

## Run

Open `index.html` in a modern browser. No build step, server, dependencies, or external network requests are required. The CSV files are read and processed locally in the browser.

## Matching behavior

CryptoLens is a local keyword filter, not a Prisma Cloud integration or vulnerability intelligence database. It looks for:

- Weak, insecure, deprecated, or broken cryptography wording; SSL 2/3 or TLS 1.0/1.1; weak or legacy algorithms such as MD5, SHA-1, DES, and RC4; and CWE-295, CWE-326, CWE-327, or CWE-330.
- Encryption, certificate, cryptography, and key terms in finding-oriented columns. These are context clues and can still produce unrelated matches.
- Known crypto libraries (OpenSSL, libssl/libcrypto, BoringSSL, wolfSSL, GnuTLS, mbedTLS, cryptsetup, libgcrypt, libsodium, bcrypt, and Bouncy Castle) in package, component, software, or similar columns. If those columns are absent, it checks finding text, or the whole row when it cannot identify finding columns. A library reference identifies a package, not necessarily a crypto-related flaw.
- Mining terms, known mining tools, Stratum/pool indicators, and explicit coin-plus-mining phrases.

Every result shows the term that triggered the match, and the download adds a `CryptoLens match reason` column. A CVE ID by itself does not trigger a match. The list is deliberately small and can miss relevant findings; review the matched row and its Prisma Cloud details before treating it as actionable. The rules are in `app.js` and can be adjusted for your report schema and policy.

## Files

- `index.html` — page structure and controls
- `styles.css` — layout and styling
- `app.js` — CSV parsing, matching, preview, and export

