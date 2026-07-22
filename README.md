# PAYOK Signature Generator

Yaak plugin to generate and verify PAYOK RSA-SHA256 digital signatures directly inside your requests.

## Features

| Feature | Description |
|---|---|
| `payok.signature` | Generate the `sign` header for outgoing PAYOK API requests |
| `payok.timestamp` | Generate a consistent ISO8601 timestamp for `requestTime` fields |
| `payok.uuid` | Generate a consistent UUID for fields like `merchantOrderId` |
| **Export Signature Code** | Export standalone signing (and webhook verification) code in 6 languages |
| **Verify Incoming Signature** | Verify a received signature live inside Yaak — no external tools needed |

---

## Template Functions

### `payok.signature`

Generates the `sign` header value. The plugin reads the request body automatically — no need to copy it into the arguments.

**Setup:**
1. In the **Headers** tab, add a header named `sign`
2. In the value field, type `payok` and select `payok.signature` from autocomplete
3. Fill in the dialog:
   - **Endpoint Path** — e.g. `/api-pay/payment/V3.2/order/create-api` (must match the path PAYOK expects for signing, independent of the request URL)
   - **Private Key** — your PKCS#8 RSA private key in Base64, or an environment variable reference
4. Click **Save**

![Generate Signature dialog](https://raw.githubusercontent.com/cibofdevs/siggen-yaak/master/assets/generate-signature.jpeg)

### `payok.timestamp` / `payok.uuid`

Place your cursor in a field, type `payok`, and select the tag from autocomplete:

```json
{ "requestTime": "${[ payok.timestamp() ]}", "merchantOrderId": "${[ payok.uuid() ]}" }
```

`payok.signature` expires both caches before rendering the body, so every send gets a fresh UUID/timestamp while still signing the exact body that gets sent.

---

## Private Key Formats

Both Base64-only and PEM-wrapped keys are accepted. If your key starts with `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1), convert it first:

```bash
openssl pkcs8 -topk8 -nocrypt -in rsa_private.pem -out pkcs8_private.pem
```

---

## Export Signature Code

Right-click any request in the sidebar and select **Export Signature Code** to generate a standalone snippet — JavaScript (Node.js), Python, Java, Go, PHP, or C# (.NET) — that reproduces the PAYOK signature algorithm. Pick a language from the dropdown, then click **Copy to Clipboard**.

![Export Signature Code dialog](https://raw.githubusercontent.com/cibofdevs/siggen-yaak/master/assets/export-signature-code.jpeg)

It captures the current request's **body** (template tags resolved), **path** (from the URL), and the **private key** used by the `sign` header's `payok.signature(...)` tag. If none is configured yet, a `PASTE_YOUR_BASE64_PKCS8_PRIVATE_KEY_HERE` placeholder is used instead.

> **Note:** `payok.signature` uses the **Endpoint Path** you enter in its dialog, while **Export Signature Code** derives the path from the request URL. Make sure both match the path PAYOK expects when signing outgoing requests.

Each snippet is fully standalone (only using each language's standard library, plus `cryptography` for Python and `openssl` for PHP) and:
1. Strips any `-----BEGIN/END (RSA) PRIVATE KEY-----` headers from the Base64 key and rewraps it as PKCS#8 PEM.
2. Builds the message as `<body> + "&" + <path>`.
3. Signs it with RSA-SHA256 (PKCS#1 v1.5 padding) and Base64-encodes the result.

> ⚠️ **Security note:** when a real key is found, the exported code — and your clipboard — contains your actual private key in plaintext. Don't paste it into shared chats, tickets, or commit it to version control.

### Verifying signatures (in exported code)

Every snippet also includes a `verifySignature` function that validates a signature against an RSA **public** key (X.509 / SubjectPublicKeyInfo, Base64 or PEM), rebuilding the message as `<body> + "&" + <path>` (or just `<body>` if no path is given) and checking it with RSA-SHA256.

A ready-to-run **webhook verification example** is included at the bottom of every snippet — paste your real values over the `PASTE_RECEIVED_WEBHOOK_BODY_HERE`, `PASTE_RECEIVED_SIGNATURE_HERE`, and `PASTE_PAYOK_BASE64_PUBLIC_KEY_HERE` placeholders. It calls `verifySignature` with an **empty path**, since PAYOK signs notifications/webhooks over the **body alone**.

---

## Verify Incoming Signature

Right-click any request in the sidebar and select **Verify Incoming Signature** to check, directly inside Yaak, whether a signature you received (e.g. on an incoming PAYOK notification/webhook) is valid — no exported code or external tools needed.

![Verify Incoming Signature dialog](https://raw.githubusercontent.com/cibofdevs/siggen-yaak/master/assets/verify-incoming-signature.jpeg)

Paste in the **Body**, the **Signature to Verify** (Base64), and the **Public Key** (Base64 or PEM). The result — ✅ Valid, ❌ Invalid, or ⚠️ an error message — updates live as you edit the fields.

> This checks the signature over the **body alone**, matching how PAYOK signs incoming notifications/webhooks — different from **outgoing** requests to PAYOK, which are signed over `body + "&" + path`. Verification only succeeds if the **public key matches the private key** that produced the signature.

---

## Signing Algorithm

**Outgoing requests** (you → PAYOK):

```
message   = <request_body_string> + "&" + <endpoint_path>
signature = Base64( RSA-SHA256-sign(privateKey, message) )
```

**Incoming notifications/webhooks** (PAYOK → you):

```
message   = <request_body_string>
signature = Base64( RSA-SHA256-sign(PAYOK_privateKey, message) )
```

Verification uses the same message format as signing — `body + "&" + path` for outgoing, `body` alone for incoming webhooks.
