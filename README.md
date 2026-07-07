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

---

### `payok.timestamp`

Generates the current ISO8601 timestamp (e.g. `2024-01-15T10:30:00.123Z`).

In the request body, place your cursor inside the `requestTime` value and select `payok.timestamp` from the template tag autocomplete.

```json
{ "requestTime": "${[ payok.timestamp() ]}" }
```

---

### `payok.uuid`

Generates a UUID for fields like `merchantOrderId` that must be unique per request.

```json
{ "merchantOrderId": "${[ payok.uuid() ]}" }
```

---

## How caching works

`payok.signature` expires both caches before rendering the body. This guarantees:

1. **Uniqueness** — each request send gets a fresh UUID and timestamp, even when requests are sent in rapid succession.
2. **Consistency** — the body used to compute the signature is identical to the body sent in the request.

```
payok.signature renders
  → expires UUID + timestamp caches
  → renders body → payok.uuid() and payok.timestamp() generate fresh values and cache them
  → signs body with those values

Yaak sends actual request
  → renders body → payok.uuid() and payok.timestamp() return cached values  ✓
```

---

## Private Key Formats

Both formats are accepted:

```
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj...
```

```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj...
-----END PRIVATE KEY-----
```

> If your key starts with `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1), convert it first:
> ```bash
> openssl pkcs8 -topk8 -nocrypt -in rsa_private.pem -out pkcs8_private.pem
> ```

---

## Export Signature Code

Right-click any request in the sidebar (or open the request's actions menu) and select **Export Signature Code** to generate a standalone code snippet that reproduces the PAYOK signature algorithm in your language of choice:

- JavaScript (Node.js)
- Python
- Java
- Go
- PHP
- C# (.NET)

Pick a language from the dropdown to regenerate the snippet, then click **Copy to Clipboard**.

### What gets captured from the request

| Value | Source |
|---|---|
| **Body** | The current request body, with template tags resolved |
| **Path** | The pathname extracted from the request URL (e.g. `/api-pay/payment/V3.2/order/create-api`) |
| **Private key** | The `private_key` argument on the `sign` header's `payok.signature(...)` tag, including nested references such as `${[ getEnvironmentVariable(...) ]}` |

If no `sign` header with a `private_key` is configured yet, a `PASTE_YOUR_BASE64_PKCS8_PRIVATE_KEY_HERE` placeholder is used instead.

> **Note:** `payok.signature` uses the **Endpoint Path** you enter in its dialog, while **Export Signature Code** derives the path from the request URL. Make sure both match the path PAYOK expects when signing outgoing requests.

### Generated signing code

Each snippet is fully standalone (only using each language's standard library, plus `cryptography` for Python and `openssl` for PHP) and implements the exact same steps as `payok.signature`:

1. Strip any `-----BEGIN/END (RSA) PRIVATE KEY-----` headers from the supplied Base64 key and rewrap it as a PKCS#8 PEM block.
2. Build the message as `<body> + "&" + <path>`.
3. Sign the message with RSA-SHA256 (PKCS#1 v1.5 padding).
4. Base64-encode the resulting signature.

> ⚠️ **Security note:** when a real key is found, the exported code — and your clipboard — contains your actual private key in plaintext. Don't paste it into shared chats, tickets, or commit it to version control.

### Verifying signatures (in exported code)

Every exported snippet also includes a `verifySignature` function (or `VerifySignature` / `verify_signature`, depending on language convention). It validates a signature against an RSA **public** key (X.509 / SubjectPublicKeyInfo, Base64 or PEM):

1. Strip any `-----BEGIN/END PUBLIC KEY-----` headers from the supplied Base64 key.
2. Rebuild the message. If a path is given: `<body> + "&" + <path>`. If the path is empty: just `<body>`.
3. Verify the signature against the message with RSA-SHA256 (PKCS#1 v1.5 padding), returning `true`/`false`.

A ready-to-run **webhook verification example** is included at the bottom of every snippet. Paste the real values over these placeholders:

- `PASTE_RECEIVED_WEBHOOK_BODY_HERE`
- `PASTE_RECEIVED_SIGNATURE_HERE`
- `PASTE_PAYOK_BASE64_PUBLIC_KEY_HERE`

The example calls `verifySignature` with an **empty path**, since PAYOK signs notifications/webhooks over the **body alone** — confirmed by testing against a real PAYOK notification payload/signature/public key.

---

## Verify Incoming Signature

Right-click any request in the sidebar (or open the request's actions menu) and select **Verify Incoming Signature** to check, directly inside Yaak, whether a signature you received (e.g. on an incoming PAYOK notification/webhook) is valid — no exported code or external tools needed.

Paste in:
- **Body** — the raw body you received (defaults to the current request's body as a starting point)
- **Signature to Verify** — the Base64 `sign` value you received
- **Public Key** — the RSA public key (Base64 or PEM) that should have produced that signature

The result — ✅ Valid, ❌ Invalid, or ⚠️ an error message (e.g. malformed Base64) — updates live as you edit the fields.

> **Note:** this checks the signature over the **body alone**, matching how PAYOK signs incoming notifications/webhooks. This is different from **outgoing** requests you send *to* PAYOK (`payok.signature`, Export Signature Code), which are signed over `body + "&" + path` instead.
>
> Verification only succeeds if the **public key matches the private key** that produced the signature. Use PAYOK's public key to verify signatures **from** PAYOK, and your own public key to verify signatures **you** produced.

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
