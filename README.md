# PAYOK Signature Generator

Yaak plugin to generate PAYOK RSA-SHA256 digital signatures directly inside your requests.

---

## Template Functions

### `payok.signature`

Generates the `sign` header value. The plugin reads the request body automatically — no need to copy it into the arguments.

**Setup:**
1. In the **Headers** tab, add a header named `sign`
2. In the value field, type `payok` and select `payok.signature` from autocomplete
3. Fill in the dialog:
   - **Endpoint Path** — e.g. `/api-pay/payment/V3.2/order/create-api`
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

Right-click any request in the sidebar (or open the request's actions menu) and select **Export Signature Code** to generate a standalone code snippet that reproduces the PAYOK signature algorithm — using the current request's body, endpoint path, and private key — in your language of choice:

- JavaScript (Node.js)
- Python
- Java
- Go
- PHP
- C# (.NET)

Pick a language from the dropdown to regenerate the snippet, then click **Copy to Clipboard**. Each snippet is fully standalone (only using each language's standard library, plus `cryptography` for Python and `openssl` for PHP) and implements the exact same steps as `payok.signature`:

1. Strip any `-----BEGIN/END (RSA) PRIVATE KEY-----` headers from the supplied Base64 key and rewrap it as a PKCS#8 PEM block.
2. Build the message as `<body> + "&" + <path>`.
3. Sign the message with RSA-SHA256 (PKCS#1 v1.5 padding).
4. Base64-encode the resulting signature.

The private key is read from the `sign` header's `payok.signature(...)` tag on the current request (same source as the path), including resolving nested references such as `${[ getEnvironmentVariable(...) ]}`. If no `sign` header is configured yet, a `PASTE_YOUR_BASE64_PKCS8_PRIVATE_KEY_HERE` placeholder is used instead.

> ⚠️ **Security note:** when a real key is found, the exported code — and your clipboard — contains your actual private key in plaintext. Don't paste it into shared chats, tickets, or commit it to version control.


---

## Signing Algorithm

```
message   = <request_body_string> + "&" + <endpoint_path>
signature = Base64( RSA-SHA256-sign(privateKey, message) )
```
