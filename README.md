# PAYOK Signature Generator

Yaak plugin to generate and verify PAYOK RSA-SHA256 digital signatures directly inside your requests.

## Features

| Feature | Description |
|---|---|
| `payok.signature` | Generate Base64 RSA-SHA256 over the full PAYOK request or selected request fields |
| `payok.timestamp` | Generate a consistent ISO8601 timestamp for `requestTime` fields |
| `payok.uuid` | Generate a consistent UUID for fields like `merchantOrderId` |
| **Export Signature Code** | Export signing and verification code in 7 languages, including Go, Python, and Rust |
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

#### Selected request fields (`x-jws-signature`)

1. Add the `x-jws-signature` header and insert `payok.signature` into its value.
2. Choose **What to sign → Choose request fields**.
3. Set **Private key** to your PKCS#8 RSA key or environment reference; the endpoint path is not used in this mode. The key input stays compact even for long PEM keys.
4. Under **Include in signature**, tick the body fields, headers, or query parameters you want. Only fields from your actual request appear.
5. Save. No field count or source mapping is required for normal use.

**Tejarat Bank — حواله:** matching body/header/query values are suggested automatically. Creditor names are optional. `IssuedAt` (Unix milliseconds) and `iat` (Unix seconds) are generated from the same timestamp. `clientId` resolves `client_id` by default; change **Client ID variable** to override it. The preset produces compact **RS256 JWS**: `base64url(header).base64url(JSON payload).base64url(signature)`, with protected header `{"alg":"RS256","typ":"JWT"}`. The signature covers the encoded header and payload, separated by a dot, with no endpoint suffix.


Signed JSON names come from the selected request fields (nested fields use their final property name). To use a different name, open **Custom field names and mappings (optional)** and configure a mapping instead of checking that source. For example:

| JSON output field | Example lookup |
|---|---|
| `DebtorAccount` | Body → `/DebtorAccount` |
| `CreditorAccount` | Body → `/CreditorAccount` |
| `Amount` | Body → `/Amount` |
| `IdempotencyKey` | Header → `Idempotency-Key` |
| `CreditorFirstName` | Body → `/CreditorFirstName` |
| `CreditorLastName` | Body → `/CreditorLastName` |
| `clientId` | Header → `clientId` or Query → `clientId` |
| `IssuedAt` | Body → `/IssuedAt` |
| `iat` | Body → `/iat` |

Lookups also support the request method, URL, and URL path. For a field not shown in the dropdown, choose **Custom path (advanced)…**, open the field's **Advanced** section, and enter `body:/nested/Amount`, `header:Idempotency-Key`, or `query:clientId`. Body lookups use JSON Pointer: `/items/0/Amount` selects an array element, `~1` escapes `/`, and `~0` escapes `~` in field names. The body must render to valid JSON when a body field is selected.

The signed message is compact UTF-8 JSON in row order, with **no `&` or endpoint suffix**. JSON body values retain their types; headers and query values are strings. For example, selecting a numeric body amount and a header produces `{"Amount":1234,"IdempotencyKey":"transaction-123"}`. Nested objects retain their parsed property order; this is not sorted/canonical JSON. Missing or ambiguous selected values, duplicate output names, and self-referencing signature values raise errors instead of signing an incomplete payload.

Outside the Tejarat preset, `IssuedAt` and `iat` are ordinary lookups. Disabled headers/query rows are excluded; an enabled query row takes precedence over the same parameter in the URL.

Generic selected-fields mode returns Base64 RSA-SHA256; **Tejarat mode returns compact JWS**. Existing PAYOK tags keep their original body-plus-path behavior.


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

Right-click any request and select **Export Signature Code**, then choose JavaScript (Node.js), Python, Java, Go, PHP, C# (.NET), or Rust. Tejarat exports produce compact RS256 JWS; other modes preserve their existing signature format.

![Export Signature Code dialog](https://raw.githubusercontent.com/cibofdevs/siggen-yaak/master/assets/export-signature-code.jpeg)

It captures the configured signature payload (template tags resolved) and the **private key** used by the header's `payok.signature(...)` tag. PAYOK mode uses the tag's endpoint path, falling back to the URL path if no path argument is configured. Selected-fields mode exports the assembled JSON object and signs it without a path suffix. If no key is configured, a `PASTE_YOUR_BASE64_PKCS8_PRIVATE_KEY_HERE` placeholder is used instead.

Python requires `cryptography`. Rust requires the `openssl` and `base64` crates (`cargo add openssl base64`) and a working OpenSSL development installation. Other snippets use their language's standard library or bundled crypto extension. Each snippet:
1. Strips any `-----BEGIN/END (RSA) PRIVATE KEY-----` headers from the Base64 key and rewraps it as PKCS#8 PEM.
2. Builds the message as `<body> + "&" + <path>` in PAYOK mode, or the selected JSON object alone in selected-fields mode.
3. Signs it with RSA-SHA256 (PKCS#1 v1.5 padding) and Base64-encodes the result.

For Tejarat, exports sign the captured JWS signing input and output the full three-segment compact JWS instead of a raw Base64 signature.

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

**Selected request fields** (no endpoint path):

```
message   = <compact JSON object in selection order>
signature = Base64( RSA-SHA256-sign(privateKey, message) )
```


**Incoming notifications/webhooks** (PAYOK → you):

```
message   = <request_body_string>
signature = Base64( RSA-SHA256-sign(PAYOK_privateKey, message) )
```

Verification covers the same message bytes: `body + "&" + path` for PAYOK requests, the selected JSON object for selected-fields requests, and `body` alone for incoming webhooks.

## Checks

Run `npm test` for signature selection regression coverage and `npx tsc --noEmit` for type checking.

