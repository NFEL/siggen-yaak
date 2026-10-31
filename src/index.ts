import type {
  CallHttpRequestActionArgs,
  Context,
  DynamicTemplateFunctionArg,
  EditorLanguage,
  PluginDefinition,
} from "@yaakapp/api";
import { createSign, createVerify, randomUUID } from "node:crypto";
import {
  generateCode,
  LANGUAGE_OPTIONS,
  type SupportedLanguage,
} from "./codegen";
import {
  buildSelectedMessage, DEFAULT_FIELDS, fieldCount, lookupOptions, MAX_FIELDS,
} from "./selection";

function buildPrivateKeyPem(keyInput: string): string {
  const stripped = keyInput
    .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----/g, "")
    .replace(/-----END (?:RSA )?PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  return `-----BEGIN PRIVATE KEY-----\n${stripped}\n-----END PRIVATE KEY-----`;
}

function generateSignature(message: string, privateKeyBase64: string): string {
  const pem = buildPrivateKeyPem(privateKeyBase64);
  const sign = createSign("RSA-SHA256");
  sign.update(message, "utf8");
  return sign.sign(pem, "base64");
}

function buildPublicKeyPem(keyInput: string): string {
  const stripped = keyInput
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return `-----BEGIN PUBLIC KEY-----\n${stripped}\n-----END PUBLIC KEY-----`;
}

/**
 * Verifies a signature against a body, path, and RSA public key. Mirrors
 * generateSignature()'s message format (`body + "&" + path`) for outgoing
 * requests.
 *
 * If `path` is blank, the message is just `body` with no separator. This
 * matches how PAYOK signs asynchronous notifications/webhooks sent to your
 * server — those signatures cover only the body, since there's no fixed
 * "path" on PAYOK's side for a merchant-controlled callback URL.
 */
function verifySignature(
  body: string,
  path: string,
  signatureBase64: string,
  publicKeyBase64: string,
): boolean {
  const message = path ? `${body}&${path}` : body;
  const pem = buildPublicKeyPem(publicKeyBase64);
  const verify = createVerify("RSA-SHA256");
  verify.update(message, "utf8");
  return verify.verify(pem, signatureBase64, "base64");
}

function extractBodyText(body: Record<string, any>): string | null {
  // Yaak stores text/json bodies as { text: "..." }
  if (typeof body.text === "string") return body.text || null;
  return null;
}

/** Extracts the path (no scheme/host/query) from a request URL, for use in the signed message. */
function extractPath(rawUrl: string): string {
  try {
    return new URL(rawUrl).pathname || "/";
  } catch {
    // Not a full absolute URL (e.g. unresolved "{{ base_url }}/api/..." or a bare path)
    const match = rawUrl.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]+(\/[^?#]*)?/);
    if (match) return match[1] ?? "/";
    if (rawUrl.startsWith("/")) return rawUrl.split(/[?#]/)[0] || "/";
    return rawUrl;
  }
}

/**
 * Decodes the `b64'...'` payload format Yaak's template renderer uses for string
 * argument values that contain characters outside [A-Za-z0-9 _] — e.g. a Base64
 * private key, which always contains "+", "/" or "=". Uses the URL-safe,
 * unpadded Base64 alphabet, matching the yaak-templates Rust implementation.
 */
function decodeTemplateBase64(text: string): string {
  let normalized = text.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4 !== 0) normalized += "=";
  return Buffer.from(normalized, "base64").toString("utf8");
}

/**
 * Finds the raw string value of a named argument (e.g. `private_key`) inside a
 * `payok.signature(...)` template tag on any of the request's headers.
 *
 * Yaak serializes string argument values one of two ways:
 *   - name='plain text'      when the text is only letters/digits/spaces/underscores
 *   - name=b64'<base64url>'  otherwise — always the case for real private keys,
 *                            since Base64 keys contain "+", "/" or "=" characters.
 *
 * The returned value may itself contain a nested template tag (e.g. an environment
 * variable reference) — render it via ctx.templates.render() to resolve it.
 */
function extractSignatureArg(
  headers: Array<{ value: string; enabled?: boolean }>,
  argName: string,
): string | null {
  const pattern = new RegExp(
    `${argName}\\s*=\\s*(?:b64'([^']*)'|'([^']*)'|"([^"]*)")`,
  );
  for (const header of headers) {
    if (header.enabled === false) continue;
    const value = header.value ?? "";
    if (!value.includes("payok.signature")) continue;
    const match = value.match(pattern);
    if (!match) continue;
    if (match[1] !== undefined) return decodeTemplateBase64(match[1]);
    if (match[2] !== undefined) return match[2];
    if (match[3] !== undefined) return match[3];
  }
  return null;
}

/**
 * Renders a string that may contain template tags, falling back to the raw
 * input on any error (e.g. incomplete/invalid tag syntax) instead of throwing,
 * so a single malformed tag can't crash the whole export action.
 */
async function safeRenderTemplate(ctx: Context, data: string): Promise<string> {
  try {
    const rendered = await ctx.templates.render({ data, purpose: "preview" });
    return typeof rendered === "string" ? rendered : data;
  } catch {
    return data;
  }
}

const LANGUAGE_TO_EDITOR: Record<SupportedLanguage, EditorLanguage> = {
  javascript: "javascript",
  python: "python",
  java: "java",
  go: "go",
  php: "php",
  csharp: "csharp",
  rust: "text",
};

const TS_CACHE_KEY = "payok_ts";
const UUID_CACHE_KEY = "payok_uuid";
const TS_CACHE_TTL = 10_000;

const selectionInputs: DynamicTemplateFunctionArg[] = Array.from(
  { length: MAX_FIELDS },
  (_, index) => {
    const row = index + 1;
    return {
      type: "h_stack",
      inputs: [],
      async dynamic(ctx, args) {
        if (args.values.message_mode !== "selected" || row > fieldCount(args.values)) {
          return { hidden: true, inputs: [] };
        }
        const id = await ctx.window.requestId();
        const request = id ? await ctx.httpRequest.getById({ id }) : null;
        const options = lookupOptions(request);
        const name = String(args.values[`field_${row}_name`] ?? DEFAULT_FIELDS[index] ?? "");
        const defaultValue = "";
        const current = String(args.values[`field_${row}_lookup`] ?? defaultValue);
        if (!options.some(option => option.value === current)) {
          options.push({ label: `Saved lookup → ${current}`, value: current });
        }
        return {
          hidden: false,
          inputs: [
            {
              type: "select", name: `field_${row}_lookup`, label: name || `Field ${row}`,
              options, defaultValue,
              description: "Choose the request value to sign, or leave this field out.",
            },
            {
              type: "accordion", label: `Advanced: ${name || `field ${row}`}`,
              inputs: [
                { type: "text", name: `field_${row}_name`, label: "Name in signed JSON", defaultValue: DEFAULT_FIELDS[index] ?? "" },
                {
                  type: "text", name: `field_${row}_custom`, label: "Custom request path",
                  placeholder: "body:/nested/Amount or header:TrackId",
                  hidden: current !== "custom",
                },
              ],
            },
          ],
        };
      },
    };
  },
);

export const plugin: PluginDefinition = {
  templateFunctions: [
    {
      name: "payok.signature",
      description:
        "Choose what to sign, then select where each value comes from in your request.",
      previewType: "none",
      args: [
        {
          type: "select", name: "message_mode", label: "What to sign",
          defaultValue: "payok",
          options: [
            { label: "Entire request body + endpoint (PAYOK)", value: "payok" },
            { label: "Choose request fields", value: "selected" },
          ],
        },
        {
          type: "text",
          name: "path",
          label: "Endpoint Path",
          placeholder: "/api/v1/payment",
          dynamic: (_ctx, args) => ({ hidden: args.values.message_mode === "selected", optional: args.values.message_mode === "selected" }),
        },
        {
          type: "text",
          name: "private_key",
          label: "Private key",
          placeholder: "Paste your key or insert an environment variable",
          description: "PKCS#8 PEM or Base64. Use an environment variable to keep the key out of the request.",
          password: true,
        },
        {
          type: "select", name: "preset", label: "Preset", defaultValue: "none",
          options: [
            { label: "Choose fields myself", value: "none" },
            { label: "Tejarat Bank — حواله", value: "tejarat" },
          ],
          dynamic: (_ctx, args) => ({ hidden: args.values.message_mode !== "selected" }),
        },
        {
          type: "text", name: "tejarat_client_variable", label: "Client ID variable", defaultValue: "client_id",
          dynamic: (_ctx, args) => ({ hidden: args.values.message_mode !== "selected" || args.values.preset !== "tejarat" }),
        },
        ...DEFAULT_FIELDS.filter(name => !["IssuedAt", "iat", "clientId"].includes(name)).map(name => ({
          type: "select" as const, name: `tejarat_${name}`, label: name, options: [],
          async dynamic(ctx: Context, args: { values: Record<string, unknown> }) {
            if (args.values.message_mode !== "selected" || args.values.preset !== "tejarat") return { hidden: true };
            const id = await ctx.window.requestId();
            const request = id ? await ctx.httpRequest.getById({ id }) : null;
            const options = lookupOptions(request).filter(option => option.value !== "custom");
            const aliases: Record<string, string[]> = {
              DebtorAccount: ["query::SourceAccountNumber", "body:/sourceAccountNumber"],
              CreditorAccount: ["body:/destinationAccountNumber"],
              Amount: ["body:/amount"],
              IdempotencyKey: ["query:TrackId"],
            };
            const candidates = [`body:/${name}`, `header:${name.toLowerCase()}`, `query:${name}`, ...(aliases[name] ?? [])];
            return {
              hidden: false,
              options: options.map(option => option.value ? option : { label: name === "CreditorFirstName" || name === "CreditorLastName" ? "Omit (optional)" : "Select request value…", value: "" }),
              defaultValue: candidates.find(value => options.some(option => option.value === value)) ?? "",
            };
          },
        })),
        {
          type: "banner", inputs: [],
          async dynamic(ctx, args) {
            if (args.values.message_mode !== "selected" || args.values.preset === "tejarat") return { hidden: true, inputs: [] };
            const id = await ctx.window.requestId();
            const request = id ? await ctx.httpRequest.getById({ id }) : null;
            const options = lookupOptions(request).filter(option => /^(body:.+|header:|query:)/.test(option.value));
            return {
              hidden: false,
              inputs: [
                { type: "markdown", content: "**Include in signature** — tick the fields you need. Field names are taken from your request." },
                ...options.map(option => ({
                  type: "checkbox" as const,
                  name: `include_${Buffer.from(option.value).toString("base64url")}`,
                  label: option.label,
                  defaultValue: "false",
                })),
              ],
            };
          },
        },
        {
          type: "accordion", label: "Custom field names and mappings (optional)",
          inputs: [
            {
              type: "select", name: "field_count", label: "Custom mapping rows",
              defaultValue: String(DEFAULT_FIELDS.length),
              options: Array.from({ length: MAX_FIELDS }, (_, i) => ({ label: String(i + 1), value: String(i + 1) })),
            },
            ...selectionInputs,
          ],
          dynamic: (_ctx, args) => ({ hidden: args.values.message_mode !== "selected" || args.values.preset === "tejarat" }),
        },
      ],
      async onRender(ctx, args) {
        const path = String(args.values.path ?? "").trim();
        const privateKey = String(args.values.private_key ?? "").trim();

        const selected = args.values.message_mode === "selected";
        if ((!selected && !path) || !privateKey) return null;

        const requestId = await ctx.window.requestId();
        if (!requestId) return null;

        const rawRequest = await ctx.httpRequest.getById({ id: requestId });
        if (!rawRequest) return null;

        const rawBodyText = extractBodyText(rawRequest.body);
        if (!selected && !rawBodyText) return null;

        // Expire caches so each send gets a fresh timestamp and UUID.
        // payok.timestamp/payok.uuid will regenerate values on the next call and
        // cache them, so the subsequent actual body render reuses the same values.
        await ctx.store.set(TS_CACHE_KEY, { ts: "", at: 0 });
        await ctx.store.set(UUID_CACHE_KEY, { id: "", at: 0 });

        if (selected) {
          const message = await buildSelectedMessage(ctx, rawRequest, args.values, args.purpose);
          if (args.values.preset === "tejarat") {
            const input = `${Buffer.from('{"alg":"RS256","typ":"JWS"}').toString("base64url")}.${Buffer.from(message).toString("base64url")}`;
            return `${input}.${Buffer.from(generateSignature(input, privateKey), "base64").toString("base64url")}`;
          }
          return generateSignature(message, privateKey);
        }

        // Render only the body to avoid recursively rendering the signature header.
        const renderedBody = await ctx.templates.render({ data: rawBodyText!, purpose: args.purpose });
        if (typeof renderedBody !== "string" || !renderedBody) return null;
        return generateSignature(`${renderedBody}&${path}`, privateKey);
      },
    },
    {
      name: "payok.timestamp",
      description:
        "Generate current ISO8601 timestamp for PAYOK request headers",
      previewType: "live",
      args: [],
      // Cache timestamp for 10 seconds so that payok.signature and the request body
      // always use the same value within a single request cycle.
      async onRender(ctx) {
        const now = Date.now();
        const cached = await ctx.store.get<{ ts: string; at: number }>(
          TS_CACHE_KEY,
        );
        if (cached && now - cached.at < TS_CACHE_TTL) {
          return cached.ts;
        }
        const ts = new Date().toISOString();
        await ctx.store.set(TS_CACHE_KEY, { ts, at: now });
        return ts;
      },
    },
    {
      name: "payok.uuid",
      description:
        "Generate a UUID that stays consistent within a single request cycle, so payok.signature and the request body use the same value.",
      previewType: "live",
      args: [],
      // Caches the UUID for 10 seconds — the same window used by payok.timestamp.
      // Both the signature render pass and the body render pass happen within
      // milliseconds of each other, so they receive the same UUID. A new UUID
      // is generated on the next send after the TTL expires.
      async onRender(ctx) {
        const now = Date.now();
        const cached = await ctx.store.get<{ id: string; at: number }>(
          UUID_CACHE_KEY,
        );
        if (cached && now - cached.at < TS_CACHE_TTL) {
          return cached.id;
        }
        const id = randomUUID();
        await ctx.store.set(UUID_CACHE_KEY, { id, at: now });
        return id;
      },
    },
  ],
  httpRequestActions: [
    {
      label: "Export Signature Code",
      icon: "copy",
      async onSelect(ctx, args) {
        try {
          await runExportSignatureCode(ctx, args);
        } catch (err) {
          await ctx.toast.show({
            message: `Failed to export signature code: ${String(
              err instanceof Error ? err.message : err,
            )}`,
            color: "danger",
          });
        }
      },
    },
    {
      label: "Verify Incoming Signature",
      icon: "check_circle",
      async onSelect(ctx, args) {
        try {
          await runVerifyIncomingSignature(ctx, args);
        } catch (err) {
          await ctx.toast.show({
            message: `Failed to verify signature: ${String(
              err instanceof Error ? err.message : err,
            )}`,
            color: "danger",
          });
        }
      },
    },
  ],
};

async function runExportSignatureCode(
  ctx: Context,
  args: CallHttpRequestActionArgs,
): Promise<void> {
  const { httpRequest } = args;

  const selectionValues: Record<string, string> = {};
  for (const name of [
    "message_mode", "field_count", "preset", "tejarat_client_variable", ...DEFAULT_FIELDS.map(name => `tejarat_${name}`),
    ...lookupOptions(httpRequest).filter(option => /^(body:.+|header:|query:)/.test(option.value))
      .map(option => `include_${Buffer.from(option.value).toString("base64url")}`),
    ...Array.from({ length: MAX_FIELDS }, (_, i) => [
      `field_${i + 1}_name`, `field_${i + 1}_lookup`, `field_${i + 1}_custom`,
    ]).flat(),
  ]) {
    const value = extractSignatureArg(httpRequest.headers, name);
    if (value !== null) selectionValues[name] = value;
  }
  const selected = selectionValues.message_mode === "selected";
  const rawBodyText = extractBodyText(httpRequest.body) ?? "";
  const renderedBody = selected
    ? await buildSelectedMessage(ctx, httpRequest, selectionValues, "preview")
    : rawBodyText ? await safeRenderTemplate(ctx, rawBodyText) : "";
  const rawPath = extractSignatureArg(httpRequest.headers, "path");
  const path = selected ? "" : rawPath !== null
    ? await safeRenderTemplate(ctx, rawPath)
    : extractPath(await safeRenderTemplate(ctx, httpRequest.url));

  // Resolve the actual private key from the `sign` header's payok.signature(...)
  // tag, the same way the path and body are resolved from the live request.
  const rawPrivateKeyArg = extractSignatureArg(
    httpRequest.headers,
    "private_key",
  );
  let privateKey = "";
  if (rawPrivateKeyArg) {
    privateKey = (await safeRenderTemplate(ctx, rawPrivateKeyArg)).trim();
  }

  const codegenInput = {
    path,
    body: renderedBody,
    messageMode: selected ? "selected" as const : "payok" as const,
    compactJws: selected && selectionValues.preset === "tejarat",
    privateKey: privateKey || undefined,
  };

  const values = await ctx.prompt.form({
    id: "payok-export-signature-code",
    title: "Export Signature Code",
    description: privateKey
      ? "Standalone code using this request's signature payload and private key. This code contains your real private key — handle it securely."
      : "Standalone code using this request's signature payload. No private_key was found, so replace the private-key placeholder before running.",
    size: "lg",
    confirmText: "Copy to Clipboard",
    cancelText: "Close",
    inputs: [
      {
        type: "select",
        name: "language",
        label: "Programming Language",
        defaultValue: "javascript",
        options: LANGUAGE_OPTIONS,
      },
      {
        type: "editor",
        name: "code",
        label: "Generated Code",
        language: "javascript",
        readOnly: true,
        rows: 26,
        dynamic: (_ctx, dynArgs) => {
          const lang =
            (dynArgs.values.language as SupportedLanguage) || "javascript";
          return {
            language: LANGUAGE_TO_EDITOR[lang] ?? "text",
            defaultValue: generateCode(lang, codegenInput),
          };
        },
      },
    ],
  });

  if (values) {
    const lang = (values.language as SupportedLanguage) || "javascript";
    const code = generateCode(lang, codegenInput);
    await ctx.clipboard.copyText(code);
    await ctx.toast.show({
      message: privateKey
        ? "Signature code copied to clipboard (contains your real private key)"
        : "Signature code copied to clipboard",
      color: "success",
    });
  }
}

/**
 * Renders the live verification result as Markdown for the "Verify Incoming
 * Signature" dialog. Never throws — invalid Base64/keys are reported as a
 * friendly error message instead of crashing the dynamic form.
 */
function formatVerifyResult(values: { [key: string]: unknown }): string {
  const body = typeof values.body === "string" ? values.body : "";
  const signature =
    typeof values.signature === "string" ? values.signature.trim() : "";
  const publicKey =
    typeof values.publicKey === "string" ? values.publicKey.trim() : "";

  if (!signature || !publicKey) {
    return "_Fill in the signature and public key below to see the result._";
  }

  try {
    const isValid = verifySignature(body, "", signature, publicKey);
    return isValid
      ? "✅ **Valid** — the signature matches this body and public key."
      : "❌ **Invalid** — the signature does not match this body and public key.";
  } catch (err) {
    return `⚠️ **Error** — ${String(
      err instanceof Error ? err.message : err,
    )}. Check that the public key and signature are valid Base64.`;
  }
}

/**
 * Lets the user paste a received body/signature/public key (e.g. from an
 * incoming PAYOK notification/webhook) and see, live, whether the signature
 * is valid — without having to run any exported code. Uses the same
 * RSA-SHA256 verification as verifySignature() above, over the body alone,
 * matching how PAYOK signs notifications/webhooks (no path involved).
 */
async function runVerifyIncomingSignature(
  ctx: Context,
  args: CallHttpRequestActionArgs,
): Promise<void> {
  const { httpRequest } = args;

  const rawBodyText = extractBodyText(httpRequest.body) ?? "";
  const renderedBody = rawBodyText
    ? await safeRenderTemplate(ctx, rawBodyText)
    : "";

  await ctx.prompt.form({
    id: "payok-verify-incoming-signature",
    title: "Verify Incoming Signature",
    description:
      "Check whether a signature you received (e.g. on an incoming PAYOK notification/webhook) is valid, using the counterparty's RSA public key. The result below updates live as you edit the fields.",
    size: "lg",
    confirmText: "Done",
    inputs: [
      {
        type: "text",
        name: "body",
        label: "Body",
        placeholder: '{"merchantOrderId":"ORDER-123","amount":10000}',
        defaultValue: renderedBody,
        multiLine: true,
        optional: true,
      },
      {
        type: "text",
        name: "signature",
        label: "Signature to Verify (Base64)",
        placeholder: "Base64-encoded RSA-SHA256 signature you received",
        multiLine: true,
      },
      {
        type: "text",
        name: "publicKey",
        label: "Public Key (Base64 or PEM)",
        placeholder: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...",
        multiLine: true,
      },
      {
        type: "markdown",
        content: formatVerifyResult({}),
        dynamic: (_ctx, dynArgs) => ({
          content: formatVerifyResult(dynArgs.values),
        }),
      },
    ],
  });
}
