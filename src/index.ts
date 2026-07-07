import type {
  CallHttpRequestActionArgs,
  Context,
  EditorLanguage,
  PluginDefinition,
} from "@yaakapp/api";
import { createSign, randomUUID } from "node:crypto";
import {
  generateCode,
  LANGUAGE_OPTIONS,
  type SupportedLanguage,
} from "./codegen";

function buildPrivateKeyPem(keyInput: string): string {
  const stripped = keyInput
    .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----/g, "")
    .replace(/-----END (?:RSA )?PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  return `-----BEGIN PRIVATE KEY-----\n${stripped}\n-----END PRIVATE KEY-----`;
}

function generateSignature(
  body: string,
  path: string,
  privateKeyBase64: string,
): string {
  const message = `${body}&${path}`;
  const pem = buildPrivateKeyPem(privateKeyBase64);
  const sign = createSign("RSA-SHA256");
  sign.update(message, "utf8");
  return sign.sign(pem, "base64");
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
};

const TS_CACHE_KEY = "payok_ts";
const UUID_CACHE_KEY = "payok_uuid";
const TS_CACHE_TTL = 10_000;

export const plugin: PluginDefinition = {
  templateFunctions: [
    {
      name: "payok.signature",
      description:
        "Generate PAYOK RSA-SHA256 digital signature. Reads the request body automatically from context.",
      previewType: "none",
      args: [
        {
          type: "text",
          name: "path",
          label: "Endpoint Path",
          placeholder: "/api/v1/payment",
        },
        {
          type: "text",
          name: "private_key",
          label: "Private Key (Base64, without PEM headers)",
          placeholder: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...",
          password: true,
          multiLine: true,
        },
      ],
      async onRender(ctx, args) {
        const path = String(args.values.path ?? "").trim();
        const privateKey = String(args.values.private_key ?? "").trim();

        if (!path || !privateKey) return null;

        const requestId = await ctx.window.requestId();
        if (!requestId) return null;

        const rawRequest = await ctx.httpRequest.getById({ id: requestId });
        if (!rawRequest) return null;

        // Read raw body text (template tags still unresolved) to avoid render recursion
        const rawBodyText = extractBodyText(rawRequest.body);
        if (!rawBodyText) return null;

        // Expire caches so each send gets a fresh timestamp and UUID.
        // payok.timestamp/payok.uuid will regenerate values on the next call and
        // cache them, so the subsequent actual body render reuses the same values.
        await ctx.store.set(TS_CACHE_KEY, { ts: "", at: 0 });
        await ctx.store.set(UUID_CACHE_KEY, { id: "", at: 0 });

        // Render only the body string — ctx.templates.render resolves {{ }} tags
        // without triggering a full request render (no infinite recursion)
        const renderedBody = await ctx.templates.render({
          data: rawBodyText,
          purpose: args.purpose,
        });

        if (typeof renderedBody !== "string" || !renderedBody) return null;

        return generateSignature(renderedBody, path, privateKey);
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
  ],
};

async function runExportSignatureCode(
  ctx: Context,
  args: CallHttpRequestActionArgs,
): Promise<void> {
  const { httpRequest } = args;

  const rawBodyText = extractBodyText(httpRequest.body) ?? "";
  const renderedBody = rawBodyText
    ? await safeRenderTemplate(ctx, rawBodyText)
    : "";
  const renderedUrl = await safeRenderTemplate(ctx, httpRequest.url);
  const path = extractPath(renderedUrl);

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
    privateKey: privateKey || undefined,
  };

  const values = await ctx.prompt.form({
    id: "payok-export-signature-code",
    title: "Export Signature Code",
    description: privateKey
      ? "Standalone code that reproduces the PAYOK signature algorithm using this request's current path, body, and private key. This code contains your real private key — handle it securely."
      : "Standalone code that reproduces the PAYOK signature algorithm using this request's current path and body. No private_key was found on the sign header, so a TODO comment in the exported code tells you where to paste your own key.",
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
