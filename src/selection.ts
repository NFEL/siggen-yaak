import type { Context, HttpRequest } from "@yaakapp/api";

export type SignatureValues = Record<string, unknown>;
export const DEFAULT_FIELDS = [
  "DebtorAccount", "CreditorAccount", "Amount", "IdempotencyKey",
  "CreditorFirstName", "CreditorLastName", "clientId", "IssuedAt", "iat",
];
export const MAX_FIELDS = 32;

export function fieldCount(values: SignatureValues): number {
  const count = Number(values.field_count ?? DEFAULT_FIELDS.length);
  if (!Number.isInteger(count) || count < 1 || count > MAX_FIELDS) {
    throw new Error(`Select between 1 and ${MAX_FIELDS} signature fields`);
  }
  return count;
}

export function lookupOptions(request: HttpRequest | null) {
  const options = [{ label: "Leave out", value: "" }];
  if (request) {
    try {
      const body: unknown = JSON.parse(request.body.text ?? "");
      const visit = (value: unknown, pointer: string, depth: number) => {
        const displayPath = pointer.slice(1).split("/").map(part => part.replace(/~1/g, "/").replace(/~0/g, "~")).join(" › ");
        options.push({ label: pointer ? `Body: ${displayPath}` : "Body: entire JSON object", value: `body:${pointer}` });
        if (depth >= 16 || options.length >= 500) return;
        if (value !== null && typeof value === "object") {
          for (const [key, child] of Object.entries(value)) {
            if (options.length >= 500) break;
            visit(child, `${pointer}/${key.replace(/~/g, "~0").replace(/\//g, "~1")}`, depth + 1);
          }
        }
      };
      visit(body, "", 0);
    } catch {
      // Custom JSON pointers remain available for bodies containing unresolved templates.
    }
    for (const header of request.headers) {
      if (header.enabled === false || !header.name.trim() || header.value.includes("payok.signature")) continue;
      const value = `header:${header.name.toLowerCase()}`;
      if (!options.some(option => option.value === value)) {
        options.push({ label: `Header: ${header.name}`, value });
      }
    }
    const queryNames = new Set(request.urlParameters.filter(p => p.enabled !== false && p.name.trim()).map(p => p.name));
    try {
      for (const name of new URL(request.url).searchParams.keys()) if (name.trim()) queryNames.add(name);
    } catch {
      // Rendered URLs can still be selected through a custom query lookup.
    }
    for (const name of queryNames) options.push({ label: `Query: ${name}`, value: `query:${name}` });
  }
  options.push(
    { label: "Request method", value: "method" },
    { label: "Request URL", value: "url" },
    { label: "Request URL path", value: "path" },
    { label: "Custom path (advanced)…", value: "custom" },
  );
  return options;
}


function jsonPointer(body: unknown, pointer: string): unknown {
  if (pointer === "") return body;
  if (!pointer.startsWith("/")) throw new Error("Body lookup must use a JSON pointer, e.g. body:/Amount");
  let value = body;
  for (const part of pointer.slice(1).split("/")) {
    if (/~(?![01])/u.test(part)) throw new Error(`Invalid JSON pointer: ${pointer}`);
    const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
    if (value === null || typeof value !== "object" || !Object.prototype.hasOwnProperty.call(value, key)) {
      throw new Error(`Body field not found: ${pointer}`);
    }
    value = (value as Record<string, unknown>)[key];
  }
  return value;
}

/** Builds compact JSON in selection order; body values retain their JSON types. */
export async function buildSelectedMessage(
  ctx: Context,
  request: HttpRequest,
  values: SignatureValues,
  purpose: "preview" | "send",
): Promise<string> {
  const render = async (data: string): Promise<string> => {
    if (data.includes("payok.signature")) throw new Error("A signature cannot include itself in its payload");
    const value = await ctx.templates.render({ data, purpose });
    if (typeof value !== "string") throw new Error("Request lookup did not render to text");
    return value;
  };
  let bodyPromise: Promise<unknown> | undefined;
  let urlPromise: Promise<URL> | undefined;
  const entries: string[] = [];
  const names = new Set<string>();
  const checked = Object.entries(values).filter(([key, value]) => key.startsWith("include_") && (value === true || value === "true"));
  const fields: Array<{ name: string; lookup: string; custom?: unknown }> = checked.map(([key]) => {
    const lookup = Buffer.from(key.slice(8), "base64url").toString("utf8");
    const sourceName = lookup.slice(lookup.indexOf(":") + 1);
    const name = lookup.startsWith("body:")
      ? sourceName.split("/").pop()!.replace(/~1/g, "/").replace(/~0/g, "~")
      : lookup.startsWith("header:")
        ? request.headers.find(header => header.name.toLowerCase() === sourceName)?.name ?? sourceName
        : sourceName;
    return { name, lookup };
  });
  if (values.preset === "tejarat") {
    fields.length = 0;
    const options = lookupOptions(request);
    const aliases: Record<string, string[]> = {
      DebtorAccount: ["query::SourceAccountNumber", "body:/sourceAccountNumber"],
      CreditorAccount: ["body:/destinationAccountNumber"],
      Amount: ["body:/amount"],
      IdempotencyKey: ["header:idempotency-key"],
    };
    for (const name of DEFAULT_FIELDS) {
      const candidates = [`body:/${name}`, `header:${name.toLowerCase()}`, `query:${name}`, ...(aliases[name] ?? [])];
      let lookup = String(values[`tejarat_${name}`] ?? candidates.find(value => options.some(option => option.value === value)) ?? "");
      if (name === "IssuedAt") lookup = "timestamp:milliseconds";
      if (name === "iat") lookup = "timestamp:seconds";
      if (name === "clientId") lookup = `variable:${String(values.tejarat_client_variable ?? "client_id").trim() || "client_id"}`;
      if (!lookup && (name === "CreditorFirstName" || name === "CreditorLastName")) continue;
      if (!lookup) throw new Error(`Tejarat حواله: select a request value for ${name}`);
      fields.push({ name, lookup });
    }
  }
  for (let i = 1; values.preset !== "tejarat" && i <= fieldCount(values); i++) {
    const name = String(values[`field_${i}_name`] ?? DEFAULT_FIELDS[i - 1] ?? "").trim();
    const lookup = String(values[`field_${i}_lookup`] ?? "");
    if (lookup) fields.push({ name, lookup, custom: values[`field_${i}_custom`] });
  }
  const timestamp = Date.now();
  for (const field of fields) {
    const name = field.name;
    let lookup = field.lookup;
    if (!lookup) continue;
    if (lookup === "custom") lookup = String(field.custom ?? "").trim();
    if (!name) throw new Error("Signature field needs an output name");
    if (names.has(name)) throw new Error(`Duplicate signature field: ${name}`);
    names.add(name);
    let value: unknown;
    if (lookup === "timestamp:milliseconds") {
      value = timestamp;
    } else if (lookup === "timestamp:seconds") {
      value = Math.floor(timestamp / 1000);
    } else if (lookup.startsWith("variable:")) {
      const variable = lookup.slice(9);
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) throw new Error("Invalid client ID variable name");
      value = await render(`\${[ ${variable} ]}`);
      if (!value || value === `\${[ ${variable} ]}`) throw new Error(`Client ID variable is empty or unresolved: ${variable}`);
    } else if (lookup.startsWith("body:")) {
      bodyPromise ??= render(request.body.text ?? "").then(text => JSON.parse(text));
      value = jsonPointer(await bodyPromise, lookup.slice(5));
    } else if (lookup.startsWith("header:")) {
      const name = lookup.slice(7).toLowerCase();
      const headers = request.headers.filter(h => h.enabled !== false && h.name.toLowerCase() === name);
      if (headers.length !== 1) throw new Error(`Expected one enabled header: ${name}`);
      value = await render(headers[0].value);
    } else if (lookup.startsWith("query:")) {
      const name = lookup.slice(6);
      const parameters = request.urlParameters.filter(p => p.enabled !== false && p.name === name);
      const matches = parameters.length
        ? await Promise.all(parameters.map(p => render(p.value)))
        : (await (urlPromise ??= render(request.url).then(value => new URL(value)))).searchParams.getAll(name);
      if (matches.length !== 1) throw new Error(`Expected one enabled query parameter: ${name}`);
      value = matches[0];
    } else if (lookup === "method") {
      value = await render(request.method);
    } else if (lookup === "url") {
      value = await render(request.url);
    } else if (lookup === "path") {
      value = (await (urlPromise ??= render(request.url).then(value => new URL(value)))).pathname;
    } else {
      throw new Error(`Unknown request lookup: ${lookup || "(empty)"}`);
    }
    // Assemble entries directly so integer-like output names also retain selection order.
    entries.push(`${JSON.stringify(name)}:${JSON.stringify(value)}`);
  }
  if (!entries.length) throw new Error("Select at least one field for the signature payload");
  return `{${entries.join(",")}}`;
}
