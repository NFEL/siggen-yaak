const assert = require('node:assert/strict');
const { test } = require('node:test');
const { generateKeyPairSync, sign, verify } = require('node:crypto');
const vm = require('node:vm');
const { plugin } = require('../build/index.js');

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const signatureFunction = plugin.templateFunctions.find(fn => fn.name === 'payok.signature');

function context(request) {
  const store = new Map();
  return {
    window: { requestId: async () => request.id },
    httpRequest: { getById: async () => request },
    store: { get: async key => store.get(key), set: async (key, value) => { store.set(key, value); } },
    templates: { render: async ({ data }) => data.replace('CLIENT_ID_TEMPLATE', 'client-123') },
  };
}

function request() {
  return {
    id: 'request-1', method: 'POST', url: 'https://example.com/api/transactions?clientId=url-client',
    body: { text: JSON.stringify({ DebtorAccount: '0398950442269', Amount: 1234, approved: false, nullable: null, nested: { 'a/b~c': ['first', 'second'] }, CreditorFirstName: 'نام' }) },
    headers: [
      { name: 'Idempotency-Key', value: 'transaction-123' },
      { name: 'clientId', value: 'CLIENT_ID_TEMPLATE' },
      { name: 'x-jws-signature', value: '${[ payok.signature() ]}' },
    ],
    urlParameters: [{ name: 'clientId', value: 'parameter-client' }],
  };
}

function selection(fields) {
  const values = { message_mode: 'selected', private_key: privateKey, field_count: String(fields.length) };
  fields.forEach(([name, lookup], index) => {
    values[`field_${index + 1}_name`] = name;
    values[`field_${index + 1}_lookup`] = lookup;
  });
  return values;
}

async function assertSignature(request, values, message) {
  const signature = await signatureFunction.onRender(context(request), { values, purpose: 'send' });
  assert.equal(verify('RSA-SHA256', Buffer.from(message), keys.publicKey, Buffer.from(signature, 'base64')), true);
  assert.equal(verify('RSA-SHA256', Buffer.from(message + '&/api/transactions'), keys.publicKey, Buffer.from(signature, 'base64')), false);
  return signature;
}

test('selected JSON preserves types, Unicode, order, and request header/query lookups without a path suffix', async () => {
  const req = request();
  const fields = [['DebtorAccount', 'body:/DebtorAccount'], ['Amount', 'body:/Amount'], ['IdempotencyKey', 'header:idempotency-key'], ['clientId', 'header:CLIENTID'], ['queryClient', 'query:clientId'], ['approved', 'body:/approved'], ['nullable', 'body:/nullable'], ['name', 'body:/CreditorFirstName']];
  const message = '{"DebtorAccount":"0398950442269","Amount":1234,"IdempotencyKey":"transaction-123","clientId":"client-123","queryClient":"parameter-client","approved":false,"nullable":null,"name":"نام"}';
  await assertSignature(req, selection(fields), message);
});

test('nested JSON pointers, custom lookups, and numeric output names retain row order', async () => {
  const values = selection([['10', 'body:/nested/a~1b~0c/1'], ['2', 'custom'], ['method', 'method'], ['path', 'path']]);
  values.field_2_custom = 'query:clientId';
  const req = request();
  req.urlParameters = [];
  await assertSignature(req, values, '{"10":"second","2":"url-client","method":"POST","path":"/api/transactions"}');
});

test('header-only selection works without a body or endpoint path', async () => {
  const req = request();
  req.body = {};
  await assertSignature(req, selection([['IdempotencyKey', 'header:Idempotency-Key']]), '{"IdempotencyKey":"transaction-123"}');
});

test('unselected rows are omitted and selected objects retain their structure', async () => {
  await assertSignature(request(), selection([['unused', ''], ['data', 'body:/nested']]), '{"data":{"a/b~c":["first","second"]}}');
});

test('missing, ambiguous, recursive, and invalid selections fail rather than signing incomplete data', async () => {
  const cases = [
    [selection([['missing', 'body:/missing']]), /Body field not found/],
    [selection([['prototype', 'body:/toString']]), /Body field not found/],
    [selection([['bad', 'body:/nested/~2']]), /Invalid JSON pointer/],
    [selection([['same', 'method'], ['same', 'path']]), /Duplicate signature field/],
    [selection([['self', 'header:x-jws-signature']]), /cannot include itself/],
    [selection([['missing', 'header:missing']]), /Expected one enabled header/],
    [selection([['unused', '']]), /Select at least one/],
    [{ ...selection([['method', 'method']]), field_count: '33' }, /between 1 and 32/],
  ];
  for (const [values, error] of cases) {
    await assert.rejects(signatureFunction.onRender(context(request()), { values, purpose: 'send' }), error);
  }
  const req = request();
  req.headers.push({ name: 'IDEMPOTENCY-KEY', value: 'duplicate' });
  await assert.rejects(signatureFunction.onRender(context(req), { values: selection([['id', 'header:idempotency-key']]), purpose: 'send' }), /Expected one enabled header/);
  req.headers = [{ name: 'disabled', value: 'secret', enabled: false }];
  await assert.rejects(signatureFunction.onRender(context(req), { values: selection([['id', 'header:disabled']]), purpose: 'send' }), /Expected one enabled header/);
});

test('existing PAYOK tags keep signing full rendered body plus configured endpoint', async () => {
  const req = request();
  const signature = await signatureFunction.onRender(context(req), { values: { private_key: privateKey, path: '/configured-path' }, purpose: 'send' });
  assert.equal(verify('RSA-SHA256', Buffer.from(req.body.text + '&/configured-path'), keys.publicKey, Buffer.from(signature, 'base64')), true);
});

test('export action captures the selected JSON payload and produces a matching signature', async () => {
  const req = request();
  const values = selection([['Amount', 'body:/Amount'], ['IdempotencyKey', 'header:Idempotency-Key']]);
  req.headers[2].value = '${[ payok.signature(' + Object.entries(values).map(([name, value]) => `${name}=b64'${Buffer.from(value).toString('base64url')}'`).join(', ') + ') ]}';
  const ctx = context(req);
  let form;
  let copied;
  ctx.prompt = { form: async input => { form = input; return { language: 'javascript' }; } };
  ctx.clipboard = { copyText: async value => { copied = value; } };
  ctx.toast = { show: async value => { assert.notEqual(value.color, 'danger', value.message); } };
  await plugin.httpRequestActions[0].onSelect(ctx, { httpRequest: req });
  assert.ok(form);
  // Supply valid webhook fixtures: untouched webhook demo placeholders are unrelated to outgoing signing.
  const webhookBody = 'notification';
  const webhookSignature = sign('RSA-SHA256', Buffer.from(webhookBody), keys.privateKey).toString('base64');
  const executable = copied.replace('PASTE_RECEIVED_WEBHOOK_BODY_HERE', webhookBody)
    .replace('PASTE_RECEIVED_SIGNATURE_HERE', webhookSignature)
    .replace('PASTE_PAYOK_BASE64_PUBLIC_KEY_HERE', keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'));
  const output = [];
  vm.runInNewContext(executable, { require, console: { log: (...args) => output.push(args) } });
  assert.equal(verify('RSA-SHA256', Buffer.from('{"Amount":1234,"IdempotencyKey":"transaction-123"}'), keys.publicKey, Buffer.from(output[0][1], 'base64')), true);
  assert.deepEqual(output[1], ['webhook valid:', true]);
});
