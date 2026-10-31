const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { plugin } = require('../build/index.js');

test('request checkboxes sign only checked fields and export the same payload', async () => {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const request = { id: 'one', body: { text: '{"amount":42,"description":"omit me"}' }, headers: [{ name: 'clientId', value: 'client-1' }], url: 'https://example.com/pay', urlParameters: [], method: 'POST' };
  const store = new Map();
  let form;
  const ctx = {
    window: { requestId: async () => 'one' }, httpRequest: { getById: async () => request },
    templates: { render: async ({ data }) => data },
    store: { get: async key => store.get(key), set: async (key, value) => { store.set(key, value); } },
    prompt: { form: async value => { form = value; return null; } },
    toast: { show: async value => { throw new Error(value.message); } },
  };
  const fn = plugin.templateFunctions[0];
  const values = { message_mode: 'selected', private_key: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
  const fields = await fn.args.find(input => input.type === 'banner').dynamic(ctx, { values, purpose: 'preview' });
  for (const label of ['Body: amount', 'Header: clientId']) {
    const checkbox = fields.inputs.find(input => input.label === label);
    assert.ok(checkbox);
    values[checkbox.name] = true;
  }
  const signature = await fn.onRender(ctx, { values, purpose: 'send' });
  assert.equal(crypto.verify('RSA-SHA256', Buffer.from('{"amount":42,"clientId":"client-1"}'), pair.publicKey, Buffer.from(signature, 'base64')), true);
  request.headers.push({ name: 'signature', value: '${[ payok.signature(' + Object.entries(values).map(([key, value]) => `${key}=b64'${Buffer.from(String(value)).toString('base64url')}'`).join(',') + ') ]}' });
  await plugin.httpRequestActions[0].onSelect(ctx, { httpRequest: request });
  const code = form.inputs.find(input => input.type === 'editor').dynamic(ctx, { values: { language: 'javascript' } }).defaultValue;
  assert.ok(code.includes('\\"amount\\":42,\\"clientId\\":\\"client-1\\"'));
});
