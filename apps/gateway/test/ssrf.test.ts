import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateEndpointUrl, validateEndpointWithDns, isBlockedIp, SsrfError } from '../src/ssrf.ts';

const bad = [
  'http://example.com/mcp', 'https://localhost/mcp', 'https://foo.localhost/mcp', 'https://127.0.0.1/mcp',
  'https://0x7f.1/mcp', 'https://2130706433/mcp', 'https://10.0.0.5/mcp', 'https://172.16.0.1/mcp',
  'https://192.168.1.1/mcp', 'https://169.254.169.254/latest/meta-data', 'https://metadata.google.internal/x',
  'https://[::1]/mcp', 'https://[::ffff:127.0.0.1]/mcp', 'https://[::ffff:7f00:1]/mcp', 'https://[fd00::1]/mcp',
  'https://[fe80::1]/mcp', 'https://[64:ff9b::a00:1]/mcp', 'https://[2002:7f00:1::]/mcp',
  'https://example.com:8443/mcp', 'https://user:pw@example.com/mcp', 'https://intranet/mcp', 'https://100.64.0.1/mcp',
  'ftp://example.com/', 'not a url', '',
];
for (const u of bad) test(`blocks ${u || '(empty)'}`, () => assert.throws(() => validateEndpointUrl(u), SsrfError));

test('allows public https', () => {
  assert.equal(validateEndpointUrl('https://mcp.example.com/mcp').hostname, 'mcp.example.com');
  assert.equal(validateEndpointUrl('https://mcp.example.com:443/mcp').hostname, 'mcp.example.com');
});
test('isBlockedIp', () => {
  assert.ok(isBlockedIp('10.1.2.3')); assert.ok(isBlockedIp('::')); assert.ok(isBlockedIp('garbage'));
  assert.ok(!isBlockedIp('8.8.8.8')); assert.ok(!isBlockedIp('2606:4700:4700::1111'));
});
test('DNS rebinding: public name resolving to private IP is blocked', async () => {
  await assert.rejects(validateEndpointWithDns('https://evil.example.com/mcp', async () => ['93.184.216.34', '10.0.0.7']), SsrfError);
  await assert.rejects(validateEndpointWithDns('https://evil.example.com/mcp', async () => ['::ffff:169.254.169.254']), SsrfError);
  await assert.rejects(validateEndpointWithDns('https://nx.example.com/mcp', async () => []), SsrfError);
  await validateEndpointWithDns('https://ok.example.com/mcp', async () => ['93.184.216.34']);
});
