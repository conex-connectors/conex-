import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handle } from '../src/handler.ts';
import { MemoryStore } from '../src/memory-store.ts';
import { parseRpc, RpcError } from '../src/jsonrpc.ts';

// Fake upstream MCP servers keyed by hostname.
type Up = { token: string; tools: string[]; sse?: boolean; redirect?: boolean };
const ups: Record<string, Up> = {
  'gh.example.com': { token: 'T1', tools: ['get_me'] },
  'cf.example.com': { token: 'T2', tools: ['whoami'], sse: true },
  'redir.example.com': { token: 'T3', tools: ['x'], redirect: true },
};
const fakeFetch = (async (input: any, init: any) => {
  const u = new URL(String(input)); const up = ups[u.hostname];
  if (!up) throw new Error('unreachable');
  if (up.redirect) return new Response(null, { status: 302, headers: { location: 'https://127.0.0.1/' } });
  if (init.headers.authorization !== `Bearer ${up.token}`) return new Response('no', { status: 401 });
  const b = JSON.parse(init.body);
  if (b.id === undefined) return new Response(null, { status: 202 });
  let result: any = {};
  if (b.method === 'initialize') result = { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'up', version: '1' } };
  if (b.method === 'tools/list') result = { tools: up.tools.map((name) => ({ name, inputSchema: { type: 'object' } })) };
  if (b.method === 'tools/call') result = { content: [{ type: 'text', text: `${b.params.name} ok` }] };
  const msg = { jsonrpc: '2.0', id: b.id, result };
  return up.sse
    ? new Response(`event: message\ndata: ${JSON.stringify(msg)}\n\n`, { headers: { 'content-type': 'text/event-stream', 'mcp-session-id': 's1' } })
    : Response.json(msg, { headers: { 'mcp-session-id': 's1' } });
}) as typeof fetch;

function setup() {
  const s = new MemoryStore();
  s.linkers.set('cx-aaaaaaaa1', { userId: 'A', linkerId: 'cx-aaaaaaaa1', enabled: true });
  s.linkers.set('cx-bbbbbbbb1', { userId: 'B', linkerId: 'cx-bbbbbbbb1', enabled: true });
  const add = (id: string, userId: string, name: string, host: string, token: string) => {
    s.secrets.set(`ref-${id}`, token);
    s.connectors.set(id, { id, userId, name, endpointUrl: `https://${host}/mcp`, credentialRef: `ref-${id}` });
  };
  const deps = { store: s, secrets: s, fetch: fakeFetch, resolve: async () => ['93.184.216.34'], allowedOrigins: ['https://app.example.com'] };
  const rpc = (linker: string, method: string, params?: object, id = 1) =>
    handle(new Request(`https://gw.test/mcp/${linker}`, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id, method, params }) }), deps)
      .then((r) => r.json() as Promise<any>);
  return { s, add, rpc, deps };
}

test('stable linker URL: add two, remove one, remove last, delete again', async () => {
  const { s, add, rpc } = setup();
  assert.deepEqual((await rpc('cx-aaaaaaaa1', 'tools/list')).result.tools, []); // new account: nothing

  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  add('c2', 'A', 'Cloudflare', 'cf.example.com', 'T2');
  const names = (await rpc('cx-aaaaaaaa1', 'tools/list')).result.tools.map((t: any) => t.name).sort();
  assert.deepEqual(names, ['cloudflare__whoami', 'github__get_me']);

  assert.equal(await s.deleteConnector('A', 'c1'), 'deleted');
  assert.deepEqual((await rpc('cx-aaaaaaaa1', 'tools/list')).result.tools.map((t: any) => t.name), ['cloudflare__whoami']);

  assert.equal(await s.deleteConnector('A', 'c2'), 'deleted'); // last connector
  assert.deepEqual((await rpc('cx-aaaaaaaa1', 'tools/list')).result.tools, []);
  assert.ok(await s.getLinker('cx-aaaaaaaa1')); // linker survives
  assert.equal(s.secrets.size, 0); // no orphaned credentials

  assert.equal(await s.deleteConnector('A', 'c2'), 'not_found'); // idempotent
});

test('tools/call routes to right connector, records usage, no secrets in output', async () => {
  const { s, add, rpc } = setup();
  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  const r = await rpc('cx-aaaaaaaa1', 'tools/call', { name: 'github__get_me', arguments: {} });
  assert.equal(r.result.content[0].text, 'get_me ok');
  assert.deepEqual(s.usage.map((u) => [u.toolName, u.outcome]), [['get_me', 'ok']]);
  assert.ok(!JSON.stringify(r).includes('T1'));
});

test('user isolation', async () => {
  const { s, add, rpc } = setup();
  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  assert.deepEqual((await rpc('cx-bbbbbbbb1', 'tools/list')).result.tools, []);
  assert.ok((await rpc('cx-bbbbbbbb1', 'tools/call', { name: 'github__get_me' })).error);
  assert.equal(await s.deleteConnector('B', 'c1'), 'not_found');
  assert.ok(s.connectors.has('c1'));
});

test('wrong token fails visibly; failing connector does not hide healthy ones', async () => {
  const { add, rpc } = setup();
  add('c1', 'A', 'GitHub', 'gh.example.com', 'WRONG');
  add('c2', 'A', 'Cloudflare', 'cf.example.com', 'T2');
  assert.deepEqual((await rpc('cx-aaaaaaaa1', 'tools/list')).result.tools.map((t: any) => t.name), ['cloudflare__whoami']);
  const r = await rpc('cx-aaaaaaaa1', 'tools/call', { name: 'github__get_me' });
  assert.match(r.error.message, /rejected credentials/);
});

test('upstream redirects and private endpoints are refused', async () => {
  const { add, rpc, s } = setup();
  add('c1', 'A', 'Redir', 'redir.example.com', 'T3');
  assert.match((await rpc('cx-aaaaaaaa1', 'tools/call', { name: 'redir__x' })).error.message, /redirect refused/);
  s.connectors.set('c2', { id: 'c2', userId: 'A', name: 'Evil', endpointUrl: 'https://169.254.169.254/mcp', credentialRef: null });
  assert.match((await rpc('cx-aaaaaaaa1', 'tools/call', { name: 'evil__x' })).error.message, /not allowed/);
});

test('agent connection recorded only on initialize', async () => {
  const { s, rpc } = setup();
  await rpc('cx-aaaaaaaa1', 'tools/list');
  assert.equal(s.agents.length, 0);
  const r = await rpc('cx-aaaaaaaa1', 'initialize', { clientInfo: { name: 'claude-code' } });
  assert.equal(r.result.serverInfo.name, 'conex');
  assert.deepEqual(s.agents, [{ userId: 'A', agentName: 'claude-code' }]);
});

test('unknown/disabled linker 404, bad method, CORS allowlist, GET refused', async () => {
  const { s, rpc, deps } = setup();
  assert.equal((await handle(new Request('https://gw.test/mcp/cx-zzzzzzzz1', { method: 'POST', body: '{}' }), deps)).status, 404);
  s.linkers.get('cx-bbbbbbbb1')!.enabled = false;
  assert.equal((await handle(new Request('https://gw.test/mcp/cx-bbbbbbbb1', { method: 'POST', body: '{}' }), deps)).status, 404);
  assert.equal((await rpc('cx-aaaaaaaa1', 'resources/list')).error.code, -32601);
  assert.equal((await handle(new Request('https://gw.test/mcp/cx-aaaaaaaa1', { method: 'POST', body: '{}', headers: { origin: 'https://evil.com' } }), deps)).status, 403);
  assert.equal((await handle(new Request('https://gw.test/mcp/cx-aaaaaaaa1', { method: 'GET' }), deps)).status, 405);
});

test('JSON-RPC validation', () => {
  for (const bad of ['{', '[]', '{"jsonrpc":"1.0","method":"ping"}', '{"jsonrpc":"2.0","method":"ping","params":[]}', '{"jsonrpc":"2.0","method":"nope"}'])
    assert.throws(() => parseRpc(bad), RpcError);
  assert.equal(parseRpc('{"jsonrpc":"2.0","id":1,"method":"ping"}').method, 'ping');
});
