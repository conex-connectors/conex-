import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handle } from '../src/handler.ts';
import { MemoryStore } from '../src/memory-store.ts';
import { parseRpc, RpcError } from '../src/jsonrpc.ts';

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

const tokens: Record<string, string> = { 'tok-A': 'A', 'tok-B': 'B' };
const auth = { authenticate: async (t: string) => (tokens[t] ? { userId: tokens[t] } : null) };

function setup() {
  const s = new MemoryStore();
  s.plans.set('A', { calls: 200 });
  s.plans.set('B', { calls: 200 });
  const add = (id: string, userId: string, name: string, host: string, token: string, status: 'connected' | 'disabled' = 'connected') => {
    s.secrets.set(id, token);
    s.connectors.set(id, { id, userId, name, endpointUrl: `https://${host}/mcp`, credentialRef: id, status });
  };
  const deps = { store: s, secrets: s, auth, authServerUrl: 'https://proj.supabase.co/auth/v1', fetch: fakeFetch, resolve: async () => ['93.184.216.34'], allowedOrigins: ['https://app.example.com'] };
  const rpc = (tok: string | null, method: string, params?: object, id = 1) =>
    handle(new Request('https://gw.test/mcp', {
      method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
      headers: tok ? { authorization: `Bearer ${tok}` } : {},
    }), deps).then((r) => r.json() as Promise<any>);
  return { s, add, rpc, deps };
}
const names = (r: any) => r.result.tools.map((t: any) => t.name).sort();

test('same URL for everyone; add two, remove one, remove last, delete again', async () => {
  const { s, add, rpc } = setup();
  assert.deepEqual((await rpc('tok-A', 'tools/list')).result.tools, []);
  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  add('c2', 'A', 'Cloudflare', 'cf.example.com', 'T2');
  assert.deepEqual(names(await rpc('tok-A', 'tools/list')), ['cloudflare__whoami', 'github__get_me']);
  assert.equal(await s.deleteConnector('A', 'c1'), 'deleted');
  assert.deepEqual(names(await rpc('tok-A', 'tools/list')), ['cloudflare__whoami']);
  assert.equal(await s.deleteConnector('A', 'c2'), 'deleted');
  assert.deepEqual((await rpc('tok-A', 'tools/list')).result.tools, []);
  assert.equal(s.secrets.size, 0);
  assert.equal(await s.deleteConnector('A', 'c2'), 'not_found');
});

test('disconnected connector disappears from tools and comes back when reconnected', async () => {
  const { s, add, rpc } = setup();
  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  s.connectors.get('c1')!.status = 'disabled';
  assert.deepEqual((await rpc('tok-A', 'tools/list')).result.tools, []);
  assert.ok((await rpc('tok-A', 'tools/call', { name: 'github__get_me' })).error);
  s.connectors.get('c1')!.status = 'connected';
  assert.deepEqual(names(await rpc('tok-A', 'tools/list')), ['github__get_me']);
});

test('no token or bad token -> 401 with discovery pointer', async () => {
  const { deps } = setup();
  for (const headers of [{}, { authorization: 'Bearer nope' }, { authorization: 'Basic abc' }]) {
    const r = await handle(new Request('https://gw.test/mcp', { method: 'POST', body: '{}', headers }), deps);
    assert.equal(r.status, 401);
    assert.match(r.headers.get('www-authenticate')!, /resource_metadata="https:\/\/gw\.test\/\.well-known\/oauth-protected-resource"/);
  }
});

test('protected resource metadata points at Supabase auth', async () => {
  const { deps } = setup();
  const r = await handle(new Request('https://gw.test/.well-known/oauth-protected-resource'), deps);
  assert.deepEqual(await r.json(), { resource: 'https://gw.test/mcp', authorization_servers: ['https://proj.supabase.co/auth/v1'], bearer_methods_supported: ['header'] });
});

test('tools/call routes correctly, records outcome, no secrets in output', async () => {
  const { s, add, rpc } = setup();
  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  const r = await rpc('tok-A', 'tools/call', { name: 'github__get_me', arguments: {} });
  assert.equal(r.result.content[0].text, 'get_me ok');
  assert.deepEqual(s.events.map((e) => [e.tool, e.outcome]), [['get_me', 'success']]);
  assert.ok(!JSON.stringify(r).includes('T1'));
});

test('no plan -> plan_required error, upstream never called', async () => {
  const { s, add, rpc } = setup();
  s.plans.delete('A');
  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  const r = await rpc('tok-A', 'tools/call', { name: 'github__get_me' });
  assert.equal(r.error.code, -32001);
  assert.equal(s.events.length, 0);
});

test('daily limit blocks the next call and logs it', async () => {
  const { s, add, rpc } = setup();
  s.plans.set('A', { calls: 2 });
  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  for (let i = 0; i < 2; i++) assert.ok((await rpc('tok-A', 'tools/call', { name: 'github__get_me' })).result);
  const r = await rpc('tok-A', 'tools/call', { name: 'github__get_me' });
  assert.equal(r.error.code, -32002);
  assert.equal(s.events.filter((e) => e.outcome === 'blocked').length, 1);
});

test('user isolation', async () => {
  const { s, add, rpc } = setup();
  add('c1', 'A', 'GitHub', 'gh.example.com', 'T1');
  assert.deepEqual((await rpc('tok-B', 'tools/list')).result.tools, []);
  assert.ok((await rpc('tok-B', 'tools/call', { name: 'github__get_me' })).error);
  assert.equal(await s.deleteConnector('B', 'c1'), 'not_found');
  assert.ok(s.connectors.has('c1'));
});

test('wrong upstream token fails visibly; failing connector does not hide healthy ones; errors are logged', async () => {
  const { s, add, rpc } = setup();
  add('c1', 'A', 'GitHub', 'gh.example.com', 'WRONG');
  add('c2', 'A', 'Cloudflare', 'cf.example.com', 'T2');
  assert.deepEqual(names(await rpc('tok-A', 'tools/list')), ['cloudflare__whoami']);
  const r = await rpc('tok-A', 'tools/call', { name: 'github__get_me' });
  assert.match(r.error.message, /rejected credentials/);
  assert.equal(s.events.at(-1)!.outcome, 'error');
});

test('upstream redirects and private endpoints are refused', async () => {
  const { add, rpc, s } = setup();
  add('c1', 'A', 'Redir', 'redir.example.com', 'T3');
  assert.match((await rpc('tok-A', 'tools/call', { name: 'redir__x' })).error.message, /redirect refused/);
  s.connectors.set('c2', { id: 'c2', userId: 'A', name: 'Evil', endpointUrl: 'https://169.254.169.254/mcp', credentialRef: null, status: 'connected' });
  assert.match((await rpc('tok-A', 'tools/call', { name: 'evil__x' })).error.message, /not allowed/);
});

test('agent recorded only on initialize, with its own name', async () => {
  const { s, rpc } = setup();
  await rpc('tok-A', 'tools/list');
  assert.equal(s.agents.length, 0);
  const r = await rpc('tok-A', 'initialize', { clientInfo: { name: 'Grok' } });
  assert.equal(r.result.serverInfo.name, 'conex');
  assert.deepEqual(s.agents, [{ userId: 'A', agentName: 'Grok' }]);
});

test('bad method, CORS allowlist, GET refused, 404', async () => {
  const { rpc, deps } = setup();
  assert.equal((await rpc('tok-A', 'resources/list')).error.code, -32601);
  assert.equal((await handle(new Request('https://gw.test/mcp', { method: 'POST', body: '{}', headers: { origin: 'https://evil.com' } }), deps)).status, 403);
  assert.equal((await handle(new Request('https://gw.test/mcp', { method: 'GET' }), deps)).status, 405);
  assert.equal((await handle(new Request('https://gw.test/mcp/cx-oldstyle12345', { method: 'POST' }), deps)).status, 404);
});

test('JSON-RPC validation', () => {
  for (const bad of ['{', '[]', '{"jsonrpc":"1.0","method":"ping"}', '{"jsonrpc":"2.0","method":"ping","params":[]}', '{"jsonrpc":"2.0","method":"nope"}'])
    assert.throws(() => parseRpc(bad), RpcError);
  assert.equal(parseRpc('{"jsonrpc":"2.0","id":1,"method":"ping"}').method, 'ping');
});
