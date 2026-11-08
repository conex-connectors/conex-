import { test } from 'node:test';
import assert from 'node:assert/strict';
import { route, isAgentToken, type RouterDeps } from '../src/router.ts';
import { MemoryStore } from '../src/memory-store.ts';
import { importKey, toB64 } from '../src/crypto.ts';

const USER = '11111111-2222-3333-4444-555555555555';
const OTHER = '22222222-2222-3333-4444-555555555555';
const jwt = (claims: object) => `h.${btoa(JSON.stringify(claims)).replace(/=+$/, '')}.s`;
const TOK = jwt({ sub: USER }), OTHER_TOK = jwt({ sub: OTHER }), AGENT_TOK = jwt({ sub: USER, client_id: 'agent-1' });
const users: Record<string, string> = { [TOK]: USER, [OTHER_TOK]: OTHER, [AGENT_TOK]: USER };

async function setup() {
  const store = new MemoryStore();
  store.subs.set(USER, { plan: 'starter', status: 'active', billingInterval: 'monthly', periodEnd: new Date(Date.now() + 20 * 86400000).toISOString(), providerSubscriptionId: 'I-TEST123456', statusUpdatedAt: null });
  const upstream: Record<string, { token?: string; tools: string[] }> = { 'good.example.com': { token: 'TKN', tools: ['a', 'b'] }, 'oauth.example.com': { tools: ['x'] } };
  const hits: string[] = [];
  const f = (async (input: any, init: any = {}) => {
    const u = new URL(String(input)); hits.push(`${init.method ?? 'GET'} ${u.host}${u.pathname}`);
    if (u.host === 'token.example.com') {
      const body = String(init.body); const basic = init.headers?.authorization;
      if (!(basic === `Basic ${btoa('cid:csecret')}` || body.includes('client_secret=csecret'))) return new Response('{}', { status: 401 });
      return Response.json({ access_token: 'ACCESS-1', expires_in: 3600 });
    }
    if (u.host === 'dir.example.com') return Response.json({ items: [{ id: 'gh', name: 'GitHub' }], echo: { auth: init.headers.authorization, user: init.headers['x-conex-user'], path: u.pathname + u.search } });
    const up = upstream[u.host]; if (!up) throw new Error('unreachable');
    const auth = init.headers.authorization;
    if (up.token && auth !== `Bearer ${up.token}`) return new Response('no', { status: 401 });
    if (!up.token && auth !== 'Bearer ACCESS-1') return new Response('no', { status: 401 });
    const b = JSON.parse(init.body); if (b.id === undefined) return new Response(null, { status: 202 });
    const result = b.method === 'initialize' ? { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'u', version: '1' } } : { tools: up.tools.map((name) => ({ name })) };
    return Response.json({ jsonrpc: '2.0', id: b.id, result });
  }) as typeof fetch;
  const resolve = async () => ['93.184.216.34'];
  const deleted: string[] = [];
  const deps: RouterDeps = {
    mcp: { store, secrets: store, fetch: f, resolve, auth: { authenticate: async (t: string) => (users[t] ? { userId: users[t] } : null) }, authServerUrl: 'https://p.supabase.co/auth/v1', allowedOrigins: [] },
    api: { store, secrets: store, fetch: f, resolve, encKey: await importKey(toB64(new Uint8Array(32).fill(3))), billing: null, deleteUser: async (u) => { deleted.push(u); return true; } },
    billing: null, paypalClientId: 'CID', supabaseUrl: 'https://p.supabase.co', publishableKey: 'pk',
    browse: { baseUrl: undefined, apiKey: undefined, fetch: f, resolve },
  };
  const call = async (method: string, path: string, body?: unknown, tok: string | null = TOK) => {
    const r = await route(new Request(`https://gw.test${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body), headers: tok ? { authorization: `Bearer ${tok}` } : {} }), deps);
    const text = await r.text();
    return { status: r.status, body: text ? JSON.parse(text) : null, text };
  };
  return { store, call, hits, deleted, deps };
}

test('account API needs a real user token; agent tokens are refused', async () => {
  const { call } = await setup();
  assert.equal((await call('GET', '/api/me', undefined, null)).status, 401);
  assert.equal((await call('GET', '/api/me', undefined, 'bogus')).status, 401);
  assert.equal((await call('GET', '/api/me', undefined, AGENT_TOK)).status, 403);
  assert.equal(isAgentToken(AGENT_TOK), true); assert.equal(isAgentToken(TOK), false); assert.equal(isAgentToken('x'), false);
});

test('GET /api/me reflects plan state', async () => {
  const { call, store } = await setup();
  assert.deepEqual((await call('GET', '/api/me', undefined, OTHER_TOK)).body, { plan: 'none', status: 'inactive', billingInterval: null, periodEnd: null, active: false, limits: { connectors: 0, calls: 0 } });
  store.subs.set(OTHER, { plan: 'pro', status: 'active', billingInterval: 'yearly', periodEnd: new Date(Date.now() + 86400000).toISOString(), providerSubscriptionId: 'I-1', statusUpdatedAt: null });
  const me = (await call('GET', '/api/me', undefined, OTHER_TOK)).body;
  assert.deepEqual([me.plan, me.active, me.limits], ['pro', true, { connectors: 100, calls: 1000 }]);
});

test('add MCP/token connector: verified for real, encrypted, then listed', async () => {
  const { call, store, hits } = await setup();
  const r = await call('POST', '/api/connectors', { kind: 'bearer', name: 'My server', url: 'https://good.example.com/mcp', token: 'TKN' });
  assert.deepEqual([r.status, r.body.status, r.body.tools], [201, 'connected', 2]);
  assert.ok(hits.some((h) => h.startsWith('POST good.example.com')));
  const secret = store.secrets.get(r.body.id)!;
  assert.ok(secret.startsWith('ENC:') && !secret.includes('TKN'));
  assert.equal((await store.listConnectors(USER)).length, 1);
});

test('add connector refuses: no plan, bad token, http, private address, bad input; nothing saved', async () => {
  const { call, store, hits } = await setup();
  const before = hits.length;
  assert.equal((await call('POST', '/api/connectors', { kind: 'bearer', name: 'x', url: 'https://good.example.com/mcp', token: 'T' }, OTHER_TOK)).status, 402);
  assert.equal(hits.length, before); // plan checked before touching the network
  const bad = await call('POST', '/api/connectors', { kind: 'bearer', name: 'x', url: 'https://good.example.com/mcp', token: 'WRONG' });
  assert.deepEqual([bad.status, bad.body.error], [422, 'verify_failed']);
  for (const url of ['http://good.example.com/mcp', 'https://169.254.169.254/mcp', 'https://localhost/mcp'])
    assert.equal((await call('POST', '/api/connectors', { kind: 'bearer', name: 'x', url, token: 'T' })).status, 422);
  assert.equal((await call('POST', '/api/connectors', { kind: 'bearer', name: '', url: 'https://good.example.com/mcp', token: 'T' })).status, 400);
  assert.equal((await call('POST', '/api/connectors', { kind: 'nope', name: 'x', url: 'https://good.example.com/mcp' })).status, 400);
  assert.equal(store.connectors.size, 0);
});

test('connector limit per plan is enforced (starter = 30)', async () => {
  const { call, store } = await setup();
  for (let i = 0; i < 30; i++) store.connectors.set(`c${i}`, { id: `c${i}`, userId: USER, name: `n${i}`, endpointUrl: 'https://good.example.com/mcp', credentialRef: null, status: 'connected' });
  const r = await call('POST', '/api/connectors', { kind: 'bearer', name: 'x', url: 'https://good.example.com/mcp', token: 'TKN' });
  assert.deepEqual([r.status, r.body.error], [409, 'connector_limit_reached']);
});

test('client ID + secret: static token and auto-refresh modes', async () => {
  const { call, store } = await setup();
  const a = await call('POST', '/api/connectors', { kind: 'client_credentials', name: 'OAuth A', url: 'https://oauth.example.com/mcp', tokenUrl: 'https://token.example.com/token', clientId: 'cid', clientSecret: 'csecret', autoRefresh: false });
  assert.deepEqual([a.status, a.body.tools], [201, 1]);
  const c = await store.getConnector(USER, a.body.id);
  assert.deepEqual([c!.authMethod, c!.autoRefresh, c!.tokenUrl], ['client_credentials', false, 'https://token.example.com/token']);
  const b = await call('POST', '/api/connectors', { kind: 'client_credentials', name: 'OAuth B', url: 'https://oauth.example.com/mcp', tokenUrl: 'https://token.example.com/token', clientId: 'cid', clientSecret: 'csecret', autoRefresh: true });
  assert.equal(b.status, 201);
  assert.equal((await call('POST', '/api/connectors', { kind: 'client_credentials', name: 'bad', url: 'https://oauth.example.com/mcp', tokenUrl: 'https://token.example.com/token', clientId: 'cid', clientSecret: 'WRONG', autoRefresh: false })).body.error, 'token_failed');
  assert.equal((await call('POST', '/api/connectors', { kind: 'client_credentials', name: 'bad', url: 'https://oauth.example.com/mcp', tokenUrl: 'https://10.0.0.1/token', clientId: 'cid', clientSecret: 'csecret' })).body.error, 'url_not_allowed');
});

test('Supabase connection stores its three values together', async () => {
  const { call } = await setup();
  const bad = await call('POST', '/api/connectors', { kind: 'supabase', name: 'DB', url: 'https://good.example.com/mcp', supabaseUrl: 'https://x.supabase.co', anonKey: 'anon' });
  assert.equal(bad.status, 400);
});

test('disconnect hides tools, reconnect re-verifies, failed reconnect marks error, delete is final', async () => {
  const { call, store } = await setup();
  const add = await call('POST', '/api/connectors', { kind: 'bearer', name: 'S', url: 'https://good.example.com/mcp', token: 'TKN' });
  const id = add.body.id;
  assert.equal((await call('POST', `/api/connectors/${id}/disconnect`)).body.status, 'disabled');
  assert.equal((await store.listConnectors(USER)).length, 0);
  store.secrets.set(id, 'TKN'); // make the stored secret directly usable in this fake
  assert.equal((await call('POST', `/api/connectors/${id}/connect`)).body.status, 'connected');
  store.secrets.set(id, 'WRONG');
  const fail = await call('POST', `/api/connectors/${id}/connect`);
  assert.deepEqual([fail.status, (await store.getConnector(USER, id))!.status], [422, 'error']);
  assert.equal((await call('DELETE', `/api/connectors/${id}`)).status, 204);
  assert.equal((await call('DELETE', `/api/connectors/${id}`)).status, 404);
  assert.equal(store.secrets.has(id), false);
});

test("a user cannot touch another user's connector", async () => {
  const { call, store } = await setup();
  const add = await call('POST', '/api/connectors', { kind: 'bearer', name: 'S', url: 'https://good.example.com/mcp', token: 'TKN' });
  const id = add.body.id;
  assert.equal((await call('POST', `/api/connectors/${id}/disconnect`, undefined, OTHER_TOK)).status, 404);
  assert.equal((await call('DELETE', `/api/connectors/${id}`, undefined, OTHER_TOK)).status, 404);
  assert.equal((await call('POST', `/api/connectors/${id}/connect`, undefined, OTHER_TOK)).status, 404);
  assert.equal((await call('DELETE', '/api/connectors/not-a-uuid')).status, 404);
  assert.equal(store.connectors.get(id)!.status, 'connected');
});

test('token generator: needs a plan, returns the token once, refuses private token URLs', async () => {
  const { call } = await setup();
  const ok = await call('POST', '/api/token-generator', { tokenUrl: 'https://token.example.com/token', clientId: 'cid', clientSecret: 'csecret' });
  assert.deepEqual([ok.status, ok.body.accessToken, ok.body.expiresIn], [200, 'ACCESS-1', 3600]);
  assert.equal((await call('POST', '/api/token-generator', { tokenUrl: 'https://token.example.com/token', clientId: 'cid', clientSecret: 'csecret' }, OTHER_TOK)).status, 402);
  assert.equal((await call('POST', '/api/token-generator', { tokenUrl: 'https://192.168.0.1/t', clientId: 'cid', clientSecret: 's' })).status, 422);
  assert.equal((await call('POST', '/api/token-generator', { tokenUrl: 'https://token.example.com/token', clientId: 'cid', clientSecret: 'bad' })).body.error, 'token_failed');
});

test('account deletion requires explicit confirmation', async () => {
  const { call, deleted } = await setup();
  assert.equal((await call('POST', '/api/account/delete', {})).status, 400);
  assert.equal((await call('POST', '/api/account/delete', { confirm: 'delete' })).status, 400);
  assert.equal((await call('POST', '/api/account/delete', { confirm: 'DELETE' })).status, 204);
  assert.deepEqual(deleted, [USER]);
});

test('Browse box: coming soon until configured, then a pass-through that adds the key server-side', async () => {
  const { call, deps } = await setup();
  assert.deepEqual((await call('GET', '/api/browse/connectors')).body, { error: 'browse_not_configured' });
  deps.browse.baseUrl = 'https://dir.example.com/v1'; deps.browse.apiKey = 'DIR-KEY';
  const r = await call('GET', '/api/browse/connectors?q=git');
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.echo, { auth: 'Bearer DIR-KEY', user: USER, path: '/v1/connectors?q=git' });
  assert.equal((await call('POST', '/api/browse/connect', { id: 'gh' })).status, 200);
  assert.equal((await call('GET', '/api/browse/connectors', undefined, null)).status, 401);
  deps.browse.baseUrl = 'https://10.0.0.5/v1';
  assert.equal((await call('GET', '/api/browse/connectors')).status, 503);
});
