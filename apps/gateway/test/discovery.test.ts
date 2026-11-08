import { test } from 'node:test';
import assert from 'node:assert/strict';
import { discoverTokenEndpoint } from '../src/discovery.ts';
import { handleApi, type ApiDeps } from '../src/api.ts';
import { MemoryStore } from '../src/memory-store.ts';
import { importKey, toB64 } from '../src/crypto.ts';

const resolve = async () => ['93.184.216.34'];
const meta: Record<string, any> = {
  'https://svc.example.com/.well-known/oauth-protected-resource/mcp': { authorization_servers: ['https://auth.example.com'] },
  'https://auth.example.com/.well-known/oauth-authorization-server': { token_endpoint: 'https://auth.example.com/oauth/token' },
  'https://own.example.com/.well-known/oauth-authorization-server': { token_endpoint: 'https://own.example.com/token' },
  'https://oidc.example.com/.well-known/openid-configuration': { token_endpoint: 'https://oidc.example.com/t' },
  'https://evil.example.com/.well-known/oauth-authorization-server': { token_endpoint: 'https://169.254.169.254/token' },
  'https://prm.example.com/.well-known/oauth-protected-resource': { authorization_servers: ['https://169.254.169.254', 'https://auth.example.com'] },
};
const seen: string[] = [];
const f = (async (url: any, init: any = {}) => {
  const u = String(url); seen.push(u);
  if (init.redirect !== 'manual') throw new Error('redirects must be refused');
  return u in meta ? Response.json(meta[u]) : new Response('no', { status: 404 });
}) as typeof fetch;

test('discovers via protected-resource metadata, own server, OpenID config', async () => {
  assert.equal(await discoverTokenEndpoint('https://svc.example.com/mcp', { fetch: f, resolve }), 'https://auth.example.com/oauth/token');
  assert.equal(await discoverTokenEndpoint('https://own.example.com/mcp', { fetch: f, resolve }), 'https://own.example.com/token');
  assert.equal(await discoverTokenEndpoint('https://oidc.example.com/', { fetch: f, resolve }), 'https://oidc.example.com/t');
  assert.equal(await discoverTokenEndpoint('https://prm.example.com/mcp', { fetch: f, resolve }), 'https://auth.example.com/oauth/token'); // skips the private issuer
});

test('returns null when nothing is found, for private token endpoints, and for junk', async () => {
  assert.equal(await discoverTokenEndpoint('https://nothing.example.com/mcp', { fetch: f, resolve }), null);
  assert.equal(await discoverTokenEndpoint('https://evil.example.com/mcp', { fetch: f, resolve }), null);
  assert.equal(await discoverTokenEndpoint('not a url', { fetch: f, resolve }), null);
  assert.equal(await discoverTokenEndpoint('https://svc.example.com/mcp', { fetch: f, resolve: async () => ['10.0.0.1'] }), null);
});

test('API: client ID + secret with NO token URL works when discovery succeeds, asks for it only when it fails', async () => {
  const store = new MemoryStore();
  const U = '11111111-2222-3333-4444-555555555555';
  store.subs.set(U, { plan: 'starter', status: 'active', billingInterval: 'monthly', periodEnd: new Date(Date.now() + 86400000).toISOString(), providerSubscriptionId: 'I-X1234567', statusUpdatedAt: null });
  const api = (async (input: any, init: any = {}) => {
    const u = new URL(String(input));
    if (u.pathname.startsWith('/.well-known/')) return u.host === 'svc.example.com' && u.pathname.includes('protected-resource') ? Response.json({ authorization_servers: ['https://auth.example.com'] }) : u.host === 'auth.example.com' ? Response.json({ token_endpoint: 'https://auth.example.com/oauth/token' }) : new Response('no', { status: 404 });
    if (u.host === 'auth.example.com') return Response.json({ access_token: 'ACCESS', expires_in: 3600 });
    if (u.host === 'svc.example.com' || u.host === 'plain.example.com') {
      if (init.headers.authorization !== 'Bearer ACCESS') return new Response('no', { status: 401 });
      const b = JSON.parse(init.body); if (b.id === undefined) return new Response(null, { status: 202 });
      return Response.json({ jsonrpc: '2.0', id: b.id, result: b.method === 'initialize' ? { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'x', version: '1' } } : { tools: [{ name: 't' }] } });
    }
    throw new Error('unreachable ' + u.host);
  }) as typeof fetch;
  const deps: ApiDeps = { store, secrets: store, fetch: api, resolve, encKey: await importKey(toB64(new Uint8Array(32).fill(5))), billing: null, deleteUser: async () => true };
  const post = async (body: unknown) => { const r = await handleApi(new Request('https://gw.test/api/connectors', { method: 'POST', body: JSON.stringify(body) }), new URL('https://gw.test/api/connectors'), U, deps); return { status: r.status, body: await r.json() as any }; };

  const ok = await post({ kind: 'client_credentials', name: 'Svc', url: 'https://svc.example.com/mcp', clientId: 'a', clientSecret: 'b', autoRefresh: true });
  assert.deepEqual([ok.status, ok.body.status], [201, 'connected']);
  assert.equal((await store.getConnector(U, ok.body.id))!.tokenUrl, 'https://auth.example.com/oauth/token');

  const need = await post({ kind: 'client_credentials', name: 'Plain', url: 'https://plain.example.com/mcp', clientId: 'a', clientSecret: 'b', autoRefresh: true });
  assert.deepEqual([need.status, need.body.error], [422, 'token_url_needed']);

  const manual = await post({ kind: 'client_credentials', name: 'Plain', url: 'https://plain.example.com/mcp', clientId: 'a', clientSecret: 'b', tokenUrl: 'https://auth.example.com/oauth/token', autoRefresh: true });
  assert.equal(manual.status, 201);
});
