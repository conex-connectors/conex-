import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAuthHeaders, fetchClientCredentialsToken, CredentialError } from '../src/credentials.ts';

const resolve = async () => ['93.184.216.34'];

test('bearer and supabase header shapes', async () => {
  const f = (async () => { throw new Error('no network expected'); }) as typeof fetch;
  assert.deepEqual(await buildAuthHeaders({ id: '1', userId: 'u', name: 'n', endpointUrl: 'https://x', credentialRef: 'r', authMethod: 'bearer' }, 'T', { fetch: f }), { authorization: 'Bearer T' });
  assert.deepEqual(await buildAuthHeaders({ id: '1', userId: 'u', name: 'n', endpointUrl: 'https://x', credentialRef: 'r' }, 'T', { fetch: f }), { authorization: 'Bearer T' });
  assert.deepEqual(await buildAuthHeaders({ id: '2', userId: 'u', name: 'n', endpointUrl: 'https://x', credentialRef: 'r', authMethod: 'supabase' },
    JSON.stringify({ kind: 'supabase', serviceKey: 'SK', anonKey: 'AK', supabaseUrl: 'https://p.supabase.co' }), { fetch: f }),
    { authorization: 'Bearer SK', apikey: 'AK', 'x-supabase-url': 'https://p.supabase.co' });
  assert.deepEqual(await buildAuthHeaders({ id: '3', userId: 'u', name: 'n', endpointUrl: 'https://x', credentialRef: null }, null, { fetch: f }), {});
});

test('refresh mode: fetches once, caches until near expiry, then refreshes', async () => {
  let n = 0; let t = 1_000_000;
  const f = (async () => { n++; return Response.json({ access_token: `A${n}`, expires_in: 100 }); }) as typeof fetch;
  const c = { id: 'cc-1', userId: 'u', name: 'n', endpointUrl: 'https://x', credentialRef: 'r', authMethod: 'client_credentials' as const, tokenUrl: 'https://token.example.com/t', autoRefresh: true };
  const secret = JSON.stringify({ mode: 'refresh', clientId: 'a', clientSecret: 'b' });
  const d = { fetch: f, resolve, now: () => t };
  assert.equal((await buildAuthHeaders(c, secret, d)).authorization, 'Bearer A1');
  assert.equal((await buildAuthHeaders(c, secret, d)).authorization, 'Bearer A1'); assert.equal(n, 1);
  t += 80_000;
  assert.equal((await buildAuthHeaders(c, secret, d)).authorization, 'Bearer A2'); assert.equal(n, 2);
});

test('static mode expires with a clear message', async () => {
  const c = { id: 'cc-2', userId: 'u', name: 'n', endpointUrl: 'https://x', credentialRef: 'r', authMethod: 'client_credentials' as const };
  const f = (async () => { throw new Error('x'); }) as typeof fetch;
  const ok = JSON.stringify({ mode: 'static', accessToken: 'S', expiresAt: 5000 });
  assert.equal((await buildAuthHeaders(c, ok, { fetch: f, now: () => 1000 })).authorization, 'Bearer S');
  await assert.rejects(buildAuthHeaders(c, ok, { fetch: f, now: () => 6000 }), /expired/);
  await assert.rejects(buildAuthHeaders(c, 'not json', { fetch: f }), CredentialError);
});

test('token exchange: Basic first, falls back to body credentials, refuses redirects/private hosts', async () => {
  const seen: string[] = [];
  const f = (async (_u: any, init: any) => {
    seen.push(init.headers.authorization ? 'basic' : 'post');
    if (init.headers.authorization) return new Response('{}', { status: 401 });
    return Response.json({ access_token: 'OK', expires_in: 60 });
  }) as typeof fetch;
  const t = await fetchClientCredentialsToken('https://token.example.com/t', 'id', 'sec', 'read', { fetch: f, resolve });
  assert.deepEqual([t.accessToken, t.expiresIn, seen], ['OK', 60, ['basic', 'post']]);
  const redirect = (async () => new Response(null, { status: 302 })) as typeof fetch;
  await assert.rejects(fetchClientCredentialsToken('https://token.example.com/t', 'i', 's', undefined, { fetch: redirect, resolve }), /redirect refused/);
  await assert.rejects(fetchClientCredentialsToken('https://token.example.com/t', 'i', 's', undefined, { fetch: f, resolve: async () => ['10.0.0.1'] }));
});
