import { test } from 'node:test';
import assert from 'node:assert/strict';
import { importKey, encryptSecret, decryptSecret, toB64 } from '../src/crypto.ts';
import { supabaseAuthenticator } from '../src/auth.ts';
import { SupabaseStore } from '../src/supabase-store.ts';
import { PlanRequiredError } from '../src/types.ts';

const KEY = toB64(new Uint8Array(32).map((_, i) => i + 1));

test('crypto round-trip, tamper and wrong-connector (AAD) fail', async () => {
  const key = await importKey(KEY);
  const { ciphertext, iv } = await encryptSecret(key, 'ghp_secret', 'conn-1');
  assert.ok(!ciphertext.includes('ghp_secret'));
  assert.equal(await decryptSecret(key, ciphertext, iv, 'conn-1'), 'ghp_secret');
  await assert.rejects(decryptSecret(key, ciphertext, iv, 'conn-2'));
  const bad = ciphertext.slice(0, -4) + 'AAAA';
  await assert.rejects(decryptSecret(key, bad, iv, 'conn-1'));
  const e2 = await encryptSecret(key, 'ghp_secret', 'conn-1');
  assert.notEqual(e2.iv, iv); // fresh IV every time
  await assert.rejects(importKey(toB64(new Uint8Array(16))));
});

test('authenticator: valid token, caching, rejection, malformed id', async () => {
  let calls = 0; let t = 1000;
  const uid = '11111111-2222-3333-4444-555555555555';
  const f = (async (url: any, init: any) => {
    calls++;
    assert.equal(String(url), 'https://p.supabase.co/auth/v1/user');
    assert.equal(init.headers.apikey, 'pk');
    const tok = init.headers.authorization.slice(7);
    if (tok === 'good') return Response.json({ id: uid });
    if (tok === 'weird') return Response.json({ id: 'not-a-uuid' });
    return new Response('{}', { status: 401 });
  }) as typeof fetch;
  const a = supabaseAuthenticator({ url: 'https://p.supabase.co', publishableKey: 'pk', fetch: f, ttlMs: 60_000, now: () => t });
  assert.deepEqual(await a.authenticate('good'), { userId: uid });
  await a.authenticate('good'); assert.equal(calls, 1); // cached
  t += 61_000; await a.authenticate('good'); assert.equal(calls, 2); // expired -> re-check
  assert.equal(await a.authenticate('bad'), null);
  assert.equal(await a.authenticate('weird'), null);
  assert.equal(await a.authenticate(''), null);
});

test('SupabaseStore: queries, rpc names/args, error mapping, secret decrypt', async () => {
  const key = await importKey(KEY);
  const enc = await encryptSecret(key, 'TOKEN-1', 'cid-1');
  const seen: { url: string; method: string; body?: any; auth: string }[] = [];
  const f = (async (url: any, init: any = {}) => {
    const u = String(url); seen.push({ url: u, method: init.method ?? 'GET', body: init.body ? JSON.parse(init.body) : undefined, auth: init.headers.authorization });
    if (u.includes('/rpc/conex_begin_call')) {
      return JSON.parse(init.body).p_tool === 'noplan'
        ? new Response(JSON.stringify({ code: 'P0001', message: 'plan_required' }), { status: 400 })
        : new Response('42', { status: 200 });
    }
    if (u.includes('/rpc/conex_delete_connector')) return new Response('"deleted"');
    if (u.includes('/rpc/conex_touch_agent') || u.includes('/rpc/conex_finish_call')) return new Response(null, { status: 204 });
    if (u.includes('conex_connectors?')) return Response.json([
      { id: 'cid-1', user_id: 'u1', name: 'GitHub', endpoint_url: 'https://x.example.com/mcp', credential_secret_ref: 'cid-1' },
      { id: 'cid-2', user_id: 'u1', name: 'NoUrl', endpoint_url: null, credential_secret_ref: null },
    ]);
    if (u.includes('conex_connector_secrets?connector_id=eq.cid-1')) return Response.json([{ ciphertext: enc.ciphertext, iv: enc.iv }]);
    if (u.includes('conex_connector_secrets?')) return Response.json([]);
    return new Response('boom secret text', { status: 500 });
  }) as typeof fetch;
  const s = new SupabaseStore({ url: 'https://p.supabase.co', serviceKey: 'SERVICE', fetch: f, encKey: key });

  const list = await s.listConnectors('u1');
  assert.deepEqual(list, [{ id: 'cid-1', userId: 'u1', name: 'GitHub', endpointUrl: 'https://x.example.com/mcp', credentialRef: 'cid-1', authMethod: null, tokenUrl: null, autoRefresh: false }]);
  assert.match(seen[0].url, /user_id=eq\.u1&status=eq\.connected/);
  assert.equal(seen[0].auth, 'Bearer SERVICE');

  assert.equal(await s.deleteConnector('u1', 'cid-1'), 'deleted');
  await s.touchAgent('u1', 'Grok');
  assert.equal(await s.beginCall('u1', 'cid-1', 'get_me'), 42);
  await s.finishCall(42, 'success');
  await assert.rejects(s.beginCall('u1', 'cid-1', 'noplan'), PlanRequiredError);
  assert.deepEqual(seen.find((x) => x.url.endsWith('conex_begin_call'))!.body, { p_user: 'u1', p_connector: 'cid-1', p_tool: 'get_me' });

  assert.equal(await s.get('cid-1'), 'TOKEN-1');
  assert.equal(await s.get('missing'), null);
  const wrongKey = new SupabaseStore({ url: 'https://p.supabase.co', serviceKey: 'S', fetch: f, encKey: await importKey(toB64(new Uint8Array(32).fill(9))) });
  assert.equal(await wrongKey.get('cid-1'), null); // cannot decrypt with another key

  const boom = new SupabaseStore({ url: 'https://p.supabase.co', serviceKey: 'S', fetch: (async () => new Response('boom secret text', { status: 500 })) as typeof fetch, encKey: key });
  await assert.rejects(boom.listConnectors('u1'), (e: Error) => !e.message.includes('secret text'));
});
