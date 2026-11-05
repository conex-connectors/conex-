import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PayPal } from '../src/paypal.ts';
import { MemoryStore } from '../src/memory-store.ts';
import { startCheckout, confirmSubscription, handleWebhook, mapSubscription } from '../src/billing.ts';
import { sessionKey, signSession, verifySession } from '../src/session.ts';
import { PLANS } from '../src/plans.ts';
import { entitled } from '../src/types.ts';
import { toB64 } from '../src/crypto.ts';

const USER = '11111111-2222-3333-4444-555555555555';
const OTHER = '99999999-2222-3333-4444-555555555555';
const KEY_B64 = toB64(new Uint8Array(32).map((_, i) => i + 7));
const NOW = Date.parse('2026-11-05T10:00:00Z');

function setup() {
  const subs = new Map<string, any>();
  const calls: string[] = [];
  const f = (async (url: any, init: any = {}) => {
    const u = new URL(String(url)); calls.push(`${init.method ?? 'GET'} ${u.pathname}`);
    if (u.pathname === '/v1/oauth2/token') return Response.json({ access_token: 'PP_TOKEN', expires_in: 32000 });
    const m = /^\/v1\/billing\/subscriptions\/(I-[A-Z0-9]+)(\/cancel)?$/.exec(u.pathname);
    if (m && m[2]) { subs.get(m[1]).status = 'CANCELLED'; return new Response(null, { status: 204 }); }
    if (m) return subs.has(m[1]) ? Response.json(subs.get(m[1])) : new Response('{}', { status: 404 });
    if (u.pathname === '/v1/notifications/verify-webhook-signature') {
      const b = JSON.parse(init.body);
      return Response.json({ verification_status: b.transmission_sig === 'good' && b.webhook_id === 'WH1' ? 'SUCCESS' : 'FAILURE' });
    }
    return new Response('?', { status: 500 });
  }) as typeof fetch;
  const store = new MemoryStore();
  return { subs, calls, store, f, build: async () => ({ paypal: new PayPal({ clientId: 'CID', clientSecret: 'SECRET', webhookId: 'WH1', env: 'live', fetch: f, now: () => NOW }), store, sessionKey: await sessionKey(KEY_B64), now: () => NOW }) };
}
const sub = (over: any = {}) => ({
  id: 'I-ABC123XYZ', plan_id: PLANS.starter_monthly.paypalPlanId, status: 'ACTIVE', custom_id: USER,
  status_update_time: '2026-11-05T09:59:00Z', billing_info: { next_billing_time: '2026-12-05T09:59:00Z' }, ...over,
});

test('session: valid, tampered, expired, wrong key', async () => {
  const k = await sessionKey(KEY_B64);
  const t = await signSession(k, { u: USER, p: 'pro_yearly', exp: NOW + 1000 });
  assert.deepEqual(await verifySession(k, t, NOW), { u: USER, p: 'pro_yearly', exp: NOW + 1000 });
  assert.equal(await verifySession(k, t, NOW + 2000), null);
  assert.equal(await verifySession(k, t.slice(0, -2) + 'AA', NOW), null);
  const [body, sig] = t.split('.');
  const forged = btoa(JSON.stringify({ u: OTHER, p: 'pro_yearly', exp: NOW + 1000 })).replace(/=+$/, '');
  assert.equal(await verifySession(k, `${forged}.${sig}`, NOW), null);
  assert.equal(await verifySession(await sessionKey(toB64(new Uint8Array(32).fill(1))), t, NOW), null);
  assert.equal(await verifySession(k, `${body}.${sig}.x`, NOW), null);
});

test('startCheckout only for the six plans', async () => {
  const { build } = setup(); const d = await build();
  assert.equal(await startCheckout(d, USER, 'gold_monthly', 'https://gw.test'), null);
  assert.equal(await startCheckout(d, USER, '__proto__', 'https://gw.test'), null);
  const r = await startCheckout(d, USER, 'scale_yearly', 'https://gw.test');
  assert.match(r!.url, /^https:\/\/gw\.test\/pay\?s=/);
});

test('confirm: PayPal says ACTIVE for this user and plan -> access granted from PayPal facts', async () => {
  const { subs, store, build } = setup(); const d = await build();
  subs.set('I-ABC123XYZ', sub());
  const token = new URL((await startCheckout(d, USER, 'starter_monthly', 'https://gw.test'))!.url).searchParams.get('s')!;
  const r = await confirmSubscription(d, token, 'I-ABC123XYZ');
  assert.deepEqual([r.status, (r.body as any).state], [200, 'active']);
  const s = await store.getSubscription(USER);
  assert.equal(s!.plan, 'starter'); assert.equal(s!.billingInterval, 'monthly');
  assert.equal(entitled(s, NOW), true);
  assert.equal(s!.periodEnd, '2026-12-07T09:59:00.000Z'); // next billing + 2 days grace
});

test('confirm refuses: other user, wrong plan, bad id, bad session, unpaid, unknown', async () => {
  const { subs, store, build } = setup(); const d = await build();
  const tok = async (plan: string, user = USER) => new URL((await startCheckout(d, user, plan, 'https://x'))!.url).searchParams.get('s')!;
  subs.set('I-ABC123XYZ', sub());
  assert.equal((await confirmSubscription(d, await tok('starter_monthly', OTHER), 'I-ABC123XYZ')).status, 403);
  assert.equal((await confirmSubscription(d, await tok('pro_yearly'), 'I-ABC123XYZ')).status, 409);
  assert.equal((await confirmSubscription(d, await tok('starter_monthly'), 'not-an-id')).status, 400);
  assert.equal((await confirmSubscription(d, 'garbage', 'I-ABC123XYZ')).status, 401);
  assert.equal((await confirmSubscription(d, await tok('starter_monthly'), 'I-NOPE12345')).status, 404);
  subs.set('I-PEND12345', sub({ id: 'I-PEND12345', status: 'APPROVAL_PENDING' }));
  const pend = await confirmSubscription(d, await tok('starter_monthly'), 'I-PEND12345');
  assert.deepEqual([pend.status, (pend.body as any).state], [200, 'pending']);
  assert.equal(await store.getSubscription(USER), null); // nothing granted
});

test('upgrading cancels the previous PayPal subscription', async () => {
  const { subs, calls, build, store } = setup(); const d = await build();
  subs.set('I-ABC123XYZ', sub());
  const t1 = new URL((await startCheckout(d, USER, 'starter_monthly', 'https://x'))!.url).searchParams.get('s')!;
  await confirmSubscription(d, t1, 'I-ABC123XYZ');
  subs.set('I-NEW123456', sub({ id: 'I-NEW123456', plan_id: PLANS.pro_yearly.paypalPlanId, status_update_time: '2026-11-05T09:59:30Z' }));
  const t2 = new URL((await startCheckout(d, USER, 'pro_yearly', 'https://x'))!.url).searchParams.get('s')!;
  await confirmSubscription(d, t2, 'I-NEW123456');
  assert.ok(calls.includes('POST /v1/billing/subscriptions/I-ABC123XYZ/cancel'));
  assert.equal((await store.getSubscription(USER))!.plan, 'pro');
});

const hook = (id: string, type: string, resource: any) => JSON.stringify({ id, event_type: type, resource });
const hdr = (sig = 'good') => new Headers({ 'paypal-auth-algo': 'SHA256withRSA', 'paypal-cert-url': 'https://api.paypal.com/c', 'paypal-transmission-id': 't', 'paypal-transmission-sig': sig, 'paypal-transmission-time': 'now' });

test('webhook: bad or missing signature changes nothing', async () => {
  const { subs, store, build } = setup(); const d = await build(); subs.set('I-ABC123XYZ', sub());
  const body = hook('WH-1', 'BILLING.SUBSCRIPTION.ACTIVATED', { id: 'I-ABC123XYZ' });
  assert.equal((await handleWebhook(d, hdr('bad'), body)).status, 400);
  assert.equal((await handleWebhook(d, new Headers(), body)).status, 400);
  assert.equal(await store.getSubscription(USER), null);
});

test('webhook lifecycle: activate, duplicate, renew, payment failed, cancel keeps access, expire', async () => {
  const { subs, store, build } = setup(); const d = await build(); subs.set('I-ABC123XYZ', sub());
  let r = await handleWebhook(d, hdr(), hook('WH-1', 'BILLING.SUBSCRIPTION.ACTIVATED', { id: 'I-ABC123XYZ' }));
  assert.deepEqual([r.status, (r.body as any).state], [200, 'applied']);
  r = await handleWebhook(d, hdr(), hook('WH-1', 'BILLING.SUBSCRIPTION.ACTIVATED', { id: 'I-ABC123XYZ' }));
  assert.equal((r.body as any).state, 'duplicate');

  subs.set('I-ABC123XYZ', sub({ status_update_time: '2026-12-05T10:00:00Z', billing_info: { next_billing_time: '2027-01-05T10:00:00Z' } }));
  r = await handleWebhook(d, hdr(), hook('WH-2', 'PAYMENT.SALE.COMPLETED', { billing_agreement_id: 'I-ABC123XYZ' }));
  assert.equal((r.body as any).state, 'applied');
  assert.equal((await store.getSubscription(USER))!.periodEnd, '2027-01-07T10:00:00.000Z');

  subs.set('I-ABC123XYZ', sub({ status: 'SUSPENDED', status_update_time: '2027-01-06T10:00:00Z' }));
  await handleWebhook(d, hdr(), hook('WH-3', 'BILLING.SUBSCRIPTION.PAYMENT.FAILED', { id: 'I-ABC123XYZ' }));
  assert.equal((await store.getSubscription(USER))!.status, 'past_due');

  subs.set('I-ABC123XYZ', sub({ status: 'CANCELLED', status_update_time: '2027-01-07T10:00:00Z' }));
  await handleWebhook(d, hdr(), hook('WH-4', 'BILLING.SUBSCRIPTION.CANCELLED', { id: 'I-ABC123XYZ' }));
  const s = await store.getSubscription(USER);
  assert.equal(s!.status, 'cancelled'); assert.equal(s!.periodEnd, '2027-01-07T10:00:00.000Z'); // paid period kept
  assert.equal(entitled(s, Date.parse('2027-01-01T00:00:00Z')), true);
  assert.equal(entitled(s, Date.parse('2027-01-08T00:00:00Z')), false);

  subs.set('I-ABC123XYZ', sub({ status: 'EXPIRED', status_update_time: '2027-02-01T10:00:00Z' }));
  await handleWebhook(d, hdr(), hook('WH-5', 'BILLING.SUBSCRIPTION.EXPIRED', { id: 'I-ABC123XYZ' }));
  assert.equal((await store.getSubscription(USER))!.plan, 'none');
});

test('webhook: stale, unknown plan, unknown type, no custom_id, lookup failure', async () => {
  const { subs, store, build } = setup(); const d = await build();
  subs.set('I-ABC123XYZ', sub({ status_update_time: '2026-11-05T09:59:00Z' }));
  await handleWebhook(d, hdr(), hook('WH-1', 'BILLING.SUBSCRIPTION.ACTIVATED', { id: 'I-ABC123XYZ' }));
  subs.set('I-ABC123XYZ', sub({ status: 'SUSPENDED', status_update_time: '2026-11-01T00:00:00Z' }));
  assert.equal(((await handleWebhook(d, hdr(), hook('WH-2', 'BILLING.SUBSCRIPTION.SUSPENDED', { id: 'I-ABC123XYZ' }))).body as any).state, 'stale');
  assert.equal((await store.getSubscription(USER))!.status, 'active');

  subs.set('I-OTHERPLAN1', sub({ id: 'I-OTHERPLAN1', plan_id: 'P-NOT-OURS' }));
  assert.equal(((await handleWebhook(d, hdr(), hook('WH-3', 'BILLING.SUBSCRIPTION.ACTIVATED', { id: 'I-OTHERPLAN1' }))).body as any).state, 'pending');
  assert.equal(((await handleWebhook(d, hdr(), hook('WH-4', 'CHECKOUT.ORDER.APPROVED', { id: 'X' }))).body as any).ignored, true);
  subs.set('I-NOCUSTOM12', sub({ id: 'I-NOCUSTOM12', custom_id: undefined }));
  assert.equal(((await handleWebhook(d, hdr(), hook('WH-5', 'BILLING.SUBSCRIPTION.ACTIVATED', { id: 'I-NOCUSTOM12' }))).body as any).ignored, true);
  assert.equal((await handleWebhook(d, hdr(), hook('WH-6', 'BILLING.SUBSCRIPTION.ACTIVATED', { id: 'I-MISSING123' }))).status, 502);
});

test('mapSubscription period rules', () => {
  const m = mapSubscription(sub({ plan_id: PLANS.pro_yearly.paypalPlanId, billing_info: { last_payment: { time: '2026-11-01T00:00:00Z' } } }), NOW)!;
  assert.equal(m.interval, 'yearly');
  assert.equal(m.periodEnd, new Date(Date.parse('2026-11-01T00:00:00Z') + 366 * 86400000 + 2 * 86400000).toISOString());
  assert.equal(mapSubscription(sub({ status: 'APPROVED' }), NOW), null);
  assert.equal(mapSubscription(sub({ plan_id: 'P-X' }), NOW), null);
});
