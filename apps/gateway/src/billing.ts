import { PLANS, planByPaypalId, isPlanKey, type PlanKey } from './plans.ts';
import { PayPalError, SUB_ID, type PayPal, type PpSubscription } from './paypal.ts';
import { signSession, verifySession } from './session.ts';
import type { ApplySubscriptionArgs, BillingStore } from './types.ts';

export interface BillingDeps { paypal: PayPal; store: BillingStore; sessionKey: CryptoKey; now?: () => number }

const GRACE_MS = 2 * 24 * 3600 * 1000; // PayPal can bill a little late
const SPAN_MS = { monthly: 31 * 24 * 3600 * 1000, yearly: 366 * 24 * 3600 * 1000 };

export async function startCheckout(d: BillingDeps, userId: string, planKey: unknown, origin: string): Promise<{ url: string } | null> {
  if (!isPlanKey(planKey)) return null;
  const exp = (d.now ?? Date.now)() + 15 * 60 * 1000;
  const token = await signSession(d.sessionKey, { u: userId, p: planKey, exp });
  return { url: `${origin}/pay?s=${encodeURIComponent(token)}` };
}

/** Maps a PayPal subscription (read from PayPal) to the state Conex stores. null = nothing to record yet. */
export function mapSubscription(sub: PpSubscription, now: number): Omit<ApplySubscriptionArgs, 'userId' | 'eventId' | 'eventType'> | null {
  const plan = planByPaypalId(sub.plan_id);
  if (!plan) return null;
  const st = String(sub.status).toUpperCase();
  const status = st === 'ACTIVE' ? 'active' : st === 'SUSPENDED' ? 'past_due' : st === 'CANCELLED' ? 'cancelled' : st === 'EXPIRED' ? 'expired' : null;
  if (!status) return null; // APPROVAL_PENDING / APPROVED: not paid yet
  let periodEnd: string | null = null;
  if (status === 'active') {
    const next = sub.billing_info?.next_billing_time ? Date.parse(sub.billing_info.next_billing_time) : NaN;
    const last = sub.billing_info?.last_payment?.time ? Date.parse(sub.billing_info.last_payment.time) : NaN;
    const base = Number.isFinite(next) ? next : Number.isFinite(last) ? last + SPAN_MS[plan.interval] : now + SPAN_MS[plan.interval];
    periodEnd = new Date(Math.max(base, now) + GRACE_MS).toISOString();
  }
  return { plan: plan.plan, interval: plan.interval, subscriptionId: sub.id, paypalPlanId: sub.plan_id, status, periodEnd, eventTime: sub.status_update_time ?? null };
}

/** Records a verified subscription state; cancels the user's previous subscription when they switch plans. */
export async function syncSubscription(d: BillingDeps, userId: string, sub: PpSubscription, eventId: string, eventType: string) {
  const now = (d.now ?? Date.now)();
  const mapped = mapSubscription(sub, now);
  if (!mapped) return { state: 'pending' as const };
  const before = await d.store.getSubscription(userId);
  const result = await d.store.applySubscription({ userId, eventId, eventType, ...mapped });
  if (result === 'applied' && mapped.status === 'active' && before?.providerSubscriptionId && before.providerSubscriptionId !== sub.id
      && ['active', 'past_due'].includes(before.status)) {
    await d.paypal.cancel(before.providerSubscriptionId, 'Replaced by a new Conex plan').catch(() => false);
  }
  return { state: result };
}

/** Called by the pay page after PayPal approval. The page's word is never trusted: PayPal is asked directly. */
export async function confirmSubscription(d: BillingDeps, token: string, subscriptionId: unknown) {
  const s = await verifySession(d.sessionKey, token, (d.now ?? Date.now)());
  if (!s || !isPlanKey(s.p)) return { status: 401 as const, body: { error: 'invalid_session' } };
  if (typeof subscriptionId !== 'string' || !SUB_ID.test(subscriptionId)) return { status: 400 as const, body: { error: 'invalid_subscription' } };
  let sub: PpSubscription;
  try { sub = await d.paypal.getSubscription(subscriptionId); }
  catch (e) { return { status: e instanceof PayPalError && e.message === 'subscription_not_found' ? 404 as const : 502 as const, body: { error: 'paypal_lookup_failed' } }; }
  const plan = PLANS[s.p as PlanKey];
  if (sub.custom_id !== s.u) return { status: 403 as const, body: { error: 'subscription_not_yours' } };
  if (sub.plan_id !== plan.paypalPlanId) return { status: 409 as const, body: { error: 'plan_mismatch' } };
  const r = await syncSubscription(d, s.u, sub, `confirm:${sub.id}:${sub.status_update_time ?? sub.status}`, 'CONFIRM');
  return { status: 200 as const, body: { state: r.state === 'pending' ? 'pending' : 'active' } };
}

const HANDLED = /^(BILLING\.SUBSCRIPTION\.(ACTIVATED|CANCELLED|SUSPENDED|EXPIRED|RE-ACTIVATED|PAYMENT\.FAILED|UPDATED)|PAYMENT\.SALE\.COMPLETED)$/;

export async function handleWebhook(d: BillingDeps, headers: Headers, body: string): Promise<{ status: number; body: unknown }> {
  if (body.length > 200_000) return { status: 413, body: { error: 'too_large' } };
  let valid = false;
  try { valid = await d.paypal.verifyWebhook(headers, body); } catch { return { status: 502, body: { error: 'verify_unavailable' } }; }
  if (!valid) return { status: 400, body: { error: 'invalid_signature' } };
  const ev = JSON.parse(body) as { id?: string; event_type?: string; resource?: { id?: string; billing_agreement_id?: string } };
  if (!ev.id || !ev.event_type || !HANDLED.test(ev.event_type)) return { status: 200, body: { ignored: true } };
  const subId = ev.event_type === 'PAYMENT.SALE.COMPLETED' ? ev.resource?.billing_agreement_id : ev.resource?.id;
  if (!subId || !SUB_ID.test(subId)) return { status: 200, body: { ignored: true } };
  let sub: PpSubscription;
  try { sub = await d.paypal.getSubscription(subId); } catch { return { status: 502, body: { error: 'lookup_failed' } }; } // PayPal retries
  const userId = sub.custom_id;
  if (!userId || !/^[0-9a-f-]{36}$/i.test(userId)) return { status: 200, body: { ignored: true } };
  try {
    const r = await syncSubscription(d, userId, sub, ev.id, ev.event_type);
    return { status: 200, body: { state: r.state } };
  } catch { return { status: 500, body: { error: 'apply_failed' } }; } // PayPal retries
}
