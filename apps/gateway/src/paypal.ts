export interface PayPalCfg {
  clientId: string; clientSecret: string; webhookId: string;
  env: 'live' | 'sandbox'; fetch: typeof fetch; now?: () => number;
}
export interface PpSubscription {
  id: string; plan_id: string; status: string; custom_id?: string; status_update_time?: string;
  billing_info?: { next_billing_time?: string; last_payment?: { time?: string } };
}
export class PayPalError extends Error {
  constructor(message: string) { super(message); this.name = 'PayPalError'; }
}
export const SUB_ID = /^I-[A-Z0-9]{6,40}$/;

export class PayPal {
  cfg: PayPalCfg;
  tokenCache: { token: string; until: number } | null = null;
  constructor(cfg: PayPalCfg) { this.cfg = cfg; }

  base(): string { return this.cfg.env === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com'; }
  now(): number { return (this.cfg.now ?? Date.now)(); }

  async token(): Promise<string> {
    if (this.tokenCache && this.tokenCache.until > this.now()) return this.tokenCache.token;
    const res = await this.cfg.fetch(`${this.base()}/v1/oauth2/token`, {
      method: 'POST',
      headers: { authorization: `Basic ${btoa(`${this.cfg.clientId}:${this.cfg.clientSecret}`)}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials', signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new PayPalError('paypal_auth_failed');
    const j = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!j.access_token) throw new PayPalError('paypal_auth_failed');
    this.tokenCache = { token: j.access_token, until: this.now() + Math.max(60, (j.expires_in ?? 300) - 60) * 1000 };
    return j.access_token;
  }

  async api(path: string, init: RequestInit = {}): Promise<Response> {
    return this.cfg.fetch(`${this.base()}${path}`, {
      ...init, signal: AbortSignal.timeout(10_000),
      headers: { authorization: `Bearer ${await this.token()}`, 'content-type': 'application/json', ...(init.headers as Record<string, string>) },
    });
  }

  /** Authoritative state of a subscription, read from PayPal itself. */
  async getSubscription(id: string): Promise<PpSubscription> {
    if (!SUB_ID.test(id)) throw new PayPalError('invalid_subscription_id');
    const res = await this.api(`/v1/billing/subscriptions/${id}`);
    if (res.status === 404) throw new PayPalError('subscription_not_found');
    if (!res.ok) throw new PayPalError('paypal_unavailable');
    return (await res.json()) as PpSubscription;
  }

  async cancel(id: string, reason: string): Promise<boolean> {
    if (!SUB_ID.test(id)) return false;
    const res = await this.api(`/v1/billing/subscriptions/${id}/cancel`, { method: 'POST', body: JSON.stringify({ reason: reason.slice(0, 120) }) });
    return res.ok || res.status === 422; // 422 = already cancelled
  }

  async verifyWebhook(headers: Headers, body: string): Promise<boolean> {
    const h = (n: string) => headers.get(n);
    const parts = { auth_algo: h('paypal-auth-algo'), cert_url: h('paypal-cert-url'), transmission_id: h('paypal-transmission-id'), transmission_sig: h('paypal-transmission-sig'), transmission_time: h('paypal-transmission-time') };
    if (Object.values(parts).some((v) => !v)) return false;
    let event: unknown;
    try { event = JSON.parse(body); } catch { return false; }
    const res = await this.api('/v1/notifications/verify-webhook-signature', {
      method: 'POST', body: JSON.stringify({ ...parts, webhook_id: this.cfg.webhookId, webhook_event: event }),
    });
    if (!res.ok) return false;
    return ((await res.json()) as { verification_status?: string }).verification_status === 'SUCCESS';
  }
}
