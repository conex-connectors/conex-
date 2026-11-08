import { handle, type HandlerDeps } from './handler.ts';
import { handleApi, type ApiDeps } from './api.ts';
import { confirmSubscription, handleWebhook, type BillingDeps } from './billing.ts';
import { consentPage, payPage } from './pages.ts';
import { ABOUT, PRIVACY, docHtml } from './legal.ts';
import { isPlanKey } from './plans.ts';
import { verifySession } from './session.ts';
import { browseProxy, type BrowseCfg } from './browse.ts';

export interface RouterDeps {
  mcp: HandlerDeps; api: ApiDeps; billing: BillingDeps | null;
  paypalClientId: string; supabaseUrl: string; publishableKey: string; browse: BrowseCfg;
}

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra } });
const html = (s: string) => new Response(s, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=300', 'x-content-type-options': 'nosniff' } });

/** Supabase OAuth access tokens issued to agents carry a client_id claim. Agents may use /mcp but never the account API. */
export function isAgentToken(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload && typeof payload === 'object' && 'client_id' in payload;
  } catch { return false; }
}

export async function route(req: Request, d: RouterDeps): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname;

  if (req.method === 'GET') {
    if (p === '/oauth/consent') return consentPage({ supabaseUrl: d.supabaseUrl, publishableKey: d.publishableKey });
    if (p === '/privacy') return html(docHtml(PRIVACY));
    if (p === '/about') return html(docHtml(ABOUT));
    if (p === '/legal/privacy.json') return json(PRIVACY);
    if (p === '/legal/about.json') return json(ABOUT);
    if (p === '/pay') {
      if (!d.billing) return json({ error: 'billing_unavailable' }, 503);
      const s = await verifySession(d.billing.sessionKey, url.searchParams.get('s') ?? '', (d.billing.now ?? Date.now)());
      if (!s || !isPlanKey(s.p)) return new Response('This payment link has expired. Go back to Conex and try again.', { status: 410, headers: { 'content-type': 'text/plain; charset=utf-8' } });
      return payPage({ clientId: d.paypalClientId, planKey: s.p, userId: s.u, session: url.searchParams.get('s')! });
    }
  }

  if (p === '/api/billing/confirm' && req.method === 'POST') {
    if (!d.billing) return json({ error: 'billing_unavailable' }, 503);
    const text = await req.text();
    let b: { s?: unknown; subscriptionID?: unknown } = {};
    try { b = text.length < 4000 ? JSON.parse(text) : {}; } catch { /* invalid */ }
    const r = await confirmSubscription(d.billing, typeof b.s === 'string' ? b.s : '', b.subscriptionID);
    return json(r.body, r.status);
  }

  if (p === '/webhooks/paypal' && req.method === 'POST') {
    if (!d.billing) return json({ error: 'billing_unavailable' }, 503);
    const r = await handleWebhook(d.billing, req.headers, await req.text());
    return json(r.body, r.status);
  }

  if (p.startsWith('/api/')) {
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
    const principal = m ? await d.mcp.auth.authenticate(m[1]) : null;
    if (!principal) return json({ error: 'unauthorized' }, 401);
    if (isAgentToken(m![1])) return json({ error: 'forbidden', message: 'Agents cannot use the account API.' }, 403);
    if (p === '/api/browse/connectors' && req.method === 'GET') return browseProxy(principal.userId, 'GET', 'connectors', url.search, null, d.browse);
    if (p === '/api/browse/connect' && req.method === 'POST') {
      const text = await req.text();
      return browseProxy(principal.userId, 'POST', 'connect', '', text.length < 20_000 ? text : null, d.browse);
    }
    return handleApi(req, url, principal.userId, d.api);
  }

  return handle(req, d.mcp);
}
