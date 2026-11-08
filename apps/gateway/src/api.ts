import { encryptSecret } from './crypto.ts';
import { CredentialError, clearTokenCache, fetchClientCredentialsToken } from './credentials.ts';
import { SsrfError, validateEndpointUrl, validateEndpointWithDns } from './ssrf.ts';
import { upstreamCall, type UpstreamDeps } from './upstream.ts';
import { LIMITS, StoreError, entitled } from './types.ts';
import type { AdminStore, AuthMethod, BillingStore, Connector, ConnectorStore, SecretResolver } from './types.ts';
import { isPlanKey } from './plans.ts';
import { discoverTokenEndpoint } from './discovery.ts';
import { startCheckout, syncSubscription, type BillingDeps } from './billing.ts';

export interface ApiDeps extends UpstreamDeps {
  store: ConnectorStore & AdminStore & BillingStore;
  encKey: CryptoKey;
  billing: BillingDeps | null;
  deleteUser: (userId: string) => Promise<boolean>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const err = (status: number, error: string, message?: string) => json({ error, ...(message ? { message } : {}) }, status);
const str = (v: unknown, max: number): string | null => (typeof v === 'string' && v.trim().length > 0 && v.length <= max ? v.trim() : null);

async function readJson(req: Request): Promise<Record<string, unknown> | null> {
  const text = await req.text();
  if (text.length > 20_000) return null;
  try { const v = JSON.parse(text); return v && typeof v === 'object' && !Array.isArray(v) ? v : null; } catch { return null; }
}

/** Checks a candidate connection by really talking to it. Returns the number of tools it exposes. */
export async function verifyConnection(c: Connector, secret: string | null, d: UpstreamDeps): Promise<{ ok: true; tools: number } | { ok: false; message: string }> {
  const resolver: SecretResolver = { get: async () => secret };
  try {
    const r = await upstreamCall({ ...c, credentialRef: secret === null ? null : 'candidate' }, 'tools/list', undefined, { ...d, secrets: resolver });
    if (r?.error || !r?.result) return { ok: false, message: 'The server did not answer like an MCP server.' };
    return { ok: true, tools: Array.isArray(r.result.tools) ? r.result.tools.length : 0 };
  } catch (e) {
    if (e instanceof SsrfError) return { ok: false, message: 'That address is not allowed. Use a public https address.' };
    return { ok: false, message: e instanceof Error ? e.message : 'Could not connect.' };
  }
}

export async function handleApi(req: Request, url: URL, userId: string, d: ApiDeps): Promise<Response> {
  const path = url.pathname;
  const m = req.method;

  if (path === '/api/me' && m === 'GET') {
    const s = await d.store.getSubscription(userId);
    const active = entitled(s);
    return json({
      plan: active ? s!.plan : 'none', status: s?.status ?? 'inactive', billingInterval: s?.billingInterval ?? null,
      periodEnd: s?.periodEnd ?? null, active, limits: active ? LIMITS[s!.plan] : { connectors: 0, calls: 0 },
    });
  }

  if (path === '/api/billing/checkout' && m === 'POST') {
    if (!d.billing) return err(503, 'billing_unavailable');
    const b = await readJson(req);
    if (!b || !isPlanKey(b.plan)) return err(400, 'invalid_plan');
    const r = await startCheckout(d.billing, userId, b.plan, url.origin);
    return r ? json(r) : err(400, 'invalid_plan');
  }

  if (path === '/api/billing/cancel' && m === 'POST') {
    if (!d.billing) return err(503, 'billing_unavailable');
    const s = await d.store.getSubscription(userId);
    if (!s?.providerSubscriptionId || !['active', 'past_due'].includes(s.status)) return err(409, 'no_active_subscription');
    if (!(await d.billing.paypal.cancel(s.providerSubscriptionId, 'Cancelled by user in Conex'))) return err(502, 'paypal_unavailable');
    const sub = await d.billing.paypal.getSubscription(s.providerSubscriptionId).catch(() => null);
    if (sub) await syncSubscription(d.billing, userId, sub, `cancel:${sub.id}:${Date.now()}`, 'USER_CANCEL');
    return json({ ok: true });
  }

  if (path === '/api/account/delete' && m === 'POST') {
    const b = await readJson(req);
    if (!b || b.confirm !== 'DELETE') return err(400, 'confirmation_required');
    const s = await d.store.getSubscription(userId);
    if (d.billing && s?.providerSubscriptionId && ['active', 'past_due'].includes(s.status)) {
      await d.billing.paypal.cancel(s.providerSubscriptionId, 'Account deleted').catch(() => false);
    }
    return (await d.deleteUser(userId)) ? new Response(null, { status: 204 }) : err(502, 'delete_failed');
  }

  if (path === '/api/token-generator' && m === 'POST') {
    if (!entitled(await d.store.getSubscription(userId))) return err(402, 'plan_required', 'An active plan is required.');
    const b = await readJson(req);
    const tokenUrl = b && str(b.tokenUrl, 2048), clientId = b && str(b.clientId, 512), clientSecret = b && str(b.clientSecret, 4096);
    if (!b || !tokenUrl || !clientId || !clientSecret) return err(400, 'invalid_input', 'Token URL, client ID and client secret are required.');
    try {
      const t = await fetchClientCredentialsToken(tokenUrl, clientId, clientSecret, str(b.scope, 512) ?? undefined, d);
      return json({ accessToken: t.accessToken, expiresIn: t.expiresIn, tokenType: 'Bearer' });
    } catch (e) {
      if (e instanceof SsrfError) return err(422, 'url_not_allowed', 'That address is not allowed. Use a public https address.');
      return err(422, 'token_failed', e instanceof CredentialError ? e.message : 'Could not generate a token.');
    }
  }

  if (path === '/api/connectors' && m === 'POST') {
    const b = await readJson(req);
    if (!b) return err(400, 'invalid_input');
    const kind = b.kind;
    const name = str(b.name, 40);
    const endpoint = str(b.url, 2048);
    if (!name || !endpoint || (kind !== 'bearer' && kind !== 'supabase' && kind !== 'client_credentials')) return err(400, 'invalid_input', 'Name and server URL are required.');
    try { validateEndpointUrl(endpoint); } catch (e) { return err(422, 'url_not_allowed', e instanceof SsrfError ? e.message : 'Invalid URL.'); }
    if (!entitled(await d.store.getSubscription(userId))) return err(402, 'plan_required', 'Choose a plan to add connectors.');

    const id = crypto.randomUUID();
    let secret: string; let authMethod: AuthMethod; let tokenUrl: string | null = null; let autoRefresh = false;
    if (kind === 'bearer') {
      const token = str(b.token, 4096);
      if (!token) return err(400, 'invalid_input', 'A token or API key is required.');
      secret = token; authMethod = 'bearer';
    } else if (kind === 'supabase') {
      const supabaseUrl = str(b.supabaseUrl, 2048), anonKey = str(b.anonKey, 4096), serviceKey = str(b.serviceKey, 4096);
      if (!supabaseUrl || !anonKey || !serviceKey) return err(400, 'invalid_input', 'Supabase URL, anon key and service role key are required.');
      try { validateEndpointUrl(supabaseUrl); } catch { return err(422, 'url_not_allowed', 'Supabase URL must be a public https address.'); }
      secret = JSON.stringify({ kind: 'supabase', serviceKey, anonKey, supabaseUrl }); authMethod = 'supabase';
    } else {
      const clientId = str(b.clientId, 512), clientSecret = str(b.clientSecret, 4096);
      if (!clientId || !clientSecret) return err(400, 'invalid_input', 'Client ID and client secret are required.');
      // The user never has to know the token URL: it is discovered from the server URL. An explicit one still wins.
      let tu = str(b.tokenUrl, 2048);
      if (!tu) {
        tu = await discoverTokenEndpoint(endpoint, d);
        if (!tu) return err(422, 'token_url_needed', 'We could not find this service\'s sign-in address automatically. Enter its token URL to continue.');
      }
      try { await validateEndpointWithDns(tu, d.resolve); } catch { return err(422, 'url_not_allowed', 'Token URL must be a public https address.'); }
      tokenUrl = tu; authMethod = 'client_credentials'; autoRefresh = b.autoRefresh === true;
      const scope = str(b.scope, 512) ?? undefined;
      if (autoRefresh) secret = JSON.stringify({ mode: 'refresh', clientId, clientSecret, scope });
      else {
        try {
          const t = await fetchClientCredentialsToken(tu, clientId, clientSecret, scope, d);
          secret = JSON.stringify({ mode: 'static', accessToken: t.accessToken, expiresAt: Date.now() + t.expiresIn * 1000 });
        } catch (e) { return err(422, 'token_failed', e instanceof CredentialError ? e.message : 'Could not get a token.'); }
      }
    }

    const candidate: Connector = { id, userId, name, endpointUrl: endpoint, credentialRef: id, authMethod, tokenUrl, autoRefresh };
    const v = await verifyConnection(candidate, secret, d);
    clearTokenCache(id);
    if (!v.ok) return err(422, 'verify_failed', v.message);

    try {
      await d.store.createConnector({ id, userId, name, endpointUrl: endpoint, authMethod, tokenUrl, autoRefresh }, await encryptSecret(d.encKey, secret, id));
    } catch (e) {
      if (e instanceof StoreError && e.code === 'plan_required') return err(402, 'plan_required', 'Choose a plan to add connectors.');
      if (e instanceof StoreError && e.code === 'connector_limit_reached') return err(409, 'connector_limit_reached', 'You have reached your connector limit. Upgrade your plan for more.');
      return err(500, 'save_failed');
    }
    return json({ id, status: 'connected', tools: v.tools }, 201);
  }

  const cm = /^\/api\/connectors\/([^/]+)(?:\/(connect|disconnect))?$/.exec(path);
  if (cm) {
    const [, cid, action] = cm;
    if (!UUID.test(cid)) return err(404, 'not_found');
    if (m === 'DELETE' && !action) {
      return (await d.store.deleteConnector(userId, cid)) === 'deleted' ? new Response(null, { status: 204 }) : err(404, 'not_found');
    }
    if (m === 'POST' && action === 'disconnect') {
      return (await d.store.setConnectorStatus(userId, cid, 'disabled')) ? json({ status: 'disabled' }) : err(404, 'not_found');
    }
    if (m === 'POST' && action === 'connect') {
      const c = await d.store.getConnector(userId, cid);
      if (!c) return err(404, 'not_found');
      const secret = c.credentialRef ? await d.secrets.get(c.credentialRef) : null;
      if (c.credentialRef && secret === null) { await d.store.setConnectorStatus(userId, cid, 'error'); return err(422, 'verify_failed', 'The saved credential could not be read. Delete and add this connector again.'); }
      clearTokenCache(cid);
      const v = await verifyConnection(c, secret, d);
      if (!v.ok) { await d.store.setConnectorStatus(userId, cid, 'error'); return err(422, 'verify_failed', v.message); }
      await d.store.setConnectorStatus(userId, cid, 'connected');
      return json({ status: 'connected', tools: v.tools });
    }
  }
  return err(404, 'not_found');
}
