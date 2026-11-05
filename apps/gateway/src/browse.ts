import { SsrfError, validateEndpointWithDns, type Resolver } from './ssrf.ts';

/**
 * The "Browse connectors" box. Your connector-directory API plugs in here without touching the app:
 *   GET  /api/browse/connectors?...   -> forwarded to  {BROWSE_API_URL}/connectors?...
 *   POST /api/browse/connect          -> forwarded to  {BROWSE_API_URL}/connect  (body forwarded)
 * Requests carry  Authorization: Bearer {BROWSE_API_KEY}  and  x-conex-user: <user id>.
 * Responses are passed through as JSON (size-capped). Until configured, the app shows "coming soon".
 */
export interface BrowseCfg { baseUrl: string | undefined; apiKey: string | undefined; fetch: typeof fetch; resolve?: Resolver }

export async function browseProxy(userId: string, method: string, sub: 'connectors' | 'connect', search: string, body: string | null, cfg: BrowseCfg): Promise<Response> {
  const out = (b: unknown, status: number) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  if (!cfg.baseUrl) return out({ error: 'browse_not_configured' }, 503);
  let base: URL;
  try { base = await validateEndpointWithDns(cfg.baseUrl, cfg.resolve); }
  catch (e) { return out({ error: e instanceof SsrfError ? 'browse_misconfigured' : 'browse_unavailable' }, 503); }
  const target = `${base.toString().replace(/\/$/, '')}/${sub}${sub === 'connectors' ? search.slice(0, 512) : ''}`;
  let res: Response;
  try {
    res = await cfg.fetch(target, {
      method, redirect: 'manual', signal: AbortSignal.timeout(10_000),
      headers: { 'content-type': 'application/json', accept: 'application/json', 'x-conex-user': userId, ...(cfg.apiKey ? { authorization: `Bearer ${cfg.apiKey}` } : {}) },
      body: method === 'POST' ? body ?? '{}' : undefined,
    });
  } catch { return out({ error: 'browse_unavailable' }, 502); }
  if (res.status >= 300 && res.status < 400) return out({ error: 'browse_unavailable' }, 502);
  const text = await res.text();
  if (text.length > 1_000_000) return out({ error: 'browse_unavailable' }, 502);
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return out({ error: 'browse_unavailable' }, 502); }
  return out(parsed, res.ok ? 200 : res.status === 404 ? 404 : 502);
}
