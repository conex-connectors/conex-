import { validateEndpointWithDns, dohResolver, type Resolver } from './ssrf.ts';
import type { Connector } from './types.ts';

export class CredentialError extends Error {
  constructor(message: string) { super(message); this.name = 'CredentialError'; }
}

export interface TokenResult { accessToken: string; expiresIn: number }

/** OAuth client-credentials exchange against a user-supplied token URL (SSRF-checked, no redirects). */
export async function fetchClientCredentialsToken(
  tokenUrl: string, clientId: string, clientSecret: string, scope: string | undefined,
  d: { fetch: typeof fetch; resolve?: Resolver },
): Promise<TokenResult> {
  const url = await validateEndpointWithDns(tokenUrl, d.resolve ?? dohResolver);
  const form = (withCreds: boolean) => {
    const p = new URLSearchParams({ grant_type: 'client_credentials' });
    if (scope) p.set('scope', scope);
    if (withCreds) { p.set('client_id', clientId); p.set('client_secret', clientSecret); }
    return p.toString();
  };
  const attempt = async (basic: boolean) => d.fetch(url.toString(), {
    method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(10_000),
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...(basic ? { authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}` } : {}) },
    body: form(!basic),
  });
  let res: Response;
  try {
    res = await attempt(true);
    if (res.status === 400 || res.status === 401) res = await attempt(false);
  } catch { throw new CredentialError('Token server unreachable or timed out'); }
  if (res.status >= 300 && res.status < 400) throw new CredentialError('Token server redirect refused');
  if (!res.ok) throw new CredentialError('Token server rejected the credentials');
  const j = (await res.json().catch(() => null)) as { access_token?: unknown; expires_in?: unknown } | null;
  if (!j || typeof j.access_token !== 'string' || !j.access_token) throw new CredentialError('Token server returned no access token');
  const exp = typeof j.expires_in === 'number' && j.expires_in > 0 ? j.expires_in : 3600;
  return { accessToken: j.access_token, expiresIn: exp };
}

type Stored =
  | { mode: 'refresh'; clientId: string; clientSecret: string; scope?: string }
  | { mode: 'static'; accessToken: string; expiresAt: number }
  | { kind: 'supabase'; serviceKey: string; anonKey: string; supabaseUrl: string };

const tokenCache = new Map<string, { token: string; until: number }>();

/** Turns a connector + its decrypted secret into the headers sent upstream. Never logs or returns the secret. */
export async function buildAuthHeaders(
  c: Connector, secret: string | null,
  d: { fetch: typeof fetch; resolve?: Resolver; now?: () => number },
): Promise<Record<string, string>> {
  if (!secret) return {};
  const now = (d.now ?? Date.now)();
  const method = c.authMethod ?? 'bearer';
  if (method === 'bearer' || method === 'token_generator' || method === 'oauth_browse') return { authorization: `Bearer ${secret}` };

  let s: Stored;
  try { s = JSON.parse(secret) as Stored; } catch { throw new CredentialError('Stored credential is unreadable'); }

  if (method === 'supabase' && 'kind' in s && s.kind === 'supabase') {
    return { authorization: `Bearer ${s.serviceKey}`, apikey: s.anonKey, 'x-supabase-url': s.supabaseUrl };
  }
  if (method === 'client_credentials' && 'mode' in s) {
    if (s.mode === 'static') {
      if (s.expiresAt <= now) throw new CredentialError('Access token expired. Reconnect to get a new one.');
      return { authorization: `Bearer ${s.accessToken}` };
    }
    const cached = tokenCache.get(c.id);
    if (cached && cached.until > now) return { authorization: `Bearer ${cached.token}` };
    if (!c.tokenUrl) throw new CredentialError('Connector has no token URL');
    const t = await fetchClientCredentialsToken(c.tokenUrl, s.clientId, s.clientSecret, s.scope, d);
    tokenCache.set(c.id, { token: t.accessToken, until: now + Math.max(30, t.expiresIn - 30) * 1000 });
    return { authorization: `Bearer ${t.accessToken}` };
  }
  throw new CredentialError('Stored credential does not match the connection type');
}

export function clearTokenCache(connectorId: string): void { tokenCache.delete(connectorId); }
