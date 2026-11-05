import type { Authenticator, Principal } from './types.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Validates a Supabase Auth access token (including OAuth tokens issued to agents) by asking Supabase who it belongs to. */
export function supabaseAuthenticator(cfg: { url: string; publishableKey: string; fetch: typeof fetch; ttlMs?: number; now?: () => number }): Authenticator {
  const cache = new Map<string, { principal: Principal; until: number }>();
  const ttl = cfg.ttlMs ?? 60_000;
  const now = cfg.now ?? Date.now;
  return {
    async authenticate(token: string): Promise<Principal | null> {
      if (!token || token.length > 4096) return null;
      const hit = cache.get(token);
      if (hit && hit.until > now()) return hit.principal;
      let res: Response;
      try {
        res = await cfg.fetch(`${cfg.url}/auth/v1/user`, {
          headers: { apikey: cfg.publishableKey, authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(8000),
        });
      } catch { return null; }
      if (!res.ok) { cache.delete(token); return null; }
      const body = (await res.json().catch(() => null)) as { id?: unknown } | null;
      if (!body || typeof body.id !== 'string' || !UUID.test(body.id)) return null;
      const principal = { userId: body.id };
      if (cache.size > 500) cache.clear();
      cache.set(token, { principal, until: now() + ttl });
      return principal;
    },
  };
}
