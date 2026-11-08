import { validateEndpointUrl, validateEndpointWithDns, type Resolver } from './ssrf.ts';

/**
 * Finds a service's OAuth token endpoint from its MCP server URL, so users never have to look it up.
 * Follows the standard discovery chain: protected-resource metadata -> authorization-server metadata -> token_endpoint.
 * Every request is SSRF-checked, no redirects, short timeout. Returns null when nothing usable is found.
 */
export async function discoverTokenEndpoint(serverUrl: string, d: { fetch: typeof fetch; resolve?: Resolver }): Promise<string | null> {
  let server: URL;
  try { server = new URL(serverUrl); } catch { return null; }

  const getJson = async (url: string): Promise<any | null> => {
    try {
      const safe = await validateEndpointWithDns(url, d.resolve);
      const r = await d.fetch(safe.toString(), { redirect: 'manual', headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
      if (!r.ok) return null;
      const text = await r.text();
      return text.length < 200_000 ? JSON.parse(text) : null;
    } catch { return null; }
  };

  const path = server.pathname === '/' ? '' : server.pathname.replace(/\/$/, '');
  const prm = (await getJson(`${server.origin}/.well-known/oauth-protected-resource${path}`))
    ?? (await getJson(`${server.origin}/.well-known/oauth-protected-resource`));
  const issuers: string[] = [];
  if (prm && Array.isArray(prm.authorization_servers)) for (const s of prm.authorization_servers) if (typeof s === 'string') issuers.push(s);
  issuers.push(server.origin); // many servers host their own authorization server

  for (const iss of issuers.slice(0, 3)) {
    let base: URL;
    try { base = new URL(iss); } catch { continue; }
    const p = base.pathname === '/' ? '' : base.pathname.replace(/\/$/, '');
    const candidates = [
      `${base.origin}/.well-known/oauth-authorization-server${p}`,
      `${base.origin}/.well-known/openid-configuration${p}`,
      ...(p ? [`${base.origin}/.well-known/oauth-authorization-server`, `${base.origin}${p}/.well-known/openid-configuration`] : []),
    ];
    for (const c of candidates) {
      const meta = await getJson(c);
      const te = meta && typeof meta.token_endpoint === 'string' ? meta.token_endpoint : null;
      if (!te) continue;
      try { validateEndpointUrl(te); return te; } catch { /* unusable, keep looking */ }
    }
  }
  return null;
}
