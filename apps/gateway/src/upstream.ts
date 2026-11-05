import { validateEndpointWithDns, type Resolver, dohResolver } from './ssrf.ts';
import { buildAuthHeaders } from './credentials.ts';
import type { Connector, SecretResolver } from './types.ts';

export interface UpstreamDeps {
  fetch: typeof fetch;
  secrets: SecretResolver;
  resolve?: Resolver;
  timeoutMs?: number;
  maxBytes?: number;
}
export class UpstreamError extends Error {
  constructor(message: string) { super(message); this.name = 'UpstreamError'; }
}

const PROTOCOL = '2025-06-18';

async function readCapped(res: Response, max: number): Promise<string> {
  const text = await res.text();
  if (text.length > max) throw new UpstreamError('Upstream response too large');
  return text;
}

function extractRpc(text: string, contentType: string, id: number): any {
  if (contentType.includes('text/event-stream')) {
    for (const block of text.split(/\n\n/)) {
      const data = block.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trimStart()).join('\n');
      if (!data) continue;
      try { const m = JSON.parse(data); if (m && m.id === id) return m; } catch { /* skip */ }
    }
    throw new UpstreamError('No matching response in upstream event stream');
  }
  try { return JSON.parse(text); } catch { throw new UpstreamError('Upstream returned invalid JSON'); }
}

/** Stateless upstream call: initialize -> initialized -> request. Never echoes credentials. */
export async function upstreamCall(c: Connector, method: string, params: object | undefined, d: UpstreamDeps): Promise<any> {
  const url = await validateEndpointWithDns(c.endpointUrl, d.resolve ?? dohResolver);
  const secret = c.credentialRef ? await d.secrets.get(c.credentialRef) : null;
  if (c.credentialRef && !secret) throw new UpstreamError('Connector credential unavailable');
  let authHeaders: Record<string, string>;
  try { authHeaders = await buildAuthHeaders(c, secret, { fetch: d.fetch, resolve: d.resolve }); }
  catch (e) { throw new UpstreamError(e instanceof Error ? e.message : 'Connector credential unavailable'); }
  const timeout = d.timeoutMs ?? 15_000;
  const max = d.maxBytes ?? 2_000_000;
  let session: string | null = null;

  const send = async (body: object, id: number | null) => {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': PROTOCOL,
    };
    Object.assign(headers, authHeaders);
    if (session) headers['mcp-session-id'] = session;
    let res: Response;
    try {
      res = await d.fetch(url.toString(), {
        method: 'POST', headers, body: JSON.stringify(body),
        redirect: 'manual', signal: AbortSignal.timeout(timeout),
      });
    } catch {
      throw new UpstreamError('Upstream unreachable or timed out');
    }
    if (res.status >= 300 && res.status < 400) throw new UpstreamError('Upstream redirect refused');
    if (res.status === 401 || res.status === 403) throw new UpstreamError('Upstream rejected credentials');
    if (!res.ok && id !== null) throw new UpstreamError(`Upstream error ${res.status}`);
    session = res.headers.get('mcp-session-id') ?? session;
    if (id === null) { await res.body?.cancel(); return null; }
    return extractRpc(await readCapped(res, max), res.headers.get('content-type') ?? '', id);
  };

  const init = await send({
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: { name: 'conex-gateway', version: '0.1.0' } },
  }, 1);
  if (init?.error) throw new UpstreamError('Upstream initialize failed');
  await send({ jsonrpc: '2.0', method: 'notifications/initialized' }, null);
  const out = await send({ jsonrpc: '2.0', id: 2, method, ...(params ? { params } : {}) }, 2);
  return out;
}
