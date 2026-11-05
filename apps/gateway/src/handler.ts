import { parseRpc, ok, fail, RpcError, MAX_BODY_BYTES } from './jsonrpc.ts';
import { upstreamCall, type UpstreamDeps } from './upstream.ts';
import { SsrfError } from './ssrf.ts';
import { PlanRequiredError } from './types.ts';
import type { Authenticator, Connector, ConnectorStore } from './types.ts';

export interface HandlerDeps extends UpstreamDeps {
  store: ConnectorStore;
  auth: Authenticator;
  authServerUrl: string; // e.g. https://<ref>.supabase.co/auth/v1
  allowedOrigins: string[];
}

const slugBase = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'connector';
export const slugFor = (c: Connector, all: Connector[]): string => {
  const base = slugBase(c.name);
  return all.some((o) => o.id !== c.id && slugBase(o.name) === base) ? `${base}-${c.id.slice(0, 6)}` : base;
};

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...extra } });

function corsHeaders(req: Request, allowed: string[]): Record<string, string> | null {
  const origin = req.headers.get('origin');
  if (!origin) return {}; // non-browser agent
  if (!allowed.includes(origin)) return null;
  return {
    'access-control-allow-origin': origin, vary: 'origin',
    'access-control-allow-headers': 'authorization, content-type, accept, mcp-session-id, mcp-protocol-version',
    'access-control-allow-methods': 'POST, OPTIONS',
  };
}

export async function handle(req: Request, d: HandlerDeps): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === '/health') return json({ ok: true });

  // MCP authorization discovery (RFC 9728): tells agents where to log in.
  if (url.pathname === '/.well-known/oauth-protected-resource' || url.pathname === '/.well-known/oauth-protected-resource/mcp') {
    return json({ resource: `${url.origin}/mcp`, authorization_servers: [d.authServerUrl], bearer_methods_supported: ['header'] });
  }
  if (url.pathname !== '/mcp') return json({ error: 'not_found' }, 404);

  const cors = corsHeaders(req, d.allowedOrigins);
  if (cors === null) return json({ error: 'origin_not_allowed' }, 403);
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { ...cors, allow: 'POST, OPTIONS' });

  const m = /^Bearer\s+(\S+)$/i.exec(req.headers.get('authorization') ?? '');
  const principal = m ? await d.auth.authenticate(m[1]) : null;
  if (!principal) {
    return json({ error: 'unauthorized' }, 401, {
      ...cors, 'www-authenticate': `Bearer resource_metadata="${url.origin}/.well-known/oauth-protected-resource"`,
    });
  }
  const userId = principal.userId;

  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) return json(fail(null, -32600, 'Request too large'), 413, cors);
  let rpc;
  try { rpc = parseRpc(raw); } catch (e) {
    if (e instanceof RpcError) return json(fail(null, e.code, e.message), 400, cors);
    throw e;
  }
  const reply = (body: unknown) => json(body, 200, cors);

  switch (rpc.method) {
    case 'notifications/initialized':
      return new Response(null, { status: 202, headers: cors });
    case 'ping':
      return reply(ok(rpc.id, {}));
    case 'initialize': {
      const ci = (rpc.params as any)?.clientInfo;
      const agent = typeof ci?.name === 'string' && ci.name.trim() ? ci.name.trim().slice(0, 80) : 'AI agent';
      await d.store.touchAgent(userId, agent);
      return reply(ok(rpc.id, {
        protocolVersion: '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'conex', version: '0.2.0' },
      }));
    }
  }

  // The connector list is read per request: the URL never changes, the tools behind it do.
  const connectors = await d.store.listConnectors(userId);

  if (rpc.method === 'tools/list') {
    const tools: unknown[] = [];
    for (const c of connectors) {
      const slug = slugFor(c, connectors);
      try {
        const r = await upstreamCall(c, 'tools/list', undefined, d);
        for (const t of r?.result?.tools ?? []) tools.push({ ...t, name: `${slug}__${t.name}` });
      } catch { /* one failing connector must not hide the others */ }
    }
    return reply(ok(rpc.id, { tools }));
  }

  // tools/call
  const full = (rpc.params as any)?.name;
  if (typeof full !== 'string' || !full.includes('__')) return reply(fail(rpc.id, -32602, 'Unknown tool'));
  const [slug, ...rest] = full.split('__');
  const tool = rest.join('__');
  const target = connectors.find((c) => slugFor(c, connectors) === slug);
  if (!target) return reply(fail(rpc.id, -32602, 'Unknown tool'));

  let eventId: number | null;
  try {
    eventId = await d.store.beginCall(userId, target.id, tool);
  } catch (e) {
    if (e instanceof PlanRequiredError) return reply(fail(rpc.id, -32001, 'An active Conex plan is required to use tools.'));
    throw e;
  }
  if (eventId === null) return reply(fail(rpc.id, -32002, 'Daily call limit reached for this tool. It resets at 00:00 UTC.'));

  try {
    const r = await upstreamCall(target, 'tools/call', { name: tool, arguments: (rpc.params as any)?.arguments ?? {} }, d);
    await d.store.finishCall(eventId, r?.error ? 'error' : 'success');
    return reply(r?.error
      ? fail(rpc.id, r.error.code ?? -32603, String(r.error.message ?? 'Upstream error').slice(0, 300))
      : ok(rpc.id, r.result));
  } catch (e) {
    await d.store.finishCall(eventId, 'error');
    const msg = e instanceof SsrfError ? 'Connector endpoint is not allowed' : e instanceof Error ? e.message : 'Upstream error';
    return reply(fail(rpc.id, -32603, msg));
  }
}
