import { parseRpc, ok, fail, RpcError, MAX_BODY_BYTES } from './jsonrpc.ts';
import { upstreamCall, type UpstreamDeps } from './upstream.ts';
import { SsrfError } from './ssrf.ts';
import type { Connector, ConnectorStore } from './types.ts';

export interface HandlerDeps extends UpstreamDeps {
  store: ConnectorStore;
  allowedOrigins: string[];
}

export const slugFor = (c: Connector, all: Connector[]): string => {
  const base = c.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'connector';
  const clash = all.filter((o) => o.id !== c.id && (o.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'connector') === base);
  return clash.length ? `${base}-${c.id.slice(0, 6)}` : base;
};

const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...extra } });

function corsHeaders(req: Request, allowed: string[]): Record<string, string> | null {
  const origin = req.headers.get('origin');
  if (!origin) return {}; // non-browser agent
  if (!allowed.includes(origin)) return null;
  return {
    'access-control-allow-origin': origin, vary: 'origin',
    'access-control-allow-headers': 'content-type, accept, mcp-session-id, mcp-protocol-version',
    'access-control-allow-methods': 'POST, OPTIONS',
  };
}

export async function handle(req: Request, d: HandlerDeps): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === '/health') return json({ ok: true });
  const m = /^\/mcp\/(cx-[A-Za-z0-9_-]{8,64})$/.exec(url.pathname);
  if (!m) return json({ error: 'not_found' }, 404);

  const cors = corsHeaders(req, d.allowedOrigins);
  if (cors === null) return json({ error: 'origin_not_allowed' }, 403);
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { ...cors, allow: 'POST, OPTIONS' });

  const linker = await d.store.getLinker(m[1]);
  if (!linker || !linker.enabled) return json({ error: 'not_found' }, 404, cors);

  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) return json(fail(null, -32600, 'Request too large'), 413, cors);
  let rpc;
  try { rpc = parseRpc(raw); } catch (e) {
    if (e instanceof RpcError) return json(fail(null, e.code, e.message), 400, cors);
    throw e;
  }
  const reply = (body: unknown, extra: Record<string, string> = {}) => json(body, 200, { ...cors, ...extra });

  switch (rpc.method) {
    case 'notifications/initialized':
      return new Response(null, { status: 202, headers: cors });
    case 'ping':
      return reply(ok(rpc.id, {}));
    case 'initialize': {
      const ci = (rpc.params as any)?.clientInfo;
      const agent = typeof ci?.name === 'string' ? ci.name.slice(0, 80) : 'unknown-agent';
      await d.store.recordAgentConnection(linker.userId, agent);
      return reply(ok(rpc.id, {
        protocolVersion: '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'conex', version: '0.1.0' },
      }));
    }
  }

  // Resolve connector list at request time: the stable URL never changes, tools do.
  const connectors = await d.store.listConnectors(linker.userId);

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
  try {
    const r = await upstreamCall(target, 'tools/call', { name: tool, arguments: (rpc.params as any)?.arguments ?? {} }, d);
    await d.store.recordUsage({ userId: linker.userId, connectorId: target.id, toolName: tool, outcome: r?.error ? 'error' : 'ok' });
    return reply(r?.error ? fail(rpc.id, r.error.code ?? -32603, String(r.error.message ?? 'Upstream error').slice(0, 300)) : ok(rpc.id, r.result));
  } catch (e) {
    await d.store.recordUsage({ userId: linker.userId, connectorId: target.id, toolName: tool, outcome: 'error' });
    const msg = e instanceof SsrfError ? 'Connector endpoint is not allowed' : e instanceof Error ? e.message : 'Upstream error';
    return reply(fail(rpc.id, -32603, msg));
  }
}
