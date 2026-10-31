import { handle } from './handler.ts';

interface Env { ALLOWED_ORIGINS?: string }

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === '/health') return Response.json({ ok: true, store: 'not_configured' });
    // Supabase-backed store + secret resolver are wired in the next phase.
    // Until then the MCP route is truthfully unavailable rather than faking tools.
    if (url.pathname.startsWith('/mcp/')) {
      return Response.json({ error: 'store_not_configured' }, { status: 503 });
    }
    return Response.json({ error: 'not_found' }, { status: 404 });
  },
};
export { handle };
