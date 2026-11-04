import { handle } from './handler.ts';
import { supabaseAuthenticator } from './auth.ts';
import { SupabaseStore } from './supabase-store.ts';
import { importKey } from './crypto.ts';

interface Env {
  SUPABASE_URL?: string;
  SUPABASE_PUBLISHABLE_KEY?: string; // public
  SUPABASE_SERVICE_ROLE_KEY?: string; // secret
  CONNECTOR_SECRET_KEY?: string; // secret, base64 32 bytes
  ALLOWED_ORIGINS?: string;
}

let keyCache: { raw: string; key: CryptoKey } | null = null;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === '/health') return Response.json({ ok: true });
    const { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SUPABASE_SERVICE_ROLE_KEY, CONNECTOR_SECRET_KEY } = env;
    if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY || !SUPABASE_SERVICE_ROLE_KEY || !CONNECTOR_SECRET_KEY) {
      return Response.json({ error: 'not_configured' }, { status: 503 }); // names only, never values
    }
    if (!keyCache || keyCache.raw !== CONNECTOR_SECRET_KEY) {
      keyCache = { raw: CONNECTOR_SECRET_KEY, key: await importKey(CONNECTOR_SECRET_KEY) };
    }
    const store = new SupabaseStore({ url: SUPABASE_URL, serviceKey: SUPABASE_SERVICE_ROLE_KEY, fetch, encKey: keyCache.key });
    return handle(req, {
      store, secrets: store, fetch,
      auth: supabaseAuthenticator({ url: SUPABASE_URL, publishableKey: SUPABASE_PUBLISHABLE_KEY, fetch }),
      authServerUrl: `${SUPABASE_URL}/auth/v1`,
      allowedOrigins: (env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
    });
  },
};
