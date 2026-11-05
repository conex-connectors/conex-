import { handle } from './handler.ts';
import { route } from './router.ts';
import { supabaseAuthenticator } from './auth.ts';
import { SupabaseStore } from './supabase-store.ts';
import { importKey } from './crypto.ts';
import { PayPal } from './paypal.ts';
import { sessionKey } from './session.ts';

interface Env {
  SUPABASE_URL?: string;
  SUPABASE_PUBLISHABLE_KEY?: string; // public
  SUPABASE_SERVICE_ROLE_KEY?: string; // secret
  CONNECTOR_SECRET_KEY?: string; // secret, base64 32 bytes
  ALLOWED_ORIGINS?: string;
  PAYPAL_CLIENT_ID?: string; // public
  PAYPAL_CLIENT_SECRET?: string; // secret
  PAYPAL_WEBHOOK_ID?: string; // secret-ish id
  PAYPAL_ENV?: string; // 'live' | 'sandbox'
  BROWSE_API_URL?: string; // connector-directory API (optional)
  BROWSE_API_KEY?: string; // secret
}

let keys: { raw: string; enc: CryptoKey; session: CryptoKey } | null = null;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === '/health') return Response.json({ ok: true });
    const { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SUPABASE_SERVICE_ROLE_KEY, CONNECTOR_SECRET_KEY } = env;
    if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY || !SUPABASE_SERVICE_ROLE_KEY || !CONNECTOR_SECRET_KEY) {
      return Response.json({ error: 'not_configured' }, { status: 503 }); // names only, never values
    }
    if (!keys || keys.raw !== CONNECTOR_SECRET_KEY) {
      keys = { raw: CONNECTOR_SECRET_KEY, enc: await importKey(CONNECTOR_SECRET_KEY), session: await sessionKey(CONNECTOR_SECRET_KEY) };
    }
    const store = new SupabaseStore({ url: SUPABASE_URL, serviceKey: SUPABASE_SERVICE_ROLE_KEY, fetch, encKey: keys.enc });
    const auth = supabaseAuthenticator({ url: SUPABASE_URL, publishableKey: SUPABASE_PUBLISHABLE_KEY, fetch });
    const mcp = {
      store, secrets: store, fetch, auth, authServerUrl: `${SUPABASE_URL}/auth/v1`,
      allowedOrigins: (env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
    };
    const billing = env.PAYPAL_CLIENT_ID && env.PAYPAL_CLIENT_SECRET && env.PAYPAL_WEBHOOK_ID
      ? { paypal: new PayPal({ clientId: env.PAYPAL_CLIENT_ID, clientSecret: env.PAYPAL_CLIENT_SECRET, webhookId: env.PAYPAL_WEBHOOK_ID, env: env.PAYPAL_ENV === 'sandbox' ? 'sandbox' : 'live', fetch }), store, sessionKey: keys.session }
      : null;
    const deleteUser = async (userId: string) => {
      const r = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${encodeURIComponent(userId)}`, {
        method: 'DELETE', headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` },
      });
      return r.ok;
    };
    return route(req, {
      mcp, billing, paypalClientId: env.PAYPAL_CLIENT_ID ?? '', supabaseUrl: SUPABASE_URL, publishableKey: SUPABASE_PUBLISHABLE_KEY,
      browse: { baseUrl: env.BROWSE_API_URL || undefined, apiKey: env.BROWSE_API_KEY || undefined, fetch },
      api: { store, secrets: store, fetch, encKey: keys.enc, billing, deleteUser },
    });
  },
};
export { handle };
