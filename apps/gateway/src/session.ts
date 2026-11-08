// Short-lived signed checkout session: binds a Conex user to a plan for the PayPal page. Never grants access by itself.
const enc = new TextEncoder();
const b64u = (u: Uint8Array) => btoa(String.fromCharCode(...u)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

export interface Session { u: string; p: string; exp: number }

export async function sessionKey(secretB64: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(secretB64), (c) => c.charCodeAt(0));
  const material = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...raw, ...enc.encode('conex-pay-session-v1')])));
  return crypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function signSession(key: CryptoKey, s: Session): Promise<string> {
  const body = b64u(enc.encode(JSON.stringify(s)));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(body)));
  return `${body}.${b64u(sig)}`;
}

export async function verifySession(key: CryptoKey, token: string, now = Date.now()): Promise<Session | null> {
  const [body, sig, extra] = token.split('.');
  if (!body || !sig || extra !== undefined || token.length > 1024) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', key, unb64u(sig), enc.encode(body));
    if (!ok) return null;
    const s = JSON.parse(new TextDecoder().decode(unb64u(body))) as Session;
    if (typeof s.u !== 'string' || typeof s.p !== 'string' || typeof s.exp !== 'number' || s.exp < now) return null;
    return s;
  } catch { return null; }
}
