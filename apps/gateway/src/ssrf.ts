// SSRF guard for user-supplied MCP endpoint URLs.
// Public HTTPS only, port 443, no credentials, no private/reserved/metadata targets.

export class SsrfError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'SsrfError';
    this.code = code;
  }
}

export function parseIPv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n >= 0 && n <= 255) ? parts : null;
}

export function isBlockedIPv4(p: number[]): boolean {
  const [a, b, c] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 169 && b === 254) return true; // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224) return true; // multicast, reserved, broadcast
  return false;
}

// Expand an IPv6 literal (no brackets) into 8 16-bit groups, or null if invalid.
export function parseIPv6(host: string): number[] | null {
  let h = host.toLowerCase();
  const zone = h.indexOf('%');
  if (zone !== -1) h = h.slice(0, zone);
  if (!h.includes(':')) return null;
  const v4tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(h);
  if (v4tail) {
    const v4 = parseIPv4(v4tail[1]);
    if (!v4) return null;
    h = h.slice(0, -v4tail[1].length) +
      ((v4[0] << 8) | v4[1]).toString(16) + ':' + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = h.split('::');
  if (halves.length > 2) return null;
  const toGroups = (s: string) => (s === '' ? [] : s.split(':'));
  const head = toGroups(halves[0]);
  const tail = halves.length === 2 ? toGroups(halves[1]) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const all = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (all.length !== 8) return null;
  const out: number[] = [];
  for (const g of all) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

function embeddedV4(g: number[], hi: number, lo: number): number[] {
  return [g[hi] >> 8, g[hi] & 255, g[lo] >> 8, g[lo] & 255];
}

export function isBlockedIPv6(g: number[]): boolean {
  if (g.every((x) => x === 0)) return true; // ::
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true; // ::1
  // IPv4-mapped ::ffff:a.b.c.d and deprecated IPv4-compatible ::a.b.c.d
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) {
    return isBlockedIPv4(embeddedV4(g, 6, 7));
  }
  // NAT64 64:ff9b::/96
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) {
    return isBlockedIPv4(embeddedV4(g, 6, 7));
  }
  if (g[0] === 0x2002) return isBlockedIPv4(embeddedV4(g, 1, 2)); // 6to4
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // documentation
  return false;
}

export function isBlockedIp(ip: string): boolean {
  const v4 = parseIPv4(ip);
  if (v4) return isBlockedIPv4(v4);
  const v6 = parseIPv6(ip.replace(/^\[|\]$/g, ''));
  if (v6) return isBlockedIPv6(v6);
  return true; // unparseable => block
}

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.localdomain', '.lan', '.home', '.corp', '.intranet'];

/** Static (no-DNS) validation. Returns the normalized URL. Throws SsrfError. */
export function validateEndpointUrl(raw: string): URL {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) {
    throw new SsrfError('invalid_url', 'Endpoint URL is missing or too long.');
  }
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new SsrfError('invalid_url', 'Endpoint URL is not a valid URL.');
  }
  if (u.protocol !== 'https:') throw new SsrfError('https_required', 'Endpoint must use https.');
  if (u.username || u.password) throw new SsrfError('credentials_in_url', 'Credentials in the URL are not allowed.');
  if (u.port && u.port !== '443') throw new SsrfError('port_blocked', 'Only port 443 is allowed.');
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[')) {
    const g = parseIPv6(host.slice(1, -1));
    if (!g || isBlockedIPv6(g)) throw new SsrfError('private_address', 'Endpoint resolves to a blocked address.');
    return u;
  }
  if (/^[\d.]+$/.test(host)) {
    const v4 = parseIPv4(host);
    if (!v4 || isBlockedIPv4(v4)) throw new SsrfError('private_address', 'Endpoint resolves to a blocked address.');
    return u;
  }
  if (host === 'localhost' || host === 'metadata' || !host.includes('.') ||
      BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
    throw new SsrfError('private_host', 'Endpoint host is not a public hostname.');
  }
  return u;
}

export type Resolver = (hostname: string) => Promise<string[]>;

/** Resolve A/AAAA via Cloudflare DoH. Injectable for tests. */
export const dohResolver: Resolver = async (hostname) => {
  const ips: string[] = [];
  for (const type of ['A', 'AAAA']) {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`,
      { headers: { accept: 'application/dns-json' } },
    );
    if (!res.ok) throw new SsrfError('dns_failed', 'DNS lookup failed.');
    const body = (await res.json()) as { Answer?: { type: number; data: string }[] };
    for (const a of body.Answer ?? []) if (a.type === 1 || a.type === 28) ips.push(a.data);
  }
  return ips;
};

/**
 * Validate and also check every resolved address is public.
 * NOTE: Workers cannot pin the resolved IP for the later fetch, so this narrows but
 * does not fully close the DNS-rebinding window; Workers also cannot reach private
 * networks. Redirects are disallowed at the fetch layer (see upstream.ts).
 */
export async function validateEndpointWithDns(raw: string, resolve: Resolver = dohResolver): Promise<URL> {
  const u = validateEndpointUrl(raw);
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (parseIPv4(host) || host.includes(':')) return u;
  const ips = await resolve(host);
  if (ips.length === 0) throw new SsrfError('dns_failed', 'Hostname did not resolve.');
  if (ips.some(isBlockedIp)) throw new SsrfError('private_address', 'Endpoint resolves to a blocked address.');
  return u;
}
