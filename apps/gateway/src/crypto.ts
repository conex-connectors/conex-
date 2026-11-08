// AES-256-GCM for connector credentials. Key is a Worker secret (base64, 32 bytes).
// The connector id is bound as additional authenticated data so a ciphertext cannot be swapped between connectors.

const enc = new TextEncoder();
const dec = new TextDecoder();

export function toB64(u: Uint8Array): string {
  let s = '';
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s);
}
export function fromB64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function importKey(b64key: string): Promise<CryptoKey> {
  const raw = fromB64(b64key);
  if (raw.length !== 32) throw new Error('CONNECTOR_SECRET_KEY must be 32 bytes (base64).');
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encryptSecret(key: CryptoKey, plaintext: string, aad: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, enc.encode(plaintext));
  return { ciphertext: toB64(new Uint8Array(ct)), iv: toB64(iv) };
}

export async function decryptSecret(key: CryptoKey, ciphertext: string, iv: string, aad: string): Promise<string> {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(iv), additionalData: enc.encode(aad) }, key, fromB64(ciphertext));
  return dec.decode(pt);
}
