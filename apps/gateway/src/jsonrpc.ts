export interface RpcRequest { jsonrpc: '2.0'; id?: string | number | null; method: string; params?: Record<string, unknown> }
export class RpcError extends Error {
  code: number;
  constructor(code: number, message: string) { super(message); this.name = 'RpcError'; this.code = code; }
}
export const MAX_BODY_BYTES = 1_000_000;
export const SUPPORTED_METHODS = new Set(['initialize', 'notifications/initialized', 'ping', 'tools/list', 'tools/call']);

export function parseRpc(text: string): RpcRequest {
  if (text.length > MAX_BODY_BYTES) throw new RpcError(-32600, 'Request too large');
  let v: unknown;
  try { v = JSON.parse(text); } catch { throw new RpcError(-32700, 'Parse error'); }
  if (Array.isArray(v) || typeof v !== 'object' || v === null) throw new RpcError(-32600, 'Single JSON-RPC object required');
  const o = v as Record<string, unknown>;
  if (o.jsonrpc !== '2.0' || typeof o.method !== 'string') throw new RpcError(-32600, 'Invalid request');
  if ('id' in o && !['string', 'number'].includes(typeof o.id) && o.id !== null) throw new RpcError(-32600, 'Invalid id');
  if (o.params !== undefined && (typeof o.params !== 'object' || o.params === null || Array.isArray(o.params))) {
    throw new RpcError(-32602, 'params must be an object');
  }
  if (!SUPPORTED_METHODS.has(o.method)) throw new RpcError(-32601, 'Method not found');
  return o as unknown as RpcRequest;
}

export const ok = (id: RpcRequest['id'], result: unknown) => ({ jsonrpc: '2.0', id: id ?? null, result });
export const fail = (id: RpcRequest['id'], code: number, message: string) =>
  ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
