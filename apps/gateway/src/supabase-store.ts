import { decryptSecret } from './crypto.ts';
import { PlanRequiredError } from './types.ts';
import type { CallOutcome, Connector, ConnectorStore, DeleteResult, SecretResolver } from './types.ts';

export interface SupabaseStoreCfg { url: string; serviceKey: string; fetch: typeof fetch; encKey: CryptoKey }

export class SupabaseStore implements ConnectorStore, SecretResolver {
  cfg: SupabaseStoreCfg;
  constructor(cfg: SupabaseStoreCfg) { this.cfg = cfg; }

  headers(): Record<string, string> {
    return { apikey: this.cfg.serviceKey, authorization: `Bearer ${this.cfg.serviceKey}`, 'content-type': 'application/json' };
  }

  async rest(path: string): Promise<any> {
    const res = await this.cfg.fetch(`${this.cfg.url}/rest/v1/${path}`, { headers: this.headers(), signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error(`db_error:${res.status}`);
    return res.json();
  }

  async rpc(name: string, args: Record<string, unknown>): Promise<any> {
    const res = await this.cfg.fetch(`${this.cfg.url}/rest/v1/rpc/${name}`, {
      method: 'POST', headers: this.headers(), body: JSON.stringify(args), signal: AbortSignal.timeout(8000),
    });
    const text = await res.text();
    if (!res.ok) {
      let msg = '';
      try { msg = String(JSON.parse(text).message ?? ''); } catch { /* ignore */ }
      if (msg === 'plan_required') throw new PlanRequiredError();
      throw new Error(`db_error:${res.status}`); // never echo database text to callers
    }
    return text ? JSON.parse(text) : null;
  }

  async listConnectors(userId: string): Promise<Connector[]> {
    const rows = await this.rest(
      `conex_connectors?user_id=eq.${encodeURIComponent(userId)}&status=eq.connected` +
      `&select=id,user_id,name,endpoint_url,credential_secret_ref&order=created_at.asc`);
    return (rows as any[])
      .filter((r) => typeof r.endpoint_url === 'string')
      .map((r) => ({ id: r.id, userId: r.user_id, name: r.name, endpointUrl: r.endpoint_url, credentialRef: r.credential_secret_ref ?? null }));
  }

  async deleteConnector(userId: string, id: string): Promise<DeleteResult> {
    const r = await this.rpc('conex_delete_connector', { p_user: userId, p_id: id });
    return r === 'deleted' ? 'deleted' : 'not_found';
  }

  async touchAgent(userId: string, agentName: string): Promise<void> {
    await this.rpc('conex_touch_agent', { p_user: userId, p_agent: agentName });
  }

  async beginCall(userId: string, connectorId: string, tool: string): Promise<number | null> {
    const r = await this.rpc('conex_begin_call', { p_user: userId, p_connector: connectorId, p_tool: tool });
    return typeof r === 'number' ? r : null;
  }

  async finishCall(eventId: number, outcome: CallOutcome): Promise<void> {
    await this.rpc('conex_finish_call', { p_id: eventId, p_outcome: outcome });
  }

  /** ref = connector id. Ciphertext is bound to that id. */
  async get(ref: string): Promise<string | null> {
    const rows = await this.rest(`conex_connector_secrets?connector_id=eq.${encodeURIComponent(ref)}&select=ciphertext,iv`);
    const row = (rows as any[])[0];
    if (!row) return null;
    try { return await decryptSecret(this.cfg.encKey, row.ciphertext, row.iv, ref); } catch { return null; }
  }
}
