import { decryptSecret } from './crypto.ts';
import { PlanRequiredError, StoreError } from './types.ts';
import type { AdminStore, ApplySubscriptionArgs, BillingStore, CallOutcome, Connector, ConnectorStatus, ConnectorStore, DeleteResult, NewConnector, SecretResolver, SubscriptionRow } from './types.ts';

export interface SupabaseStoreCfg { url: string; serviceKey: string; fetch: typeof fetch; encKey: CryptoKey }

const toConnector = (r: any): Connector => ({
  id: r.id, userId: r.user_id, name: r.name, endpointUrl: r.endpoint_url, credentialRef: r.credential_secret_ref ?? null,
  authMethod: r.auth_method ?? null, tokenUrl: r.token_url ?? null, autoRefresh: r.auto_refresh === true,
});

export class SupabaseStore implements ConnectorStore, AdminStore, BillingStore, SecretResolver {
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
      `&select=id,user_id,name,endpoint_url,credential_secret_ref,auth_method,token_url,auto_refresh&order=created_at.asc`);
    return (rows as any[])
      .filter((r) => typeof r.endpoint_url === 'string')
      .map((r) => toConnector(r));
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

  async getConnector(userId: string, id: string): Promise<(Connector & { status: ConnectorStatus }) | null> {
    const rows = (await this.rest(
      `conex_connectors?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(userId)}` +
      `&select=id,user_id,name,endpoint_url,credential_secret_ref,auth_method,token_url,auto_refresh,status`)) as any[];
    return rows[0] && typeof rows[0].endpoint_url === 'string' ? { ...toConnector(rows[0]), status: rows[0].status } : null;
  }

  async send(path: string, method: string, body?: unknown, prefer = 'return=minimal'): Promise<Response> {
    return this.cfg.fetch(`${this.cfg.url}/rest/v1/${path}`, {
      method, headers: { ...this.headers(), prefer }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(8000),
    });
  }

  async createConnector(c: NewConnector, secret: { ciphertext: string; iv: string } | null): Promise<void> {
    const res = await this.send('conex_connectors', 'POST', {
      id: c.id, user_id: c.userId, name: c.name, connector_type: 'other', endpoint_url: c.endpointUrl, status: 'connected',
      credential_secret_ref: secret ? c.id : null, auth_method: c.authMethod, token_url: c.tokenUrl, auto_refresh: c.autoRefresh,
      last_checked_at: new Date().toISOString(),
    });
    if (!res.ok) {
      let msg = '';
      try { msg = String(((await res.json()) as any).message ?? ''); } catch { /* ignore */ }
      if (msg === 'plan_required') throw new StoreError('plan_required');
      if (msg === 'connector_limit_reached') throw new StoreError('connector_limit_reached');
      throw new StoreError('db_error');
    }
    if (secret) {
      const r2 = await this.send('conex_connector_secrets', 'POST', { connector_id: c.id, ciphertext: secret.ciphertext, iv: secret.iv });
      if (!r2.ok) { await this.deleteConnector(c.userId, c.id).catch(() => 'not_found'); throw new StoreError('db_error'); }
    }
  }

  async setConnectorStatus(userId: string, id: string, status: ConnectorStatus): Promise<boolean> {
    const res = await this.send(
      `conex_connectors?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(userId)}`, 'PATCH',
      { status, last_checked_at: new Date().toISOString() }, 'return=representation');
    if (!res.ok) throw new StoreError('db_error');
    return ((await res.json()) as unknown[]).length > 0;
  }

  async getSubscription(userId: string): Promise<SubscriptionRow | null> {
    const rows = (await this.rest(
      `conex_subscriptions?user_id=eq.${encodeURIComponent(userId)}&select=plan,status,billing_interval,current_period_end,provider_subscription_id`)) as any[];
    const r = rows[0];
    return r ? { plan: r.plan, status: r.status, billingInterval: r.billing_interval ?? null, periodEnd: r.current_period_end ?? null, providerSubscriptionId: r.provider_subscription_id ?? null } : null;
  }

  async applySubscription(a: ApplySubscriptionArgs) {
    const r = await this.rpc('conex_apply_subscription', {
      p_user: a.userId, p_plan: a.plan, p_interval: a.interval, p_sub_id: a.subscriptionId, p_paypal_plan_id: a.paypalPlanId,
      p_status: a.status, p_period_end: a.periodEnd, p_event_id: a.eventId, p_event_type: a.eventType, p_event_time: a.eventTime,
    });
    return r as 'applied' | 'duplicate' | 'stale' | 'superseded';
  }
}
