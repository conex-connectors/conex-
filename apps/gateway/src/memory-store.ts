import { PlanRequiredError, StoreError, LIMITS, entitled } from './types.ts';
import type { AdminStore, ApplySubscriptionArgs, BillingStore, CallOutcome, Connector, ConnectorStatus, ConnectorStore, DeleteResult, NewConnector, SecretResolver, SubscriptionRow } from './types.ts';

export interface MemConnector extends Connector { status: ConnectorStatus }

/** Reference implementation of the store contracts (tests / local dev only). Mirrors the SQL rules. */
export class MemoryStore implements ConnectorStore, AdminStore, BillingStore, SecretResolver {
  connectors = new Map<string, MemConnector>();
  secrets = new Map<string, string>();
  subs = new Map<string, SubscriptionRow & { statusUpdatedAt: string | null }>();
  seenEvents = new Set<string>();
  agents: { userId: string; agentName: string }[] = [];
  events: { id: number; userId: string; tool: string; outcome: string }[] = [];
  /** Test shortcut: give a user an active plan with this daily call limit (connector limit from the plan). */
  plans = new Map<string, { calls: number; plan?: string }>();

  limits(userId: string): { calls: number; connectors: number } | null {
    const p = this.plans.get(userId);
    if (p) return { calls: p.calls, connectors: LIMITS[p.plan ?? 'starter'].connectors };
    const s = this.subs.get(userId) ?? null;
    return entitled(s) ? { calls: LIMITS[s!.plan].calls, connectors: LIMITS[s!.plan].connectors } : null;
  }

  async listConnectors(userId: string) {
    return [...this.connectors.values()].filter((c) => c.userId === userId && c.status === 'connected');
  }
  async deleteConnector(userId: string, id: string): Promise<DeleteResult> {
    const c = this.connectors.get(id);
    if (!c || c.userId !== userId) return 'not_found';
    this.connectors.delete(id);
    if (c.credentialRef) this.secrets.delete(c.credentialRef);
    return 'deleted';
  }
  async touchAgent(userId: string, agentName: string) {
    if (!this.agents.some((a) => a.userId === userId && a.agentName === agentName)) this.agents.push({ userId, agentName });
  }
  async beginCall(userId: string, _connectorId: string, tool: string) {
    const lim = this.limits(userId);
    if (!lim) throw new PlanRequiredError();
    const used = this.events.filter((e) => e.userId === userId && e.tool === tool && e.outcome !== 'blocked').length;
    const id = this.events.length + 1;
    if (used >= lim.calls) { this.events.push({ id, userId, tool, outcome: 'blocked' }); return null; }
    this.events.push({ id, userId, tool, outcome: 'success' });
    return id;
  }
  async finishCall(eventId: number, outcome: CallOutcome) {
    const e = this.events.find((x) => x.id === eventId);
    if (e) e.outcome = outcome;
  }
  async get(ref: string) { return this.secrets.get(ref) ?? null; }

  async getConnector(userId: string, id: string) {
    const c = this.connectors.get(id);
    return c && c.userId === userId ? { ...c } : null;
  }
  async createConnector(c: NewConnector, secret: { ciphertext: string; iv: string } | null) {
    const lim = this.limits(c.userId);
    if (!lim) throw new StoreError('plan_required');
    if ([...this.connectors.values()].filter((x) => x.userId === c.userId).length >= lim.connectors) throw new StoreError('connector_limit_reached');
    this.connectors.set(c.id, { id: c.id, userId: c.userId, name: c.name, endpointUrl: c.endpointUrl, credentialRef: secret ? c.id : null, authMethod: c.authMethod, tokenUrl: c.tokenUrl, autoRefresh: c.autoRefresh, status: 'connected' });
    if (secret) this.secrets.set(c.id, `ENC:${secret.ciphertext}:${secret.iv}`);
  }
  async setConnectorStatus(userId: string, id: string, status: ConnectorStatus) {
    const c = this.connectors.get(id);
    if (!c || c.userId !== userId) return false;
    c.status = status;
    return true;
  }

  async getSubscription(userId: string) { return this.subs.get(userId) ?? null; }
  async applySubscription(a: ApplySubscriptionArgs) {
    if (this.seenEvents.has(a.eventId)) return 'duplicate' as const;
    this.seenEvents.add(a.eventId);
    for (const [uid, s] of this.subs) if (s.providerSubscriptionId === a.subscriptionId && uid !== a.userId) throw new Error('subscription_owned_by_another_user');
    const cur = this.subs.get(a.userId) ?? { plan: 'none', status: 'inactive', billingInterval: null, periodEnd: null, providerSubscriptionId: null, statusUpdatedAt: null };
    if (cur.statusUpdatedAt && a.eventTime && a.eventTime < cur.statusUpdatedAt) return 'stale' as const;
    if (cur.providerSubscriptionId && cur.providerSubscriptionId !== a.subscriptionId && a.status !== 'active') return 'superseded' as const;
    this.subs.set(a.userId, {
      plan: a.status === 'expired' ? 'none' : a.plan, status: a.status, billingInterval: a.interval,
      periodEnd: a.periodEnd ?? (cur.providerSubscriptionId === a.subscriptionId ? cur.periodEnd : null),
      providerSubscriptionId: a.subscriptionId, statusUpdatedAt: a.eventTime ?? new Date().toISOString(),
    });
    return 'applied' as const;
  }
}
