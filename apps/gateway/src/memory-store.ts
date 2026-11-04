import { PlanRequiredError } from './types.ts';
import type { CallOutcome, Connector, ConnectorStore, DeleteResult, SecretResolver } from './types.ts';

export interface MemConnector extends Connector { status: 'pending' | 'connected' | 'error' | 'disabled' }

/** Reference implementation of the store contract (tests / local dev only). */
export class MemoryStore implements ConnectorStore, SecretResolver {
  connectors = new Map<string, MemConnector>();
  secrets = new Map<string, string>();
  plans = new Map<string, { calls: number }>(); // userId -> daily call limit; missing = no plan
  agents: { userId: string; agentName: string }[] = [];
  events: { id: number; userId: string; tool: string; outcome: string }[] = [];

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
    const plan = this.plans.get(userId);
    if (!plan) throw new PlanRequiredError();
    const used = this.events.filter((e) => e.userId === userId && e.tool === tool && e.outcome !== 'blocked').length;
    const id = this.events.length + 1;
    if (used >= plan.calls) { this.events.push({ id, userId, tool, outcome: 'blocked' }); return null; }
    this.events.push({ id, userId, tool, outcome: 'success' });
    return id;
  }
  async finishCall(eventId: number, outcome: CallOutcome) {
    const e = this.events.find((x) => x.id === eventId);
    if (e) e.outcome = outcome;
  }
  async get(ref: string) { return this.secrets.get(ref) ?? null; }
}
