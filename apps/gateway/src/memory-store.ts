import type { Connector, ConnectorStore, DeleteResult, Linker, SecretResolver } from './types.ts';

/** Reference implementation of the store contract (tests / local dev only). */
export class MemoryStore implements ConnectorStore, SecretResolver {
  linkers = new Map<string, Linker>();
  connectors = new Map<string, Connector>();
  secrets = new Map<string, string>();
  agents: { userId: string; agentName: string }[] = [];
  usage: { userId: string; connectorId: string | null; toolName: string; outcome: string }[] = [];

  async getLinker(id: string) { return this.linkers.get(id) ?? null; }
  async listConnectors(userId: string) { return [...this.connectors.values()].filter((c) => c.userId === userId); }
  async deleteConnector(userId: string, id: string): Promise<DeleteResult> {
    const c = this.connectors.get(id);
    if (!c || c.userId !== userId) {
      return 'not_found'; // idempotent; never touches other users' rows
    }
    this.connectors.delete(id);
    if (c.credentialRef) this.secrets.delete(c.credentialRef);
    return 'deleted';
  }
  async recordAgentConnection(userId: string, agentName: string) { this.agents.push({ userId, agentName }); }
  async recordUsage(e: { userId: string; connectorId: string | null; toolName: string; outcome: 'ok' | 'error' }) { this.usage.push(e); }
  async get(ref: string) { return this.secrets.get(ref) ?? null; }
}
