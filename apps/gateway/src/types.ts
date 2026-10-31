export interface Linker { userId: string; linkerId: string; enabled: boolean }
export interface Connector {
  id: string;
  userId: string;
  name: string;
  endpointUrl: string;
  credentialRef: string | null; // opaque; credential itself lives in a secret store
}
export type DeleteResult = 'deleted' | 'not_found';

/** Persistence contract. Supabase implementation comes later; must pass test/store-contract. */
export interface ConnectorStore {
  getLinker(linkerId: string): Promise<Linker | null>;
  listConnectors(userId: string): Promise<Connector[]>;
  /** Idempotent. Removes connector + its secret ref. Safe for the last connector and for missing ids. */
  deleteConnector(userId: string, connectorId: string): Promise<DeleteResult>;
  recordAgentConnection(userId: string, agentName: string): Promise<void>;
  recordUsage(e: { userId: string; connectorId: string | null; toolName: string; outcome: 'ok' | 'error' }): Promise<void>;
}
export interface SecretResolver { get(ref: string): Promise<string | null> }
