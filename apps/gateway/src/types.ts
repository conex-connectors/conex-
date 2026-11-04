export interface Connector {
  id: string;
  userId: string;
  name: string;
  endpointUrl: string;
  credentialRef: string | null; // opaque; the credential itself is encrypted in conex_connector_secrets
}
export type DeleteResult = 'deleted' | 'not_found';
export type CallOutcome = 'success' | 'error';

export class PlanRequiredError extends Error {
  constructor() { super('plan_required'); this.name = 'PlanRequiredError'; }
}

export interface ConnectorStore {
  /** Only connectors the user has left connected (disabled/pending/error are hidden from agents). */
  listConnectors(userId: string): Promise<Connector[]>;
  /** Idempotent. Works for the last connector and for missing ids. */
  deleteConnector(userId: string, connectorId: string): Promise<DeleteResult>;
  touchAgent(userId: string, agentName: string): Promise<void>;
  /** Atomic plan + daily-quota check. Returns event id, null if the daily limit is hit, throws PlanRequiredError without an active plan. */
  beginCall(userId: string, connectorId: string, tool: string): Promise<number | null>;
  finishCall(eventId: number, outcome: CallOutcome): Promise<void>;
}
export interface SecretResolver { get(ref: string): Promise<string | null> }
export interface Principal { userId: string }
export interface Authenticator { authenticate(token: string): Promise<Principal | null> }
