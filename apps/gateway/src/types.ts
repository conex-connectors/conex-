export type AuthMethod = 'bearer' | 'oauth_browse' | 'client_credentials' | 'token_generator' | 'supabase';

export interface Connector {
  id: string;
  userId: string;
  name: string;
  endpointUrl: string;
  credentialRef: string | null; // opaque; the credential itself is encrypted in conex_connector_secrets
  authMethod?: AuthMethod | null;
  tokenUrl?: string | null;
  autoRefresh?: boolean;
}
export type DeleteResult = 'deleted' | 'not_found';
export type CallOutcome = 'success' | 'error';
export type ConnectorStatus = 'pending' | 'connected' | 'error' | 'disabled';

export class PlanRequiredError extends Error {
  constructor() { super('plan_required'); this.name = 'PlanRequiredError'; }
}
export class StoreError extends Error {
  code: 'plan_required' | 'connector_limit_reached' | 'db_error';
  constructor(code: 'plan_required' | 'connector_limit_reached' | 'db_error') { super(code); this.name = 'StoreError'; this.code = code; }
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

export interface NewConnector {
  id: string; userId: string; name: string; endpointUrl: string;
  authMethod: AuthMethod; tokenUrl: string | null; autoRefresh: boolean;
}
export interface AdminStore {
  getConnector(userId: string, id: string): Promise<(Connector & { status: ConnectorStatus }) | null>;
  /** Inserts a verified connector (+ its encrypted secret). Throws StoreError (plan_required / connector_limit_reached). */
  createConnector(c: NewConnector, secret: { ciphertext: string; iv: string } | null): Promise<void>;
  setConnectorStatus(userId: string, id: string, status: ConnectorStatus): Promise<boolean>;
}

export interface SubscriptionRow {
  plan: string; status: string; billingInterval: string | null; periodEnd: string | null; providerSubscriptionId: string | null;
}
export interface ApplySubscriptionArgs {
  userId: string; plan: string; interval: string; subscriptionId: string; paypalPlanId: string;
  status: 'active' | 'cancelled' | 'past_due' | 'expired'; periodEnd: string | null;
  eventId: string; eventType: string; eventTime: string | null;
}
export interface BillingStore {
  getSubscription(userId: string): Promise<SubscriptionRow | null>;
  applySubscription(a: ApplySubscriptionArgs): Promise<'applied' | 'duplicate' | 'stale' | 'superseded'>;
}

export const LIMITS: Record<string, { connectors: number; calls: number }> = {
  starter: { connectors: 30, calls: 200 }, pro: { connectors: 100, calls: 1000 }, scale: { connectors: 500, calls: 5000 },
};
export const entitled = (s: SubscriptionRow | null, now = Date.now()): boolean =>
  !!s && ['active', 'cancelled', 'past_due'].includes(s.status) && !!s.periodEnd && Date.parse(s.periodEnd) > now && s.plan in LIMITS;
