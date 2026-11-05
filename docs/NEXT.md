# Next phases

1. Supabase store implementing `ConnectorStore` (must pass the same scenarios as `test/gateway.test.ts`), migrations in `supabase/migrations`, Auth, RLS tests.
2. Credential storage: encrypted at rest with `CONNECTOR_SECRET_KEY`; `credential_secret_ref` stays opaque.
3. Atomic quota enforcement (200 calls/tool/day, 30 connectors) in Postgres.
4. Rate limiting binding, request IDs, structured logs.
5. PayPal subscriptions + verified webhooks.
6. UI.

Known limit: Workers cannot pin the DNS-resolved IP for `fetch`, so the DoH check narrows but does not fully close DNS rebinding. Redirects are refused and Workers cannot reach private networks.
