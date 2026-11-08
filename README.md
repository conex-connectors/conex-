# Conex

Connects AI agents to their tools through one permanent linker URL per user.
Adding or removing connectors changes the tools behind the link, never the link.

**Stack:** Cloudflare Workers (gateway) · Supabase (auth, Postgres, RLS) · PayPal (billing) · GitHub/Codespaces.

## Status (branch `feat/conex-production-runtime`)

| Area | State |
|---|---|
| Gateway: stable-linker MCP routing, tool aggregation, upstream client | Built, unit-tested |
| SSRF guard (IPv4/IPv6, metadata, DNS check, no redirects, port 443) | Built, unit-tested |
| Store contract + idempotent connector delete (incl. last connector) | Built (in-memory reference), tested |
| Supabase store, Auth, secret vault, quotas | Not started |
| PayPal subscriptions + webhooks | Not started |
| UI (React/Vite, CON≡X) | Not started |
| Cloudflare deploy | Not deployed. `/mcp/*` returns 503 until the store is wired |

## Develop

```
npm install
npm run typecheck
npm test
```

## Gateway behavior

`POST /mcp/<linkerId>` (JSON-RPC 2.0: `initialize`, `tools/list`, `tools/call`, `ping`).
Tools from each connector are exposed as `<connector-slug>__<tool>`. The connector list is read per request.
Agent connections are recorded only on `initialize`. Upstream errors are sanitized; credentials never appear in responses.

Secret *names* (values never committed): `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `CONNECTOR_SECRET_KEY`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`.
