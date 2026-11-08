import { PLANS, type PlanKey } from './plans.ts';

const SUPABASE_JS = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.106.2/dist/umd/supabase.js';
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
export const nonce = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));

const BASE_CSS = `:root{color-scheme:light dark;--bg:#f2f6fb;--card:#fff;--fg:#0b1a2c;--mut:#5a6b80;--line:#d8e2ee;--acc:#0a84ff}
@media(prefers-color-scheme:dark){:root{--bg:#050b16;--card:#0d1829;--fg:#e8f0fa;--mut:#9fb0c6;--line:#1c2b42}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;padding:20px}
.card{width:100%;max-width:420px;background:var(--card);border:1px solid var(--line);border-radius:28px;padding:28px 24px;text-align:center}
.logo{font-size:26px;letter-spacing:.35em;font-weight:300;margin:0 0 6px}h1{font-size:22px;font-weight:600;margin:14px 0 6px}p{color:var(--mut);margin:6px 0}
input{width:100%;padding:14px 18px;border-radius:999px;border:1px solid var(--line);background:transparent;color:var(--fg);font-size:16px;margin:6px 0}
button{width:100%;padding:14px;border-radius:999px;border:1px solid var(--line);font-size:16px;font-weight:600;margin-top:10px;cursor:pointer;background:transparent;color:var(--fg)}
button.pri{background:linear-gradient(90deg,#1f8fff,#27c1ff);border:0;color:#04121f}.row{display:flex;gap:10px}.err{color:#ff6b6b;min-height:1.4em}.ok{color:#2ecc71}`;

function pageHeaders(n: string, extraScript: string[], extraConnect: string[], extraFrame: string[] = []): Record<string, string> {
  return {
    'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff',
    'content-security-policy': [
      "default-src 'none'", `script-src 'nonce-${n}' ${extraScript.join(' ')}`.trim(), "style-src 'unsafe-inline'", "img-src data: https://*.paypal.com https://*.paypalobjects.com",
      `connect-src ${['\'self\'', ...extraConnect].join(' ')}`, extraFrame.length ? `frame-src ${extraFrame.join(' ')}` : "frame-src 'none'",
      "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
    ].join('; '),
  };
}

/** Agent approval page ("Connect <agent> to Conex"): Supabase's OAuth server redirects here with ?authorization_id=. */
export function consentPage(cfg: { supabaseUrl: string; publishableKey: string }): Response {
  const n = nonce();
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect an agent · Conex</title><style>${BASE_CSS}</style></head>
<body><main class="card"><div class="logo">CON≡X</div><div id="view"><p>Loading…</p></div></main>
<script nonce="${n}" src="${SUPABASE_JS}"></script>
<script nonce="${n}">
const sb = supabase.createClient(${JSON.stringify(cfg.supabaseUrl)}, ${JSON.stringify(cfg.publishableKey)});
const id = new URLSearchParams(location.search).get('authorization_id');
const view = document.getElementById('view');
const el = (t, props = {}, ...kids) => { const e = document.createElement(t); Object.assign(e, props); kids.forEach(k => e.append(k)); return e; };
const show = (...nodes) => view.replaceChildren(...nodes);
const fail = (m) => show(el('h1', {textContent: 'Something went wrong'}), el('p', {className: 'err', textContent: m}));
async function main() {
  if (!id) return fail('This link is missing its request id. Start the connection again from your agent.');
  const { data: { session } } = await sb.auth.getSession();
  if (!session) return login();
  const { data, error } = await sb.auth.oauth.getAuthorizationDetails(id);
  if (error || !data) return fail('This request has expired or is invalid. Start the connection again from your agent.');
  if (!('authorization_id' in data)) { location.replace(data.redirect_url); return; }
  const name = (data.client && data.client.name) || 'This agent';
  const msg = el('p', {className: 'err'});
  const act = (fn) => async () => { msg.textContent = ''; const r = await fn(id); if (r.error) { msg.textContent = 'Could not complete. Please try again.'; return; } location.replace(r.data.redirect_url); };
  show(el('h1', {textContent: 'Connect ' + name + ' to Conex'}),
    el('p', {textContent: 'Signed in as ' + session.user.email}),
    el('p', {textContent: name + ' will be able to use all your connected tools through Conex with full read and write access.'}),
    el('button', {className: 'pri', textContent: 'Approve', onclick: act(sb.auth.oauth.approveAuthorization.bind(sb.auth.oauth))}),
    el('button', {textContent: 'Cancel connection', onclick: act(sb.auth.oauth.denyAuthorization.bind(sb.auth.oauth))}), msg);
}
function login() {
  const email = el('input', {type: 'email', placeholder: 'you@email.com', autocomplete: 'email'});
  const pw = el('input', {type: 'password', placeholder: 'Password', autocomplete: 'current-password'});
  const msg = el('p', {className: 'err'});
  const go = el('button', {className: 'pri', textContent: 'Sign in', onclick: async () => {
    msg.textContent = '';
    const { error } = await sb.auth.signInWithPassword({ email: email.value.trim(), password: pw.value });
    if (error) { msg.textContent = 'Wrong email or password.'; return; }
    main();
  }});
  show(el('p', {textContent: 'Sign in to approve this connection'}), email, pw, go, msg);
}
main();
</script></body></html>`;
  return new Response(html, { headers: pageHeaders(n, [SUPABASE_JS.slice(0, SUPABASE_JS.indexOf('/npm/')), ], [cfg.supabaseUrl]) });
}

/** PayPal subscription button page (opened in the app's WebView). The button is the plan's own PayPal button. */
export function payPage(cfg: { clientId: string; planKey: PlanKey; userId: string; session: string }): Response {
  const n = nonce();
  const plan = PLANS[cfg.planKey];
  const sdk = `https://www.paypal.com/sdk/js?client-id=${encodeURIComponent(cfg.clientId)}&vault=true&intent=subscription`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Subscribe · Conex</title><style>${BASE_CSS}</style></head>
<body><main class="card"><div class="logo">CON≡X</div><h1>Conex ${esc(plan.plan[0].toUpperCase() + plan.plan.slice(1))}</h1>
<p>$${plan.usd} per ${plan.interval === 'monthly' ? 'month' : 'year'}. Cancel any time in PayPal.</p><div id="pp" style="margin-top:18px"></div><p id="msg" class="err"></p></main>
<script nonce="${n}" src="${esc(sdk)}" data-sdk-integration-source="button-factory"></script>
<script nonce="${n}">
const S = ${JSON.stringify(cfg.session)};
const msg = document.getElementById('msg');
paypal.Buttons({
  style: { shape: 'pill', color: ${JSON.stringify(plan.color)}, layout: 'horizontal', label: 'subscribe' },
  createSubscription: (data, actions) => actions.subscription.create({ plan_id: ${JSON.stringify(plan.paypalPlanId)}, custom_id: ${JSON.stringify(cfg.userId)} }),
  onApprove: async (data) => {
    msg.className = ''; msg.textContent = 'Confirming with PayPal…';
    try {
      const r = await fetch('/api/billing/confirm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ s: S, subscriptionID: data.subscriptionID }) });
      const j = await r.json();
      if (r.ok && j.state === 'active') { msg.className = 'ok'; msg.textContent = 'You are all set. You can return to Conex.'; location.href = 'conex://billing/done'; }
      else if (r.ok) { msg.textContent = 'Almost there. Your plan will unlock in a moment.'; location.href = 'conex://billing/pending'; }
      else { msg.className = 'err'; msg.textContent = 'We could not confirm this yet. If you were charged, your plan unlocks automatically within minutes.'; }
    } catch { msg.className = 'err'; msg.textContent = 'Network problem. If you were charged, your plan unlocks automatically within minutes.'; }
  },
  onError: () => { msg.className = 'err'; msg.textContent = 'PayPal could not start. Please try again.'; },
}).render('#pp');
</script></body></html>`;
  return new Response(html, { headers: pageHeaders(n, ['https://www.paypal.com'], ['https://*.paypal.com'], ['https://*.paypal.com']) });
}
