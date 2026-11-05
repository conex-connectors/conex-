import { test } from 'node:test';
import assert from 'node:assert/strict';
import { consentPage, payPage } from '../src/pages.ts';
import { PRIVACY, ABOUT, docHtml } from '../src/legal.ts';
import { PLANS } from '../src/plans.ts';

test('consent page: strict CSP, nonce scripts, only public config, approve/cancel wording', async () => {
  const r = consentPage({ supabaseUrl: 'https://p.supabase.co', publishableKey: 'sb_publishable_x' });
  const csp = r.headers.get('content-security-policy')!;
  const html = await r.text();
  const nonce = /'nonce-([^']+)'/.exec(csp)![1];
  assert.match(csp, /default-src 'none'/); assert.match(csp, /frame-ancestors 'none'/);
  assert.ok(!/script-src[^;]*unsafe-inline/.test(csp));
  assert.ok((html.match(new RegExp(`<script nonce="${nonce.replace(/[+/=]/g, (c) => '\\' + c)}"`, 'g')) ?? []).length === 2);
  for (const t of ['Approve', 'Cancel connection', 'full read and write access', 'supabase-js@2.106.2', 'getAuthorizationDetails']) assert.ok(html.includes(t), t);
  assert.ok(!/service_role|SERVICE/i.test(html));
  assert.equal(r.headers.get('cache-control'), 'no-store');
});

test('pay page renders the plan\'s own PayPal button bound to the user', async () => {
  for (const [key, plan] of Object.entries(PLANS)) {
    const r = payPage({ clientId: 'CID', planKey: key as keyof typeof PLANS, userId: '11111111-2222-3333-4444-555555555555', session: 'SESS' });
    const html = await r.text();
    assert.ok(html.includes(`plan_id: "${plan.paypalPlanId}"`), key);
    assert.ok(html.includes('custom_id: "11111111-2222-3333-4444-555555555555"'));
    assert.ok(html.includes(`color: "${plan.color}"`) && html.includes("label: 'subscribe'") && html.includes("shape: 'pill'") && html.includes("layout: 'horizontal'"));
    assert.ok(html.includes('intent=subscription') && html.includes('vault=true'));
    assert.ok(!/checkout/i.test(html.replace(/\/api\/billing\/confirm/g, '')), 'no Checkout text'); // the button brings its own UI
    assert.match(r.headers.get('content-security-policy')!, /script-src 'nonce-[^']+' https:\/\/www\.paypal\.com/);
  }
});

test('legal documents are real and render safely', () => {
  assert.ok(PRIVACY.sections.length >= 8 && ABOUT.sections.length >= 3);
  assert.ok(!/prototype|demo|do not enter production/i.test(JSON.stringify(PRIVACY)));
  const evil = docHtml({ title: '<script>x</script>', updated: 'x', sections: [{ heading: '"><img>', body: '<b>' }] });
  assert.ok(!evil.includes('<script>x') && !evil.includes('<img>') && !evil.includes('<b>'));
});
