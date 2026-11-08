// Single source for the privacy policy and About text (served as JSON for the app and HTML at /privacy, /about).
export interface Doc { title: string; updated: string; sections: { heading: string; body: string }[] }

export const PRIVACY: Doc = {
  title: 'Privacy policy',
  updated: '2026-11-04',
  sections: [
    { heading: 'The short version', body: 'Conex connects your AI agents to your tools. We keep only what is needed to do that, we protect your credentials, and we never sell your data.' },
    { heading: 'What we store', body: 'Your email address and a password hash (managed by our authentication provider); the connectors you add (name, server address, how you connected); your plan and payment status; and simple usage counts per tool so we can enforce daily limits. We also record which AI agents you approved and when they last connected.' },
    { heading: 'Your credentials', body: 'Tokens, client secrets and keys you enter are encrypted on our servers before they are saved and are only decrypted at the moment a tool call needs them. They are never shown again, never written to logs and never stored on your phone. When you generate an API key, it is shown once and we do not keep it.' },
    { heading: 'What passes through Conex', body: 'When an agent uses a tool, the request and the answer travel through our gateway to the service you connected. We do not read, keep or train on the content of those requests or answers. We keep only the tool name, the time and whether it succeeded.' },
    { heading: 'Payments', body: 'Payments are handled by PayPal. We never see your card or PayPal login. We receive a subscription reference and its status so we can unlock your plan, and we remove access when a subscription ends or is cancelled.' },
    { heading: 'Who we share with', body: 'Only the providers that run Conex: Supabase (accounts and database), Cloudflare (network and servers) and PayPal (billing). Each only receives what it needs. We do not sell or rent personal data and we do not run ads.' },
    { heading: 'Your choices', body: 'You can disconnect or delete any connector at any time, which also deletes its stored credential. You can delete your account from Settings, which removes your connectors, credentials and usage history. You can ask for a copy of your data or for corrections by contacting us.' },
    { heading: 'Security', body: 'Connections use HTTPS, credentials are encrypted at rest, other users can never read your data, and the gateway refuses to connect to private or internal network addresses. No system is perfect, so please use tokens with the least access that gets the job done.' },
    { heading: 'Children', body: 'Conex is not intended for people under 16.' },
    { heading: 'Changes and contact', body: 'If this policy changes in a meaningful way we will tell you in the app. Questions: use the contact details on our store listing.' },
  ],
};

export const ABOUT: Doc = {
  title: 'About Conex',
  updated: '2026-11-04',
  sections: [
    { heading: 'One link for all your tools', body: 'Conex brings your connected tools together behind one stable link for your AI agents. Add GitHub, Cloudflare, Supabase or any MCP server once, then connect Claude, Grok or any agent to Conex and it can use them all.' },
    { heading: 'Why we built it', body: 'Tool connections break, tokens expire and every agent wants its own setup. Conex keeps that in one calm place, so you stop fighting connection issues and get back to building.' },
    { heading: 'You stay in control', body: 'You approve each agent, you can disconnect a tool with one tap, and your secrets stay encrypted on our side. Plans start at $5 a month so it stays affordable for solo builders.' },
  ],
};

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
export function docHtml(doc: Doc): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(doc.title)} · Conex</title>
<style>:root{color-scheme:light dark;--bg:#f5f8fc;--fg:#0b1a2c;--mut:#5a6b80}@media(prefers-color-scheme:dark){:root{--bg:#050b16;--fg:#e8f0fa;--mut:#9fb0c6}}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif}main{max-width:680px;margin:0 auto;padding:32px 20px 64px}h1{font-weight:500;letter-spacing:.02em}h2{font-size:1.05rem;margin:28px 0 6px}p{margin:0;color:var(--mut)}small{color:var(--mut)}</style></head><body><main><h1>${esc(doc.title)}</h1><small>Updated ${esc(doc.updated)}</small>${doc.sections.map((s) => `<h2>${esc(s.heading)}</h2><p>${esc(s.body)}</p>`).join('')}</main></body></html>`;
}
