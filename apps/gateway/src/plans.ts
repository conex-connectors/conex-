export type PlanName = 'starter' | 'pro' | 'scale';
export type Interval = 'monthly' | 'yearly';
export type PlanKey = `${PlanName}_${Interval}`;

export interface PlanDef { plan: PlanName; interval: Interval; paypalPlanId: string; usd: number; color: 'black' | 'silver' }

// The six PayPal subscription plans (IDs come from the PayPal subscription buttons).
export const PLANS: Record<PlanKey, PlanDef> = {
  starter_monthly: { plan: 'starter', interval: 'monthly', paypalPlanId: 'P-9WR48516N3116070HNLVN5II', usd: 5, color: 'black' },
  pro_monthly: { plan: 'pro', interval: 'monthly', paypalPlanId: 'P-1AW45116P0298370JNLVN66A', usd: 10, color: 'black' },
  scale_monthly: { plan: 'scale', interval: 'monthly', paypalPlanId: 'P-1XS36593KR758542DNLVOAFA', usd: 15, color: 'black' },
  starter_yearly: { plan: 'starter', interval: 'yearly', paypalPlanId: 'P-3TX56005CV3762023NLVOB3Q', usd: 60, color: 'silver' },
  pro_yearly: { plan: 'pro', interval: 'yearly', paypalPlanId: 'P-9A566081A08321138NLVOC6Y', usd: 120, color: 'silver' },
  scale_yearly: { plan: 'scale', interval: 'yearly', paypalPlanId: 'P-7CS87109RE997563YNLVOEEI', usd: 180, color: 'silver' },
};

export const isPlanKey = (k: unknown): k is PlanKey => typeof k === 'string' && Object.prototype.hasOwnProperty.call(PLANS, k);
export const planByPaypalId = (id: string): (PlanDef & { key: PlanKey }) | null => {
  for (const [key, def] of Object.entries(PLANS)) if (def.paypalPlanId === id) return { ...def, key: key as PlanKey };
  return null;
};
