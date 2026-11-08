-- PayPal Subscriptions for the 6 plan buttons.
-- Access = paid-through date, kept after cancel / failed payment until it passes.
-- Applied as migration name: conex_subscriptions_paypal (superseded in part by 20261101100000_conex_fresh_paypal.sql).

create or replace function public.conex_connector_limit(p_user uuid) returns int
language sql stable security definer set search_path = '' as $$
  select coalesce((select case s.plan when 'starter' then 30 when 'pro' then 100 when 'scale' then 500 end
    from public.conex_subscriptions s
    where s.user_id = p_user and s.status in ('active','cancelled','past_due') and s.current_period_end > now()), 0);
$$;
create or replace function public.conex_call_limit(p_user uuid) returns int
language sql stable security definer set search_path = '' as $$
  select coalesce((select case s.plan when 'starter' then 200 when 'pro' then 1000 when 'scale' then 5000 end
    from public.conex_subscriptions s
    where s.user_id = p_user and s.status in ('active','cancelled','past_due') and s.current_period_end > now()), 0);
$$;
