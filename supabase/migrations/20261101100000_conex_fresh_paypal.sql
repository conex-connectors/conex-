-- Fresh start for PayPal: remove the earlier hosted-checkout experiment (functions, events table shape, leftover columns)
-- and the one-time-payment function. Subscriptions are applied only through conex_apply_subscription.
-- Safe: no users or subscription rows existed when this ran. Applied as migration name: conex_fresh_paypal.

do $$ declare f record; begin
  for f in select oid::regprocedure as sig from pg_proc
    where pronamespace = 'public'::regnamespace
      and proname in ('conex_apply_paypal_event','conex_begin_paypal_checkout','conex_complete_paypal_checkout','conex_release_paypal_checkout','conex_activate_plan')
  loop execute 'drop function ' || f.sig; end loop;
end $$;

drop table if exists public.conex_paypal_events;
create table public.conex_paypal_events (
  event_id text primary key,
  event_type text not null,
  resource_id text not null,
  event_time timestamptz,
  processing_status text not null default 'received' check (processing_status in ('received','processed','ignored')),
  processed_at timestamptz,
  received_at timestamptz not null default now()
);
create index conex_paypal_events_received_at_idx on public.conex_paypal_events (received_at desc);
alter table public.conex_paypal_events enable row level security;
revoke all on public.conex_paypal_events from anon, authenticated;

alter table public.conex_subscriptions drop column if exists approval_url, drop column if exists checkout_request_id;

create or replace function public.conex_apply_subscription(
  p_user uuid, p_plan text, p_interval text, p_sub_id text, p_paypal_plan_id text,
  p_status text, p_period_end timestamptz, p_event_id text, p_event_type text, p_event_time timestamptz)
returns text language plpgsql security definer set search_path = '' as $$
declare cur public.conex_subscriptions; ins int;
begin
  if p_plan not in ('starter','pro','scale') or p_interval not in ('monthly','yearly')
     or p_status not in ('active','cancelled','past_due','expired')
     or p_sub_id is null or length(p_sub_id) > 128 or p_event_id is null or length(p_event_id) > 160 then
    raise exception 'invalid_subscription' using errcode = 'P0001';
  end if;

  insert into public.conex_paypal_events (event_id, event_type, resource_id, event_time, processing_status)
  values (p_event_id, left(coalesce(p_event_type, 'unknown'), 128), p_sub_id, p_event_time, 'received')
  on conflict (event_id) do nothing;
  get diagnostics ins = row_count;
  if ins = 0 then return 'duplicate'; end if;

  if exists (select 1 from public.conex_subscriptions where provider_subscription_id = p_sub_id and user_id <> p_user) then
    raise exception 'subscription_owned_by_another_user' using errcode = 'P0001';
  end if;

  select * into cur from public.conex_subscriptions where user_id = p_user for update;
  if not found then raise exception 'unknown_user' using errcode = 'P0001'; end if;

  if cur.provider_status_updated_at is not null and p_event_time is not null and p_event_time < cur.provider_status_updated_at then
    update public.conex_paypal_events set processing_status = 'ignored', processed_at = now() where event_id = p_event_id;
    return 'stale';
  end if;
  if cur.provider_subscription_id is not null and cur.provider_subscription_id <> p_sub_id and p_status <> 'active' then
    update public.conex_paypal_events set processing_status = 'ignored', processed_at = now() where event_id = p_event_id;
    return 'superseded';
  end if;

  update public.conex_subscriptions set
    plan = case when p_status = 'expired' then 'none' else p_plan end,
    billing_interval = p_interval, status = p_status, provider = 'paypal',
    provider_subscription_id = p_sub_id, provider_plan_id = p_paypal_plan_id,
    current_period_end = coalesce(p_period_end, case when cur.provider_subscription_id = p_sub_id then cur.current_period_end end),
    provider_status_updated_at = coalesce(p_event_time, now()), updated_at = now()
  where user_id = p_user;

  update public.conex_paypal_events set processing_status = 'processed', processed_at = now() where event_id = p_event_id;
  return 'applied';
end $$;

revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.conex_delete_connector(uuid, uuid), public.conex_rotate_linker(uuid),
  public.conex_begin_call(uuid, uuid, text), public.conex_finish_call(bigint, text),
  public.conex_touch_agent(uuid, text), public.conex_connector_limit(uuid), public.conex_call_limit(uuid),
  public.conex_apply_subscription(uuid, text, text, text, text, text, timestamptz, text, text, timestamptz) to service_role;
