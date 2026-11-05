-- Plans model: NO free tier, NO trial, checkout-based (not recurring).
-- starter 30 connectors/200 calls; pro 100/1000; scale 500/5000. Access ends at current_period_end.
-- Applied to the Conex Supabase project on 2026-10-31 (migration name: conex_plans_checkout).

do $$ declare c record; begin
  for c in select conname from pg_constraint
    where conrelid = 'public.conex_subscriptions'::regclass and contype = 'c'
      and (pg_get_constraintdef(oid) like '%plan%' or pg_get_constraintdef(oid) like '%status%')
  loop execute format('alter table public.conex_subscriptions drop constraint %I', c.conname); end loop;
end $$;
update public.conex_subscriptions set plan = 'none' where plan = 'free';
alter table public.conex_subscriptions alter column plan set default 'none';
alter table public.conex_subscriptions add constraint conex_subscriptions_plan_check
  check (plan in ('none','starter','pro','scale'));
alter table public.conex_subscriptions add constraint conex_subscriptions_status_check
  check (status in ('inactive','pending','active','expired','past_due','cancelled'));
alter table public.conex_subscriptions add column billing_interval text
  check (billing_interval in ('monthly','yearly'));
comment on column public.conex_subscriptions.provider_subscription_id is
  'Last paid PayPal order/capture id (checkout model; name kept for compatibility).';

create function public.conex_connector_limit(p_user uuid) returns int
language sql stable security definer set search_path = '' as $$
  select coalesce((select case s.plan when 'starter' then 30 when 'pro' then 100 when 'scale' then 500 end
    from public.conex_subscriptions s
    where s.user_id = p_user and s.status = 'active' and s.current_period_end > now()), 0);
$$;
create function public.conex_call_limit(p_user uuid) returns int
language sql stable security definer set search_path = '' as $$
  select coalesce((select case s.plan when 'starter' then 200 when 'pro' then 1000 when 'scale' then 5000 end
    from public.conex_subscriptions s
    where s.user_id = p_user and s.status = 'active' and s.current_period_end > now()), 0);
$$;

create or replace function public.conex_enforce_connector_limit() returns trigger
language plpgsql set search_path = '' as $$
declare lim int;
begin
  perform pg_advisory_xact_lock(hashtextextended(new.user_id::text, 1));
  lim := public.conex_connector_limit(new.user_id);
  if lim = 0 then raise exception 'plan_required' using errcode = 'P0001'; end if;
  if (select count(*) from public.conex_connectors where user_id = new.user_id) >= lim then
    raise exception 'connector_limit_reached' using errcode = 'P0001';
  end if;
  return new;
end $$;

drop function public.conex_begin_call(uuid, uuid, text, int);
create function public.conex_begin_call(p_user uuid, p_connector uuid, p_tool text)
returns bigint language plpgsql security definer set search_path = '' as $$
declare lim int; used int; eid bigint;
begin
  lim := public.conex_call_limit(p_user);
  if lim = 0 then raise exception 'plan_required' using errcode = 'P0001'; end if;
  perform pg_advisory_xact_lock(hashtextextended(p_user::text || ':' || p_tool, 2));
  select count(*) into used from public.conex_usage_events
   where user_id = p_user and tool_name = p_tool and outcome <> 'blocked'
     and created_at >= date_trunc('day', now() at time zone 'utc') at time zone 'utc';
  if used >= lim then
    insert into public.conex_usage_events (user_id, connector_id, tool_name, outcome)
      values (p_user, p_connector, p_tool, 'blocked');
    return null;
  end if;
  insert into public.conex_usage_events (user_id, connector_id, tool_name, outcome)
    values (p_user, p_connector, p_tool, 'success') returning id into eid;
  return eid;
end $$;

-- Single entry point for PayPal wiring: grant a paid period. Idempotent per order id.
create function public.conex_activate_plan(p_user uuid, p_plan text, p_interval text, p_order_id text)
returns text language plpgsql security definer set search_path = '' as $$
declare cur public.conex_subscriptions; base timestamptz; span interval;
begin
  if p_plan not in ('starter','pro','scale') or p_interval not in ('monthly','yearly') then
    raise exception 'invalid_plan' using errcode = 'P0001';
  end if;
  select * into cur from public.conex_subscriptions where user_id = p_user for update;
  if not found then raise exception 'unknown_user' using errcode = 'P0001'; end if;
  if cur.provider_subscription_id = p_order_id then return 'duplicate'; end if;
  span := case p_interval when 'monthly' then interval '30 days' else interval '365 days' end;
  base := case when cur.status = 'active' and cur.plan = p_plan and cur.current_period_end > now()
               then cur.current_period_end else now() end;
  update public.conex_subscriptions
     set plan = p_plan, billing_interval = p_interval, status = 'active', provider = 'paypal',
         provider_subscription_id = p_order_id, current_period_end = base + span, updated_at = now()
   where user_id = p_user;
  return 'activated';
end $$;

alter table public.conex_profiles add column hint_seen boolean not null default false;
grant update (hint_seen) on public.conex_profiles to authenticated;
alter table public.conex_connectors
  add column auth_method text check (auth_method in ('bearer','oauth_browse','client_credentials','token_generator','supabase')),
  add column token_url text,
  add column auto_refresh boolean not null default false;
grant select (auth_method, token_url, auto_refresh) on public.conex_connectors to authenticated;

revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.conex_delete_connector(uuid, uuid), public.conex_rotate_linker(uuid),
  public.conex_begin_call(uuid, uuid, text), public.conex_finish_call(bigint, text),
  public.conex_touch_agent(uuid, text), public.conex_activate_plan(uuid, text, text, text),
  public.conex_connector_limit(uuid), public.conex_call_limit(uuid) to service_role;
