-- Conex hardening: least-privilege grants, server-only writes, signup bootstrap,
-- encrypted secret storage, atomic quotas, idempotent delete, linker rotation.
-- Applied to the Conex Supabase project on 2026-10-31 (migration name: conex_hardening).

-- 1. Lock down table grants. Browser (anon key) may only READ own rows; all writes go via the gateway (service role).
revoke all on public.conex_profiles, public.conex_connectors, public.conex_linkers,
  public.conex_agent_connections, public.conex_subscriptions, public.conex_usage_events from anon, authenticated;

grant select on public.conex_linkers, public.conex_agent_connections,
  public.conex_subscriptions, public.conex_usage_events to authenticated;
grant select on public.conex_profiles to authenticated;
grant update (display_name) on public.conex_profiles to authenticated;
-- credential_secret_ref is deliberately not readable by browsers.
grant select (id, user_id, name, connector_type, endpoint_url, status, last_checked_at, created_at, updated_at)
  on public.conex_connectors to authenticated;

-- 2. Replace broad ALL policies with read-only ones (writes are denied by grants + no policy).
drop policy "Users manage own connectors" on public.conex_connectors;
create policy "Users read own connectors" on public.conex_connectors
  for select to authenticated using ((select auth.uid()) = user_id);
drop policy "Users manage own linker" on public.conex_linkers;
create policy "Users read own linker" on public.conex_linkers
  for select to authenticated using ((select auth.uid()) = user_id);
drop policy "Users manage own profile" on public.conex_profiles;
create policy "Users read own profile" on public.conex_profiles
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "Users update own profile" on public.conex_profiles
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- 3. Linker ID is a bearer capability: raise entropy to 128 bits.
alter table public.conex_linkers alter column linker_id
  set default ('cx-' || encode(extensions.gen_random_bytes(16), 'hex'));

-- 4. Encrypted connector credentials (ciphertext only; key lives in a Worker secret). No browser access.
-- RLS enabled with no policies on purpose: deny-all for anon/authenticated (advisor INFO is expected).
create table public.conex_connector_secrets (
  connector_id uuid primary key references public.conex_connectors(id) on delete cascade,
  ciphertext text not null,
  iv text not null,
  created_at timestamptz not null default now()
);
alter table public.conex_connector_secrets enable row level security;
revoke all on public.conex_connector_secrets from anon, authenticated;

-- 5. One agent row per (user, agent name).
create unique index conex_agent_connections_user_agent_key
  on public.conex_agent_connections (user_id, agent_name);

-- 6. Signup bootstrap: profile + stable linker + free subscription row.
create function public.conex_handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.conex_profiles (user_id) values (new.id) on conflict do nothing;
  insert into public.conex_linkers (user_id) values (new.id) on conflict do nothing;
  insert into public.conex_subscriptions (user_id) values (new.id) on conflict do nothing;
  return new;
end $$;
create trigger conex_on_auth_user_created after insert on auth.users
  for each row execute function public.conex_handle_new_user();
insert into public.conex_profiles (user_id) select id from auth.users on conflict do nothing;
insert into public.conex_linkers (user_id) select id from auth.users on conflict do nothing;
insert into public.conex_subscriptions (user_id) select id from auth.users on conflict do nothing;

-- 7. Max 30 connectors per user, race-safe.
create function public.conex_enforce_connector_limit() returns trigger
language plpgsql set search_path = '' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(new.user_id::text, 1));
  if (select count(*) from public.conex_connectors where user_id = new.user_id) >= 30 then
    raise exception 'connector_limit_reached' using errcode = 'P0001';
  end if;
  return new;
end $$;
create trigger conex_connector_limit before insert on public.conex_connectors
  for each row execute function public.conex_enforce_connector_limit();

-- 8. Idempotent delete (works for the last connector; secret row cascades).
create function public.conex_delete_connector(p_user uuid, p_id uuid) returns text
language plpgsql security definer set search_path = '' as $$
declare n int;
begin
  delete from public.conex_connectors where id = p_id and user_id = p_user;
  get diagnostics n = row_count;
  return case when n > 0 then 'deleted' else 'not_found' end;
end $$;

-- 9. Linker rotation (revokes the old URL, keeps exactly one row per user).
create function public.conex_rotate_linker(p_user uuid) returns text
language plpgsql security definer set search_path = '' as $$
declare v text;
begin
  update public.conex_linkers
     set linker_id = 'cx-' || encode(extensions.gen_random_bytes(16), 'hex'), updated_at = now()
   where user_id = p_user returning linker_id into v;
  return v;
end $$;

-- 10. Atomic per-tool daily quota (UTC day). Returns event id, or null when blocked.
create function public.conex_begin_call(p_user uuid, p_connector uuid, p_tool text, p_limit int default 200)
returns bigint language plpgsql security definer set search_path = '' as $$
declare used int; eid bigint;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_user::text || ':' || p_tool, 2));
  select count(*) into used from public.conex_usage_events
   where user_id = p_user and tool_name = p_tool and outcome <> 'blocked'
     and created_at >= date_trunc('day', now() at time zone 'utc') at time zone 'utc';
  if used >= p_limit then
    insert into public.conex_usage_events (user_id, connector_id, tool_name, outcome)
      values (p_user, p_connector, p_tool, 'blocked');
    return null;
  end if;
  insert into public.conex_usage_events (user_id, connector_id, tool_name, outcome)
    values (p_user, p_connector, p_tool, 'success') returning id into eid;
  return eid;
end $$;

create function public.conex_finish_call(p_id bigint, p_outcome text) returns void
language sql security definer set search_path = '' as $$
  update public.conex_usage_events set outcome = p_outcome where id = p_id and p_outcome in ('success','error');
$$;

-- 11. Real agent connection tracking.
create function public.conex_touch_agent(p_user uuid, p_agent text) returns void
language sql security definer set search_path = '' as $$
  insert into public.conex_agent_connections (user_id, agent_name) values (p_user, left(p_agent, 80))
  on conflict (user_id, agent_name) do update set last_seen_at = now(), status = 'connected';
$$;

-- 12. Functions are backend-only.
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.conex_delete_connector(uuid, uuid), public.conex_rotate_linker(uuid),
  public.conex_begin_call(uuid, uuid, text, int), public.conex_finish_call(bigint, text),
  public.conex_touch_agent(uuid, text) to service_role;
