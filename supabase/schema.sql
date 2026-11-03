-- Word Wisp shared accounts, progress, and global maintenance mode.
-- This schema stores no passwords. Supabase Auth handles password hashing and sessions.

create or replace function public.word_wisp_name_is_allowed(candidate text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select char_length(btrim(coalesce(candidate, ''))) between 1 and 32
    and lower(regexp_replace(btrim(coalesce(candidate, '')), '[^a-zA-Z0-9]+', ' ', 'g')) !~ '(^| )(fuck|fucker|fucking|fucked|motherfucker|shit|shitty|shitter|shithead|shitface|bitch|bitches|bitchy|ass|asshole|dumbass|bitchass|dick|dicks|dickhead|pussy|pussies|cunt|cunts|cock|cocksucker|whore|slut|bastard|twat|wanker|jerkoff|damn|crap|poop|nigger|nigga|faggot|fag|dyke|kike|chink|spic|wetback|retard|retarded|tranny|pedo|pedophile|rape|rapist)( |$)';
$$;

create table if not exists public.word_wisp_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Explorer'
    check (public.word_wisp_name_is_allowed(display_name)),
  app_state jsonb not null default '{}'::jsonb,
  daily_quests jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.word_wisp_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  is_admin boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.word_wisp_settings (
  id smallint primary key default 1 check (id = 1),
  maintenance_enabled boolean not null default false,
  updated_at timestamptz not null default now()
);

insert into public.word_wisp_settings (id, maintenance_enabled)
values (1, false)
on conflict (id) do nothing;

alter table public.word_wisp_profiles enable row level security;
alter table public.word_wisp_admins enable row level security;
alter table public.word_wisp_settings enable row level security;

grant usage on schema public to anon, authenticated;
revoke all on table public.word_wisp_profiles from anon, authenticated;
revoke all on table public.word_wisp_admins from anon, authenticated;
revoke all on table public.word_wisp_settings from anon, authenticated;
grant select, insert, update on table public.word_wisp_profiles to authenticated;
grant select on table public.word_wisp_admins to authenticated;
grant select on table public.word_wisp_settings to anon, authenticated;
grant update on table public.word_wisp_settings to authenticated;

drop policy if exists word_wisp_profiles_read_own on public.word_wisp_profiles;
create policy word_wisp_profiles_read_own
  on public.word_wisp_profiles for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists word_wisp_profiles_insert_own on public.word_wisp_profiles;
create policy word_wisp_profiles_insert_own
  on public.word_wisp_profiles for insert to authenticated
  with check (user_id = (select auth.uid()));

drop policy if exists word_wisp_profiles_update_own on public.word_wisp_profiles;
create policy word_wisp_profiles_update_own
  on public.word_wisp_profiles for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

drop policy if exists word_wisp_admins_read_own on public.word_wisp_admins;
create policy word_wisp_admins_read_own
  on public.word_wisp_admins for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists word_wisp_settings_read_public on public.word_wisp_settings;
create policy word_wisp_settings_read_public
  on public.word_wisp_settings for select to anon, authenticated
  using (id = 1);

drop policy if exists word_wisp_settings_update_admin on public.word_wisp_settings;
create policy word_wisp_settings_update_admin
  on public.word_wisp_settings for update to authenticated
  using (
    exists (
      select 1 from public.word_wisp_admins a
      where a.user_id = (select auth.uid()) and a.is_admin
    )
  )
  with check (
    exists (
      select 1 from public.word_wisp_admins a
      where a.user_id = (select auth.uid()) and a.is_admin
    )
  );

create or replace function public.word_wisp_handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  chosen_name text;
begin
  chosen_name := nullif(btrim(new.raw_user_meta_data ->> 'display_name'), '');
  if chosen_name is null or not public.word_wisp_name_is_allowed(chosen_name) then
    chosen_name := 'Explorer';
  end if;

  insert into public.word_wisp_profiles (user_id, display_name)
  values (new.id, chosen_name)
  on conflict (user_id) do nothing;
  return new;
end;
$$;

revoke all on function public.word_wisp_handle_new_user() from public, anon, authenticated;
drop trigger if exists word_wisp_on_auth_user_created on auth.users;
create trigger word_wisp_on_auth_user_created
  after insert on auth.users
  for each row execute function public.word_wisp_handle_new_user();
