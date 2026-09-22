-- Throttle Tribe UK — members area schema
--
-- STATUS: draft. Not yet run against a live project (no Supabase project exists yet).
-- Run in the Supabase SQL editor once the project is created, then re-test.
--
-- Security model: every private table has RLS enabled with NO permissive default.
-- Unauthenticated requests return zero rows because no policy matches them —
-- the data is never sent, rather than hidden by the frontend.

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
create type member_role as enum ('admin', 'member', 'road_captain', 'ride_leader', 'marshal');
create type member_status as enum ('active', 'suspended', 'removed');

-- ---------------------------------------------------------------------------
-- Members. One row per person who accepted an invitation.
-- Authentication lives in auth.users; membership lives here. A Google account
-- with no row in this table has no access to anything.
-- ---------------------------------------------------------------------------
create table members (
  id            uuid primary key references auth.users(id) on delete cascade,
  full_name     text not null,
  email         text not null,
  mobile        text,
  town          text,
  bike_make     text,
  bike_model    text,
  engine_cc     text,
  licence_type  text,
  years_riding  text,
  instagram     text,
  photo_url     text,
  role          member_role   not null default 'member',
  status        member_status not null default 'active',
  joined_at     timestamptz   not null default now()
);

-- Emergency contacts kept separate so ordinary members can never read them,
-- even though they can read the rest of a member's profile.
create table member_emergency_contacts (
  member_id  uuid primary key references members(id) on delete cascade,
  name       text,
  phone      text,
  relation   text
);

-- ---------------------------------------------------------------------------
-- Helper functions. security definer so they can read members under RLS.
-- ---------------------------------------------------------------------------
create or replace function is_active_member() returns boolean
  language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from members
    where id = auth.uid() and status = 'active'
  );
$$;

create or replace function is_admin() returns boolean
  language sql security definer stable set search_path = public as $$
  select exists (
    select 1 from members
    where id = auth.uid() and role = 'admin' and status = 'active'
  );
$$;

-- ---------------------------------------------------------------------------
-- Rides. `is_public` lets the admin surface a past ride on the public site;
-- everything else is members-only.
-- ---------------------------------------------------------------------------
create table rides (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  tag           text,
  summary       text,          -- safe for public display
  description   text,          -- members only
  ride_date     date,
  meet_time     time,
  meet_point    text,
  destination   text,
  route_notes   text,
  maps_url      text,
  gpx_url       text,
  distance      text,
  duration      text,
  fuel_stops    text,
  food_stops    text,
  hotel_details text,
  ferry_details text,
  ride_leader   text,
  instructions  text,
  difficulty    text,
  is_public     boolean not null default false,
  is_cancelled  boolean not null default false,
  created_at    timestamptz not null default now()
);

create type rsvp_state as enum ('riding', 'maybe', 'not_riding');

create table rsvps (
  ride_id    uuid references rides(id) on delete cascade,
  member_id  uuid references members(id) on delete cascade,
  state      rsvp_state not null,
  updated_at timestamptz not null default now(),
  primary key (ride_id, member_id)
);

-- ---------------------------------------------------------------------------
-- Invitations. Single-use, expiring, revocable.
-- token_hash stores a hash, never the raw token, so a database leak does not
-- hand over usable invitation links.
-- ---------------------------------------------------------------------------
create type invite_status as enum ('pending', 'accepted', 'expired', 'revoked');

create table invitations (
  id           uuid primary key default gen_random_uuid(),
  token_hash   text unique not null,
  rider_name   text not null,
  email        text,
  mobile       text,
  message      text,
  status       invite_status not null default 'pending',
  expires_at   timestamptz not null default (now() + interval '24 hours'),
  created_by   uuid references members(id),
  created_at   timestamptz not null default now(),
  accepted_by  uuid references members(id),
  accepted_at  timestamptz
);

create table admin_audit_log (
  id         bigserial primary key,
  actor_id   uuid references members(id),
  action     text not null,
  detail     jsonb,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Row level security
-- ---------------------------------------------------------------------------
alter table members                   enable row level security;
alter table member_emergency_contacts enable row level security;
alter table rides                     enable row level security;
alter table rsvps                     enable row level security;
alter table invitations               enable row level security;
alter table admin_audit_log           enable row level security;

-- Members: active members see each other; you may edit only yourself; admin edits anyone.
create policy members_read   on members for select using (is_active_member());
create policy members_self   on members for update using (id = auth.uid());
create policy members_admin  on members for all    using (is_admin()) with check (is_admin());

-- Emergency contacts: yourself, or an admin. Never other members.
create policy emg_own   on member_emergency_contacts for all using (member_id = auth.uid());
create policy emg_admin on member_emergency_contacts for all using (is_admin()) with check (is_admin());

-- Rides: members see all; anonymous visitors see ONLY rides explicitly marked public.
create policy rides_member on rides for select using (is_active_member());
create policy rides_public on rides for select using (is_public = true);
create policy rides_admin  on rides for all    using (is_admin()) with check (is_admin());

-- RSVPs: members see who is riding; you may only write your own.
create policy rsvp_read  on rsvps for select using (is_active_member());
create policy rsvp_write on rsvps for all    using (member_id = auth.uid()) with check (member_id = auth.uid());

-- Invitations and audit log: admin only. Token validation happens in an Edge
-- Function using the service role, so invitees never query this table directly.
create policy invites_admin on invitations     for all using (is_admin()) with check (is_admin());
create policy audit_admin   on admin_audit_log for select using (is_admin());

-- ---------------------------------------------------------------------------
-- Table privileges.
--
-- RLS decides WHICH ROWS a role may touch, but the role must also hold the
-- table privilege at all. Both are required: a missing GRANT means no access
-- regardless of policy, and a GRANT without a matching policy still returns
-- nothing. Anonymous visitors are granted select on `rides` only, and even
-- there the rides_public policy limits them to rides marked public.
-- ---------------------------------------------------------------------------
grant usage on schema public to anon, authenticated;

grant select                         on rides   to anon;
grant select, insert, update, delete on rides   to authenticated;
grant select, update                 on members to authenticated;
grant select, insert, update, delete on rsvps   to authenticated;
grant select, insert, update, delete on member_emergency_contacts to authenticated;
grant select, insert, update, delete on invitations to authenticated;
grant select                         on admin_audit_log to authenticated;
grant insert                         on admin_audit_log to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- Anonymous visitors get nothing else, explicitly.
revoke all on members                   from anon;
revoke all on member_emergency_contacts from anon;
revoke all on rsvps                     from anon;
revoke all on invitations               from anon;
revoke all on admin_audit_log           from anon;

-- ---------------------------------------------------------------------------
-- Designated administrator
--
-- Promotes throttletribe.uk@gmail.com to admin the first time that account
-- signs in with Google. Every later admin is granted from the dashboard.
-- ---------------------------------------------------------------------------
create or replace function handle_new_user() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if new.email = 'throttletribe.uk@gmail.com' then
    insert into members (id, full_name, email, role, status)
    values (new.id, 'Throttle Tribe Admin', new.email, 'admin', 'active')
    on conflict (id) do update set role = 'admin', status = 'active';
  end if;
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();
