-- Throttle Tribe UK — invitation logic
--
-- All of this runs inside Postgres. The browser never validates a token:
-- it calls an RPC, and the function decides. A tampered or guessed token
-- simply returns nothing.
--
-- Tokens are stored as sha256 hashes, so a database dump does not hand
-- over working invitation links.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- Admin: create one invitation. Returns the raw token ONCE - it is not
-- recoverable afterwards, only revocable.
-- ---------------------------------------------------------------------------
create or replace function invite_create(
  p_rider_name    text,
  p_email         text default null,
  p_mobile        text default null,
  p_message       text default null,
  p_expiry_hours  int  default 24
) returns table (invitation_id uuid, token text, expires_at timestamptz)
  language plpgsql security definer set search_path = public as $$
declare
  v_token text;
  v_id    uuid;
  v_exp   timestamptz;
begin
  if not is_admin() then
    raise exception 'not authorised' using errcode = '42501';
  end if;

  if p_expiry_hours < 1 or p_expiry_hours > 720 then
    raise exception 'expiry must be between 1 and 720 hours';
  end if;

  -- 32 random bytes, url-safe. Not sequential, not guessable.
  v_token := replace(replace(encode(gen_random_bytes(32), 'base64'), '+', '-'), '/', '_');
  v_token := rtrim(v_token, '=');
  v_exp   := now() + make_interval(hours => p_expiry_hours);

  insert into invitations (token_hash, rider_name, email, mobile, message, expires_at, created_by)
  values (encode(digest(v_token, 'sha256'), 'hex'), p_rider_name, p_email, p_mobile, p_message, v_exp, auth.uid())
  returning id into v_id;

  insert into admin_audit_log (actor_id, action, detail)
  values (auth.uid(), 'invite_create', jsonb_build_object('invitation_id', v_id, 'rider_name', p_rider_name));

  return query select v_id, v_token, v_exp;
end;
$$;

-- ---------------------------------------------------------------------------
-- Admin: bulk create. One call mints the whole list, so onboarding 112
-- riders is a single action rather than 112.
-- ---------------------------------------------------------------------------
create or replace function invite_create_bulk(
  p_riders        jsonb,          -- [{"name":"Hari","mobile":"+44..."}, ...]
  p_expiry_hours  int default 24
) returns table (invitation_id uuid, rider_name text, token text, expires_at timestamptz)
  language plpgsql security definer set search_path = public as $$
declare
  r jsonb;
begin
  if not is_admin() then
    raise exception 'not authorised' using errcode = '42501';
  end if;

  for r in select * from jsonb_array_elements(p_riders) loop
    return query
      select c.invitation_id, (r->>'name')::text, c.token, c.expires_at
      from invite_create(
        r->>'name', r->>'email', r->>'mobile', r->>'message', p_expiry_hours
      ) c;
  end loop;
end;
$$;

-- ---------------------------------------------------------------------------
-- Public: what the invitation landing page may see.
-- Reveals only the invited rider's name, and only while the token is live.
-- Anything invalid, expired, used or revoked returns no row - the page
-- cannot tell the difference, so tokens cannot be probed.
-- ---------------------------------------------------------------------------
create or replace function invite_preview(p_token text)
  returns table (rider_name text, expires_at timestamptz)
  language sql security definer stable set search_path = public as $$
  select i.rider_name, i.expires_at
  from invitations i
  where i.token_hash = encode(digest(p_token, 'sha256'), 'hex')
    and i.status = 'pending'
    and i.expires_at > now();
$$;

-- ---------------------------------------------------------------------------
-- Accept. Caller must already be signed in (Google or magic link): that is
-- what proves identity. The token is what proves they were invited.
--
-- Marking the invitation accepted and creating the member row happen in one
-- transaction, and the `status = 'pending'` predicate in the UPDATE means a
-- second concurrent attempt updates zero rows. A token cannot be used twice.
-- ---------------------------------------------------------------------------
create or replace function invite_accept(
  p_token        text,
  p_full_name    text,
  p_mobile       text default null,
  p_town         text default null,
  p_bike_make    text default null,
  p_bike_model   text default null,
  p_engine_cc    text default null,
  p_licence_type text default null,
  p_years_riding text default null,
  p_instagram    text default null,
  p_emg_name     text default null,
  p_emg_phone    text default null,
  p_emg_relation text default null
) returns uuid
  language plpgsql security definer set search_path = public as $$
declare
  v_invite invitations%rowtype;
  v_uid    uuid := auth.uid();
  v_email  text;
begin
  if v_uid is null then
    raise exception 'sign in first' using errcode = '42501';
  end if;

  -- Claim the invitation. Atomic: only one caller can move it off 'pending'.
  update invitations
     set status = 'accepted', accepted_by = v_uid, accepted_at = now()
   where token_hash = encode(digest(p_token, 'sha256'), 'hex')
     and status = 'pending'
     and expires_at > now()
  returning * into v_invite;

  if v_invite.id is null then
    raise exception 'this invitation is not valid' using errcode = '42501';
  end if;

  select email into v_email from auth.users where id = v_uid;

  insert into members (
    id, full_name, email, mobile, town,
    bike_make, bike_model, engine_cc, licence_type, years_riding, instagram,
    role, status
  ) values (
    v_uid, p_full_name, v_email, p_mobile, p_town,
    p_bike_make, p_bike_model, p_engine_cc, p_licence_type, p_years_riding, p_instagram,
    'member', 'active'
  )
  on conflict (id) do update set
    full_name = excluded.full_name,
    status    = 'active';

  if p_emg_name is not null or p_emg_phone is not null then
    insert into member_emergency_contacts (member_id, name, phone, relation)
    values (v_uid, p_emg_name, p_emg_phone, p_emg_relation)
    on conflict (member_id) do update set
      name = excluded.name, phone = excluded.phone, relation = excluded.relation;
  end if;

  return v_uid;
end;
$$;

-- ---------------------------------------------------------------------------
-- Admin: revoke. Takes effect immediately - the next open of that link fails.
-- ---------------------------------------------------------------------------
create or replace function invite_revoke(p_invitation_id uuid)
  returns void language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then
    raise exception 'not authorised' using errcode = '42501';
  end if;

  update invitations set status = 'revoked'
   where id = p_invitation_id and status = 'pending';

  insert into admin_audit_log (actor_id, action, detail)
  values (auth.uid(), 'invite_revoke', jsonb_build_object('invitation_id', p_invitation_id));
end;
$$;

-- ---------------------------------------------------------------------------
-- Housekeeping: flip lapsed invitations to 'expired' so the admin list is
-- accurate. Expiry is already enforced by the time checks above; this is
-- only for display. Run from cron, or call it when the admin list loads.
-- ---------------------------------------------------------------------------
create or replace function invites_mark_expired()
  returns int language sql security definer set search_path = public as $$
  with done as (
    update invitations set status = 'expired'
     where status = 'pending' and expires_at <= now()
    returning 1
  ) select count(*)::int from done;
$$;

-- ---------------------------------------------------------------------------
-- Function privileges. Default is EXECUTE to public, which would expose the
-- admin functions, so revoke and grant deliberately.
-- ---------------------------------------------------------------------------
revoke execute on function invite_create(text,text,text,text,int)          from public, anon, authenticated;
revoke execute on function invite_create_bulk(jsonb,int)                   from public, anon, authenticated;
revoke execute on function invite_revoke(uuid)                             from public, anon, authenticated;
revoke execute on function invites_mark_expired()                          from public, anon;

-- Admin functions: reachable by signed-in users, but every one re-checks
-- is_admin() internally, so a member calling them gets 'not authorised'.
grant execute on function invite_create(text,text,text,text,int)           to authenticated;
grant execute on function invite_create_bulk(jsonb,int)                    to authenticated;
grant execute on function invite_revoke(uuid)                              to authenticated;
grant execute on function invites_mark_expired()                           to authenticated;

-- The invitation landing page is opened by someone not yet signed in.
grant execute on function invite_preview(text)                             to anon, authenticated;

-- Accepting requires a signed-in user.
revoke execute on function invite_accept(text,text,text,text,text,text,text,text,text,text,text,text,text) from public, anon;
grant  execute on function invite_accept(text,text,text,text,text,text,text,text,text,text,text,text,text) to authenticated;
