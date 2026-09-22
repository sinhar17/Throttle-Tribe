# Throttle Tribe — members-area backend

Self-hosted on the Proxmox box. The public site stays on GitHub Pages and
calls this API for anything private.

**Status: not yet run.** These files have never been executed against a live
Docker host. Expect to fix things on first boot — the notes under
*Known unknowns* flag where problems are most likely.

---

## Why it is shaped this way

The public site is static, so it cannot keep a secret. Every private thing
therefore lives here, behind Postgres row level security: an unauthenticated
request returns **zero rows**, rather than rows the frontend then hides.

`cloudflared` makes an **outbound** connection to Cloudflare. No router ports
are opened, and `api.throttletribe.uk` resolves to Cloudflare rather than to
your home IP — which matters, because publishing your home address would be a
worse leak than the ride meeting points this whole exercise is meant to protect.

```
Browser ──▶ throttletribe.uk        (GitHub Pages, public, no private data)
   │
   └──────▶ api.throttletribe.uk    (Cloudflare edge)
                  │
                  ▼  outbound tunnel, no open ports
            Proxmox LXC / VM
              ├── caddy      routing, CORS, noindex headers
              ├── gotrue     Google sign-in + magic links
              ├── postgrest  REST API, enforces RLS per request
              └── postgres   members, rides, invitations
```

---

## Setup

### 1. Container on Proxmox

An LXC with **4GB RAM, 2 vCPU, 20GB disk** is enough. Debian 12 is fine.
If using LXC rather than a VM, it must be **privileged** or have nesting
enabled, or Docker will not start.

Install Docker, then:

```bash
mkdir -p /opt/throttle-tribe && cd /opt/throttle-tribe
# copy this _backend directory here
```

### 2. Secrets

```bash
cp .env.example .env
openssl rand -base64 48   # -> POSTGRES_PASSWORD
openssl rand -base64 48   # -> JWT_SECRET
chmod 600 .env
```

`.env` must never be committed. The repo ignores it, but check before pushing.

### 3. Google sign-in

Google Cloud Console → APIs & Services → Credentials → **Create OAuth client
ID** → Web application. Authorised redirect URI, exactly:

```
https://api.throttletribe.uk/auth/v1/callback
```

Put the client ID and secret in `.env`.

### 4. Cloudflare Tunnel

Cloudflare Zero Trust → Networks → Tunnels → **Create a tunnel** → Docker.
Copy the token into `CLOUDFLARE_TUNNEL_TOKEN`.

Add a public hostname on the tunnel:

| Field | Value |
|---|---|
| Subdomain | `api` |
| Domain | `throttletribe.uk` |
| Service | `http://gateway:8080` |

`throttletribe.uk` itself stays pointed at GitHub Pages — do not change the
existing A records or the `www` CNAME. Only `api` goes through the tunnel.

### 5. Start, then apply the schema

```bash
docker compose up -d
docker compose logs -f db      # wait for "database system is ready"
```

PostgREST connects as `authenticator`, so give that role the password first:

```bash
docker compose exec db psql -U postgres -d throttletribe -c \
  "alter role authenticator with password '<POSTGRES_PASSWORD>';"
```

Then apply the migrations, in order, checking each for errors:

```bash
docker compose exec db psql -U postgres -d throttletribe -v ON_ERROR_STOP=1 -f /migrations/01-schema.sql
docker compose exec db psql -U postgres -d throttletribe -v ON_ERROR_STOP=1 -f /migrations/02-invitations.sql
docker compose restart rest
```

### 6. Become admin

Sign in once at the site with **throttletribe.uk@gmail.com** via Google. A
trigger promotes that account to `admin`. Confirm:

```bash
docker compose exec db psql -U postgres -d throttletribe -c \
  "select email, role, status from members;"
```

---

## Verify it is actually private

Run these **before** putting real ride data in. Each must return an empty
result or an error — never data.

```bash
API=https://api.throttletribe.uk

# 1. Anonymous cannot read members
curl -s "$API/rest/v1/members?select=*"

# 2. Anonymous cannot read private rides
curl -s "$API/rest/v1/rides?select=*&is_public=eq.false"

# 3. Anonymous cannot read invitations
curl -s "$API/rest/v1/invitations?select=*"

# 4. Anonymous cannot read emergency contacts
curl -s "$API/rest/v1/member_emergency_contacts?select=*"

# 5. A guessed invitation token reveals nothing
curl -s -X POST "$API/rest/v1/rpc/invite_preview" \
     -H 'Content-Type: application/json' -d '{"p_token":"guessed"}'

# 6. Anonymous cannot mint invitations
curl -s -X POST "$API/rest/v1/rpc/invite_create" \
     -H 'Content-Type: application/json' -d '{"p_rider_name":"attacker"}'

# 7. Members area is not indexable
curl -sI "$API/rest/v1/rides" | grep -i x-robots-tag
```

Repeat 1–4 with a **member's** token to confirm a member cannot reach
`invitations`, `admin_audit_log` or anyone else's emergency contact.

---

## Backups

The whole thing is one Postgres volume.

```bash
docker compose exec -T db pg_dump -U postgres throttletribe | gzip > tribe-$(date +%F).sql.gz
```

Put that on a cron and keep copies **off** the Proxmox box. A backup on the
same machine does not survive the failure you are backing up against.

Test a restore before you rely on it — an untested backup is a guess.

---

## Known unknowns

Things most likely to need fixing on first run:

1. **`authenticator` role password** — step 5 assumes the role exists in the
   `supabase/postgres` image and just needs a password. If PostgREST logs
   auth failures, check whether the role exists at all.
2. **`anon` / `authenticated` roles** — assumed present from the image. If
   the grants in `01-schema.sql` fail with "role does not exist", they need
   creating first.
3. **`auth.uid()`** — assumed provided by the image. If not, it must be
   defined to read `request.jwt.claims`, or every policy will fail closed
   (denying everyone, including you).
4. **Image tags** are pinned to specific versions that may need bumping.
5. **GoTrue signup** is left enabled because it is what creates the auth user
   during invitation acceptance. Membership is gated separately by the invite
   token, so a stranger signing in with Google gets an account with **no**
   members row and therefore no access. Worth re-testing after any GoTrue
   upgrade — verify with check 1 above while signed in as a non-member.
