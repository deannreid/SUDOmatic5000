# Sudomatic 5000

***Turning realms into real users, one sudo at a time.***

Sync OIDC users from **Proxmox VE** into real **Linux** accounts: create local users, set a random (expired) password, manage groups/sudoers idempotently, and handle removals (lock → delete after 24h). Logs live at `/var/log/sudomatic5000/thelog.log`. Safe-by-default: reserved accounts are never touched, binaries are pinned, and runs are lockfile-protected.

---
## ⚠️ Casual Cyber Warning

> **This script will refuse to start unless it’s `root:root` and `0700`.**
> That’s intentional—so nobody can swap it and mint sudo. The service also uses an **ExecCondition checksum guard**: `/usr/local/sbin/sudomatic_check.sh` verifies the **SHA-256** of `/usr/local/sbin/sudomatic5000.py` captured at install/update.
> **If the file changes on disk, the checksum fails and the service will not run.**
>
> **Before enabling the service or timer, enforce correct ownership and permissions:**
>
> ```bash
> sudo chown root:root /usr/local/sbin/sudomatic5000.py /usr/local/sbin/sudomatic_check.sh
> sudo chmod 700        /usr/local/sbin/sudomatic5000.py /usr/local/sbin/sudomatic_check.sh
> sudo install -d -m 0750 -o root -g root /var/log/sudomatic5000
> sudo install -d -m 0750 -o root -g root /var/lib/sudomatic5000
> ```
>
> **Service must run as root** and paths must not be world-writable. Never place the script in user-writable locations (`/tmp`, `$HOME`, shared mounts, etc.).
>
> **Need to change the code?** Do **not** edit the installed file directly. Update from your repo and let the installer refresh the checksum:
>
> ```bash
> # replace sudomatic5000.py in your repo working dir, then:
> sudo ./installer.py update --restart
> ```
>
> If ownership, permissions, or checksum don’t match, the script **actively exits** to prevent privilege-escalation via file tampering.

---

## Quick start


### What you must grant (permissions)

### Application (app-only, used by Sudomatic service)

> These are **required** for the client-credentials flow the service uses.

* **GroupMember.Read.All** *(Application)* — **required** to list group members
* **User.Read.All** *(Application)* — **required** to read `userPrincipalName` / `mail`
* *(Optional, only if your group uses hidden membership)* **Member.Read.Hidden** *(Application)*

### Delegated (optional; only if you want user sign-in flows)

> Not used by the Sudomatic service. Helpful if you test with your own user token or build UI flows.

* **email**, **openid**, **profile** *(Delegated)* — needed if you want users to sign in interactively (e.g., web/app auth)
* *(Optional for debugging)* **GroupMember.Read.All** *(Delegated)* — lets your **personal** token read memberships in Graph Explorer/Azure CLI

---

## Portal steps (quick)

1. **Register the app**
   Entra ID → **App registrations** → **New registration** → Name: `Sudomatic 5000` → Single tenant → **Register**

2. **Create a client secret**
   App → **Certificates & secrets** → **New client secret** → copy the **Value**

3. **Add Application permissions**
   App → **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**
   Add:

   * `GroupMember.Read.All`
   * `User.Read.All`
   * *(Optional)* `Member.Read.Hidden`
     Click **Grant admin consent**.

4. **Collect IDs**

   * **Tenant ID** (Directory ID)
   * **Application (client) ID**
   * **Group Object ID** for the group you want to enforce

---

## Plug creds into the service (two ways)

### A) Edit the systemd service env

```bash
sudo systemctl edit sudomatic.service
```

Add under `[Service]`:

```ini
[Service]
Environment=ENTR_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Environment=ENTR_CLNT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
Environment=ENTR_CLNT_SEC=your-super-secret
Environment=ENTR_SUPERUSR_ID=75a68561-7a39-4eef-9a59-d9666d7533b3
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart sudomatic.service
```

### B) **Re-run the installer** (it will write/update the service env for you)

```bash
# First-time installation (deploys script, checker, service, and timer)
sudo ./installer.py install

# Updating later
sudo ./installer.py update
sudo ./installer.py update --restart   # optional auto-restart
```

> Either approach is fine. If you used A) earlier and swap to B), the installer will overwrite with whatever you provide there.

---

## Sanity check (app token path the service uses)

```bash
TENANT="$ENTR_TENANT_ID"
CLIENT="$ENTR_CLNT_ID"
SECRET="$ENTR_CLNT_SEC"

ACCESS_TOKEN=$(curl -sS -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT" \
  -d "client_secret=$SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default" \
  | jq -r .access_token)

GROUP_ID="$ENTR_SUPERUSR_ID"
curl -sS -H "Authorization: Bearer $ACCESS_TOKEN" -H "Accept: application/json" \
  "https://graph.microsoft.com/v1.0/groups/$GROUP_ID/members/microsoft.graph.user?\$select=id,displayName,userPrincipalName&\$top=999" \
| jq -r '.value[] | select(.userPrincipalName!=null) | .userPrincipalName'
```

* If you get **403 Authorization_RequestDenied** → admin consent or permissions missing.
* If UPNs are **null** → add **User.Read.All (Application)** and consent.
* Hidden membership group? Add **Member.Read.Hidden (Application)** and consent.

---

## Logs & behavior

```bash
journalctl -u sudomatic.service -f
```

* If Graph fails or perms are wrong, Sudomatic **fails open**: it logs a **warning** and **does not** add/remove/lock users for that run (relies on Proxmox only).
* When permissions are correct, you’ll see:
  `Graph: group '...' members fetched (STRICT UPN): kept=N, ...`

That’s it—grant the **Application** roles, plug env into the service (or re-run the installer), and Sudomatic 5000 will sync exactly the group’s **userPrincipalName** members.



### Application Install
```bash
# First-time install (deploys script, env file, checker, service & timer)
sudo ./installer.py install

# Logs
journalctl -u sudomatic.service -n 200 --no-pager

# Update the installed script (idempotent)
sudo ./installer.py update
sudo ./installer.py update --restart   # update + restart service

# Uninstall everything the installer created
sudo ./installer.py uninstall
```

---

## Configuration (env-first)

Sudomatic is **env-driven** at runtime. The installer writes `/etc/sudomatic5000.env`, and the systemd service loads it via `EnvironmentFile=`. Anything set there **overrides** the in-code defaults.

**Edit:**

```bash
sudoedit /etc/sudomatic5000.env
sudo systemctl daemon-reload
sudo systemctl restart sudomatic.service
```

### Minimal env example

```ini
# --- Core ---
REALM='MY-REALM'                   # Must match Proxmox exactly
DEFAULT_SHELL='/bin/bash'
EXTRA_GROUPS='sudo'                # space or comma separated; empty = none
GRANT_SUDO='true'                  # true|false
SUDO_NOPASSWD='false'              # true|false
ALLOWED_UPN_DOMAINS='example.com sub.example.com'   # empty = allow all

# --- Microsoft Graph enforcement (optional) ---
GRAPH_ENFORCE='true'               # intersect with group members (strict UPN)
GRAPH_FAIL_OPEN='true'             # on Graph error: make no user changes
ENTR_SUPERUSR_ID='00000000-0000-0000-0000-000000000000'

# App-only token (recommended for service)
ENTR_TENANT_ID='tenant-guid'
ENTR_CLNT_ID='app-client-guid'
ENTR_CLNT_SEC='super-secret'

# OR delegated test token (short-lived; not for timers)
# GRAPH_ACCESS_TOKEN='eyJ0eXAiOiJKV1Qi…'
```

> The **“Tweakers”** block in `sudomatic5000.py` still exists, but serves as **fallback defaults**. Env wins at runtime.

---

## What each knob does (quick)

* `REALM` — Proxmox realm name (must match PVE or nothing syncs).
* `DEFAULT_SHELL` — shell for new users.
* `EXTRA_GROUPS` — extra groups to add; empty to skip.
* `GRANT_SUDO` / `SUDO_NOPASSWD` — per-user sudoers in `/etc/sudoers.d` (validated with `visudo -cf`).
* `ALLOWED_UPN_DOMAINS` — only accept UPNs from these domains (empty = allow all).
* `GRAPH_ENFORCE` — require membership in `ENTR_SUPERUSR_ID` (strict UPN) **and** presence in PVE realm.
* `GRAPH_FAIL_OPEN` — if Graph errors, don’t disable/delete anyone this run.
* `ENTR_TENANT_ID`, `ENTR_CLNT_ID`, `ENTR_CLNT_SEC` — app-only auth for Graph; preferred for the timer.
* `GRAPH_ACCESS_TOKEN` — delegated bearer for quick testing (short-lived).

**Permissions (Entra → App Registration → API permissions → Application):**

* `GroupMember.Read.All` (required)
* `User.Read.All` (required)
* `Member.Read.Hidden` (only if the group hides membership)
* For delegated testing: add `email`, `openid`, `profile` (Delegated)

> Current release note: **Graph enforcement is safe and fail-open**, but user disable/delete still relies on removal from **PVE** realm while Graph support matures.

---

## How it behaves

* **Create** missing users (from PVE realm ∩ Graph group if enabled), set random password, **expire** it.
* **Idempotent** group add & sudoers update.
* **Leavers**: if a user disappears from desired set → **lock** immediately → **delete** after `DELETE_AFTER`.
* **Never touches** `RESERVED_USERS` (root, www-data, etc).
* **Binary pinning**: uses exact paths (defense-in-depth).
* **Lockfile**: prevents overlapping runs.
* **Logs**: `/var/log/sudomatic5000/thelog.log` (installer can drop a logrotate file).

---

## Troubleshooting (rapid-fire)

* **No users found**: check `REALM` spelling, and that users actually exist in PVE (`pvesh get /access/users`).
* **Graph shows 403**: ensure Application perms (`GroupMember.Read.All`, `User.Read.All`) and Admin consent granted.
* **Everyone filtered**: set `ALLOWED_UPN_DOMAINS` to your tenant’s UPN suffix(es) or leave empty.
* **Sudo not granted**: script must be `root:root 0700`; the built-in security gate refuses to create sudoers otherwise.
* **Service not seeing env**: `systemctl show sudomatic.service -p EnvironmentFiles -p Environment`.

---

## Uninstall

```bash
sudo ./installer.py uninstall
# removes: service + timer + checker + script + env file (keeps logs/state)
```

Enjoy the realm wrangling 🧙‍♂️
