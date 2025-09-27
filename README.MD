# Sudomatic 5000

***Turning realms into real users, one sudo at a time.***

Sync OIDC users from **Proxmox VE** into real **Linux** accounts: create local users, set a random (expired) password, manage groups/sudoers idempotently, and handle removals (lock → delete after 24h). Logs live at `/var/log/sudomatic5000/thelog.log`. Safe-by-default: reserved accounts are never touched, binaries are pinned, and runs are lockfile-protected.

---
Here’s an updated **Casual Cyber Warning** block with the checksum bit baked in:

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
