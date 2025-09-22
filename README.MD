# Sudomatic 5000

***Turning realms into real users, one sudo at a time.***

Sync OIDC users from **Proxmox VE** into real **Linux** accounts: create local users, set a random (expired) password, manage groups/sudoers idempotently, and handle removals (lock → delete after 24h). Logs live at `/var/log/sudomatic5000/thelog.log`. Safe-by-default: reserved accounts are never touched, binaries are pinned, and runs are lockfile-protected.

---
## ⚠️ Casual Cyber Warning.
> **This script will refuse to start unless the file is owned by `root:root` and has permissions `0700`.** 
> That’s intentional, don't remove this code from the script: when run automatically, a misconfigured copy of this script could let **anyone** drop/modify it and thereby create **full sudo accounts** on the box.
>
> **Before enabling the service or timer, enforce correct ownership and permissions:**
>
> ```bash
> sudo chown root:root /usr/local/sbin/sudomatic5000.py
> sudo chown root:root /usr/local/sbin/sudomatic_check.sh
>
> sudo chmod 700 /usr/local/sbin/sudomatic5000.py
> sudo chmod 700 /usr/local/sbin/sudomatic_check.sh
> ```
>
> **Also ensure the service runs as root and paths aren’t world-writable:**
>
> * systemd unit must specify `User=root`
> * log dir: `sudo install -d -m 0750 -o root -g root /var/log/sudomatic5000`
> * state dir: `sudo install -d -m 0750 -o root -g root /var/lib/sudomatic5000`
> * never place the script in user-writable locations (`/tmp`, `$HOME`, shared mounts, etc.)
>
> If ownership/permissions don’t match, the script **actively exits** to prevent privilege-escalation via file tampering.

---

## Quick start

```bash
# First-time installation (deploys script, checker, service, and timer)
sudo ./installer.py install

# View service logs
journalctl -u sudomatic.service

# --- Updating later ---

# Replace sudomatic5000.py in this directory, then run:
sudo ./installer.py update

# Optionally restart the service automatically after updating:
sudo ./installer.py update --restart
```

---

## Configure (Tweakers)

Paste/adjust these at the top of the script:

```python
# --- Tweakers ---
REALM = "SSOREALMNAME-HERE"         # Must match the Proxmox realm name exactly.
DEFAULT_SHELL = "/bin/bash"

EXTRA_GROUPS = ["sudo"]             # Supplementary groups (set [] if you only want sudoers files created)
GRANT_SUDO = True                   # Per-user sudoers in /etc/sudoers.d - False only creates the user
SUDO_NOPASSWD = False               # Keep False to require a password for sudo

LOG_FILE = "/var/log/sudomatic5000/thelog.log"
STATE_DIR = "/var/lib/sudomatic5000/pve_oidc_sync"
STATE_PATH = os.path.join(STATE_DIR, "state.json")
LOCK_PATH  = os.path.join(STATE_DIR, ".lock")
MANAGED_SUDOERS_PREFIX = "/etc/sudoers.d/pve_realm-"

DELETE_AFTER = timedelta(hours=24)  # How long to keep an ex-realm user locked before deletion
PASSWORD_LENGTH = 38                # Random initial password length - Longer password means less cracking it, though its forced to reset on first login.

# Only allow these UPN domains from IdProvider.
ALLOWED_UPN_DOMAINS = {"",""}

# System/builtin users we will never manage (create/sudo/delete). Stand back pls.
RESERVED_USERS = {
    "root","daemon","bin","sys","sync","games","man","lp","mail","news",
    "uucp","proxy","www-data","backup","list","irc","gnats","nobody"
}

# --- Username mapping from UPN -> Unix ---
USERNAME_MODE = "useronly"          # "useronly" or "upn_concat"
USERNAME_SEPARATOR = "_"            # Only if using upn_concat
USERNAME_LOWERCASE = True
USERNAME_MAXLEN = 32

# Pin the binaries so shenanigans can't bite me
BIN = {
  "pvesh":    "/usr/bin/pvesh",
  "useradd":  "/usr/sbin/useradd",
  "usermod":  "/usr/sbin/usermod",
  "userdel":  "/usr/sbin/userdel",
  "passwd":   "/usr/bin/passwd",
  "chage":    "/usr/bin/chage",
  "chpasswd": "/usr/sbin/chpasswd",
  "visudo":   "/usr/sbin/visudo",
  "id":       "/usr/bin/id",
  "getent":   "/usr/bin/getent",
}

# --- Microsoft Graph enforcement (client credentials via env vars) --- --- WORK IN PROGRESS NO WORKY
GRAPH_ENFORCE = True            # set False if I want to ignore Graph entirely
GRAPH_FAIL_OPEN = True          # if token/fetch fails: True = proceed without disabling extra users; False = fail closed (treat as no members)
GRAPH_GROUP_ID = "ENTRAGROUPID"  # the group I care about
GRAPH_TIMEOUT = 8               # seconds

# Token via either a pre-baked access token or client creds in env (client credentials flow)
ENV_GRAPH_ACCESS_TOKEN = "GRAPH_ACCESS_TOKEN"

ENV_MS_TENANT_ID       = "MS_TENANT_ID"
ENV_MS_CLIENT_ID       = "MS_CLIENT_ID"
ENV_MS_CLIENT_SECRET   = "MS_CLIENT_SECRET"
```

---

## Help: what each knob does

### Core realm & shell

* `REALM` *(str)* — Your Proxmox OIDC realm **ID** (e.g., `AVGRP-SSO`). Must match PVE or nothing syncs.
* `DEFAULT_SHELL` *(str)* — Shell for newly created local users (e.g., `/bin/bash`, `/usr/bin/zsh`).

### Groups & sudo

* `EXTRA_GROUPS` *(list\[str])* — Supplementary groups to add (e.g., `["sudo"]`). Set `[]` to skip.
* `GRANT_SUDO` *(bool)* — If `True`, writes a **per-user** file in `/etc/sudoers.d` granting sudo.
* `SUDO_NOPASSWD` *(bool)* — If `True`, users can sudo without a password (`NOPASSWD:ALL`). Default `False` (safer).

> The sudoers filename is built from `MANAGED_SUDOERS_PREFIX` + `<username>`.

### Logging, state & locking

* `LOG_FILE` *(str)* — Where logs go. Ensure the directory exists and is writable by root.
* `STATE_DIR` *(str)* — Folder that holds script state (known/disabled users).
* `STATE_PATH` *(str)* — JSON file tracking known users and who’s in the 24h lock period.
* `LOCK_PATH` *(str)* — Advisory lockfile to prevent overlapping runs.

### Lifecycle & initial passwords

* `DELETE_AFTER` *(timedelta)* — How long an account stays **locked** before being **deleted** (home included).
* `PASSWORD_LENGTH` *(int)* — Length of the **random initial password**; it’s immediately **expired**. The password is never logged or stored.

### Identity filtering

* `ALLOWED_UPN_DOMAINS` *(set\[str])* — Only accept UPNs from these domains (defence-in-depth).
  **Example:** `{"example.com", "subsidiary.co.uk"}`
* `RESERVED_USERS` *(set\[str])* — Local accounts you **never** touch (create/sudo/delete). Keep system users here.

### Username mapping

* `USERNAME_MODE` *(str)* — How to convert UPN → Unix user:

  * `"useronly"` → `user@domain.com` ⇒ `user`
  * `"upn_concat"` → `user@domain.com` ⇒ `user_domain_com`
* `USERNAME_SEPARATOR` *(str)* — Used only with `upn_concat` (e.g., `"_"`).
* `USERNAME_LOWERCASE` *(bool)* — Force lowercase usernames (recommended).
* `USERNAME_MAXLEN` *(int)* — Truncate usernames to this length (Linux tools are happier ≤32).

### Pinned binaries

* `BIN` *(dict\[str,str])* — Exact paths to the tools we call as root. Adjust if your distro differs.
  **Tip:** if a path is wrong, the script logs `Missing required binary: key -> path`.

### Microsoft Graph (WIP)

* `GRAPH_ENFORCE` *(bool)* — Turn Graph checks on/off. **WIP:** does not delete on its own yet.
* `GRAPH_FAIL_OPEN` *(bool)* — If Graph is unreachable:

  * `True` = continue without disabling extra users (safe default)
  * `False` = treat as **no members** (hard lock)
* `GRAPH_GROUP_ID` *(str)* — Entra group ID whose **members** are allowed.
* `GRAPH_TIMEOUT` *(int)* — HTTP timeout for token/members fetch.
* `ENV_GRAPH_ACCESS_TOKEN` *(str)* — Env var name for a **ready** bearer token.
* `ENV_MS_TENANT_ID / ENV_MS_CLIENT_ID / ENV_MS_CLIENT_SECRET` *(str)* — Env var names for client-credentials flow (service principal).

> **Note:** In this version, the Entra API is **work in progress**. The script will only **Disable/Delete** users once they’re **manually removed in Proxmox** (realm). Keep Graph vars ready; enforcement will be wired as the feature matures.

---

## How it matches users (UPN → Unix)

* Proxmox user IDs look like `USER@DOMAIN.com@REALM`.
* The script splits on the **last** `@` → UPN + Realm.
* UPN → Unix via your `USERNAME_MODE`, sanitized to `[a-z0-9._-]`, truncated to `USERNAME_MAXLEN`.

---

## SSH & passwords

* On first creation a **random password** is set, then **expired** (`chage -d 0`).
* With SSH password auth disabled (recommended), the admin drops a key and the user runs `passwd` after first login to set their own password.
* The random password is **never printed or stored**.

---

## Logs & rotation

* Log file: `LOG_FILE` (default `/var/log/sudomatic5000/thelog.log`).
* Add a logrotate policy (example):

```conf
# /etc/logrotate.d/sudomatic5000
/var/log/sudomatic5000/thelog.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  create 0640 root root
}
```

---

## Troubleshooting

* **No desired users**: ensure at least one user has logged in via the OIDC realm so PVE lists `user@REALM`.

  ```bash
  pveum realm list
  pveum user list
  pvesh get /access/users --output-format json | jq -r '.[].userid'
  ```
* **Domain filter blocked everyone**: set `ALLOWED_UPN_DOMAINS` to match your tenant UPN suffix(es).
* **Sudo too broad**: set `GRANT_SUDO=False` or gate by your own allow-list logic in code.
* **Binary missing**: fix the path in `BIN[...]` for your distro.

---


## Test Output

```python
2025-09-22 09:00:12,104 INFO ---- Script start ----
2025-09-22 09:00:12,406 WARNING Graph enforcement skipped: token unavailable (fail-open)
2025-09-22 09:00:12,407 INFO Realm 'SSOREALMNAME-HERE' desired users (post-Graph): ['dean', 'opsadmin', 'root']
2025-09-22 09:00:12,407 WARNING Refusing to manage reserved username: root
2025-09-22 09:00:12,612 INFO Created local user: dean
2025-09-22 09:00:12,794 INFO Added dean to groups ['sudo']
2025-09-22 09:00:12,986 INFO Updated sudoers for dean at /etc/sudoers.d/pve_realm-dean
2025-09-22 09:00:13,173 INFO Initial password set and expired for dean (not stored)
2025-09-22 09:00:13,421 INFO Created local user: opsadmin
2025-09-22 09:00:13,603 INFO Added opsadmin to groups ['sudo']
2025-09-22 09:00:13,812 INFO Updated sudoers for opsadmin at /etc/sudoers.d/pve_realm-opsadmin
2025-09-22 09:00:14,005 INFO Initial password set and expired for opsadmin (not stored)
2025-09-22 09:00:14,256 INFO Sync complete. Known=2, Desired=2, Disabled=0


2025-09-22 10:30:07,019 INFO ---- Script start ----
2025-09-22 10:30:07,271 WARNING Graph enforcement skipped: token unavailable (fail-open)
2025-09-22 10:30:07,272 INFO Realm 'SSOREALMNAME-HERE' desired users (post-Graph): ['dean']
2025-09-22 10:30:07,563 INFO User opsadmin removed by Graph/PVE; locked and marked for deletion in 1 day, 0:00:00
2025-09-22 10:30:07,804 INFO Sync complete. Known=2, Desired=1, Disabled=1


2025-09-23 10:31:02,448 INFO ---- Script start ----
2025-09-23 10:31:02,711 WARNING Graph enforcement skipped: token unavailable (fail-open)
2025-09-23 10:31:02,712 INFO Realm 'SSOREALMNAME-HERE' desired users (post-Graph): ['dean']
2025-09-23 10:31:03,044 INFO User opsadmin disabled for >= 1 day, 0:00:00; deleting
2025-09-23 10:31:03,287 INFO Removed sudoers file for opsadmin
2025-09-23 10:31:03,522 INFO Deleted user (and home): opsadmin
2025-09-23 10:31:03,788 INFO Sync complete. Known=1, Desired=1, Disabled=0
```

If a user reappears in the realm (or in Graph once that’s wired), you’ll also see:

```text
2025-09-22 12:05:44,221 INFO User dean reappeared in inputs; clearing disabled state
```
