#!/usr/bin/env python3
# Script: sudomatic5000.py
# Developed by Dean with a bit of love and Irn Bru
#
# What this does (for my future self):
# - Pull PVE users from my OpenID realm (e.g. USER@DOMAIN.com@SSOREALM)
# - Map UPN -> sensible Unix username (config)
# - Create local users if missing, set a random password, and expire it immediately 
# - Add groups + per-user sudoers (only writes if needed)
# - If a user disappears from the realm: lock them, then delete after 24h
# - Logs to /var/log/sudomatic5000/thelog.log

import os
import re
import sys
import json
import random
import logging
import secrets
import string
import subprocess
import stat
import fcntl
from datetime import datetime, timedelta, timezone
from colorama import Fore, Style
from urllib import request as _urlreq, parse as _urlparse
from urllib.error import URLError, HTTPError

VERSION = "1.4.0a"
MIN_PYTHON_VERSION = (3, 11)
ADMIN_REQUIRED = True   # yes, this needs root

# --- Defaults (will be overridden by env vars below) ---
REALM = "SSOREALMNAME-HERE"         # Must match the Proxmox realm name exactly
DEFAULT_SHELL = "/bin/bash"         # e.g. /bin/bash or /bin/zsh

EXTRA_GROUPS = ["sudo"]             # Supplementary groups (set [] if you only want sudoers files)
GRANT_SUDO = False                  # Per-user sudoers in /etc/sudoers.d - disabled by default 
SUDO_NOPASSWD = False               # False = require sudo password

LOG_FILE = "/var/log/sudomatic5000/thelog.log"
STATE_DIR = "/var/lib/sudomatic5000/pve_oidc_sync"
STATE_PATH = os.path.join(STATE_DIR, "state.json")
LOCK_PATH  = os.path.join(STATE_DIR, ".lock")
MANAGED_SUDOERS_PREFIX = "/etc/sudoers.d/pve_realm-"

DELETE_AFTER = timedelta(hours=24)  # How long to keep an ex-realm user locked before deletion
PASSWORD_LENGTH = 38                # Random initial password length - Longer password means less cracking it, though its forced to reset on first login.

# Only allow these UPN domains from IdProvider (empty set = block all)
ALLOWED_UPN_DOMAINS = {"",""}

# System/builtin users we will never manage (create/sudo/delete)
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

# --- Microsoft Graph enforcement (client credentials via env vars) ---
GRAPH_ENFORCE = True            # will be overridden by env
GRAPH_FAIL_OPEN = True          # will be overridden by env
GRAPH_GROUP_ID = os.getenv("ENTR_SUPERUSR_ID", "").strip()  # group to read
GRAPH_TIMEOUT = 8               # seconds

# Token via either a pre-baked access token or client creds in env (client credentials flow)
ENV_GRAPH_ACCESS_TOKEN = "GRAPH_ACCESS_TOKEN"
ENV_MS_TENANT_ID       = "ENTR_TENANT_ID"
ENV_MS_CLIENT_ID       = "ENTR_CLNT_ID"
ENV_MS_CLIENT_SECRET   = "ENTR_CLNT_SEC"

TOKEN_ENV_FALLBACKS = [
    ENV_GRAPH_ACCESS_TOKEN,
    "MSFT_GRAPH_ACC_TK",
    "MS_GRAPH_ACCESS_TOKEN",
    "GRAPH_TOKEN",
]

# -------- env overlay helpers --------
def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

def _env_list(name: str, default: list[str]) -> list[str]:
    v = os.getenv(name, "")
    if not v.strip():
        return default
    parts = [p.strip() for p in re.split(r"[,\s]+", v) if p.strip()]
    return parts or default

def _env_set(name: str, default: set[str]) -> set[str]:
    v = os.getenv(name, "")
    if not v.strip():
        return default
    parts = {p.strip().lower() for p in re.split(r"[,\s]+", v) if p.strip()}
    return parts or default

def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return (v.strip() if v is not None else default)

# -------- apply env overrides --------
REALM          = _env_str ("REALM", REALM)
DEFAULT_SHELL  = _env_str ("DEFAULT_SHELL", DEFAULT_SHELL)

GRANT_SUDO     = _env_bool("GRANT_SUDO", GRANT_SUDO)
SUDO_NOPASSWD  = _env_bool("SUDO_NOPASSWD", SUDO_NOPASSWD)

# Allow overriding EXTRA_GROUPS via env: "sudo wheel" or "sudo,wheel"
EXTRA_GROUPS   = _env_list("EXTRA_GROUPS", EXTRA_GROUPS)

# Space/comma-separated; empty string means "allow all"
ALLOWED_UPN_DOMAINS = _env_set("ALLOWED_UPN_DOMAINS", ALLOWED_UPN_DOMAINS)

# Graph toggles from env/file
GRAPH_ENFORCE  = _env_bool("GRAPH_ENFORCE", GRAPH_ENFORCE)
GRAPH_FAIL_OPEN= _env_bool("GRAPH_FAIL_OPEN", GRAPH_FAIL_OPEN)
GRAPH_GROUP_ID = _env_str ("ENTR_SUPERUSR_ID", GRAPH_GROUP_ID)

#===================#
# Utility / Logging #
#===================#

# ================================================================
# Function: fncScriptSecurityCheck
# Purpose : Ensure script is only executed by root and has safe perms
# Notes   : Exits with warning if insecure
# ================================================================
def fncScriptSecurityCheck():
    script_path = os.path.realpath(__file__)
    st = os.stat(script_path)

    # 1. Must be executed as root
    if os.geteuid() != 0:
        fncPrintMessage("This script must be run as root.", "error")
        sys.exit(1)

    # 2. Must be owned by root
    if st.st_uid != 0:
        fncPrintMessage("Script must be owned by root.", "error")
        sys.exit(1)

    # 3. Permissions must not allow group/others ANY access
    bad_perms = stat.S_IRWXG | stat.S_IRWXO
    if st.st_mode & bad_perms:
        fncPrintMessage(
            f"Insecure permissions on {script_path}. "
            "Only root should have access (chmod 700).",
            "error"
        )
        sys.exit(1)

def fncEnsurePaths():
    """Make sure log/state folders exist (and sane perms)."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
    # Also ensure /var/log/sudomatic5000 perms (root:root 0750)
    try:
        logdir = os.path.dirname(LOG_FILE)
        os.chmod(logdir, 0o750)
    except Exception:
        pass

def fncEnsureLogrotate():
    """Drop a logrotate file so the log doesn't grow to wales."""
    path = "/etc/logrotate.d/sudomatic5000"
    content = f"""{LOG_FILE} {{
  weekly
  rotate 8
  compress
  missingok
  notifempty
  create 0640 root root
}}
"""
    try:
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(content)
            os.chmod(path, 0o644)
    except Exception as e:
        logging.warning("Couldn't write logrotate file (%s): %s", path, e)

def fncSetupLogging():
    """Log to file + stdout. Keep INFO for real changes; DEBUG is quiet by default."""
    fncEnsurePaths()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
    )
    logging.info("---- Script start ----")
    fncEnsureLogrotate()

def fncPrintMessage(message, msg_type="info"):
    styles = {
        "info":    Fore.CYAN  + "{~} ",
        "warning": Fore.RED   + "{!} ",
        "success": Fore.GREEN + "{=]} ",
        "error":   Fore.RED   + "{!} ",
        "disabled":Fore.LIGHTBLACK_EX + "{X} ",
    }
    print(f"{styles.get(msg_type, Fore.WHITE)}{message}{Style.RESET_ALL}")

def fncCheckPyVersion():
    """Refuse to run on potato Python."""
    python_version = sys.version.split()[0]
    fncPrintMessage(f"Python Version Detected: {python_version}", "info")
    if sys.version_info < MIN_PYTHON_VERSION:
        fncPrintMessage("This script requires Python 3.10.0 or higher. Please upgrade.", "error")
        sys.exit(1)

def fncAdminCheck():
    """
    Linux-only: require root when ADMIN_REQUIRED is True.
    No drama, just bail if we're not root.
    """
    if ADMIN_REQUIRED and os.geteuid() != 0:
        fncPrintMessage("This needs root. Try sudo, if you don't have sudo then you shouldn't be anywhere near this", "error")
        sys.exit(1)

# Lockfile so two runs don't stampede each other
_LOCK_FH = None
def fncAcquireLock():
    os.makedirs(STATE_DIR, exist_ok=True)
    global _LOCK_FH
    _LOCK_FH = open(LOCK_PATH, "w")
    fcntl.lockf(_LOCK_FH, fcntl.LOCK_EX | fcntl.LOCK_NB)

def _graph_print_error(code: str, message: str,
                       request_id: str | None = None,
                       client_request_id: str | None = None,
                       when: str | None = None):
    if when is None:
        when = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    err = {
        "error": {
            "code": code,
            "message": message,
            "innerError": {
                "date": when,
                "request-id": request_id or "",
                "client-request-id": client_request_id or ""
            }
        }
    }
    print(json.dumps(err, separators=(',', ':')))

#====================#
# Proxmox OIDC sync  #
#====================#

def fncSanitiseUnix(name: str) -> str:
    """Trim/sanitise to a login-friendly username."""
    name = name.replace(".", "_") # Replce .'s with _'s 
    if USERNAME_LOWERCASE:
        name = name.lower()
    name = re.sub(r"[^a-z0-9._-]", "_", name)
    return name[:USERNAME_MAXLEN]

def fncUpnToUnix(upn: str) -> str:
    """Map a UPN (user@domain.com) to the Unix login I actually want."""
    base = upn.replace("@", USERNAME_SEPARATOR) if USERNAME_MODE == "upn_concat" else upn.split("@", 1)[0] # Because Entra.. It passes the full UPN which breaks this because PVE also adds a @..
    return fncSanitiseUnix(base)

def fncRun(cmdkey: str, args: list[str] | None = None, input: str | None = None) -> tuple[int, str, str]:
    """Run a pinned binary by key, capture rc/out/err.
       Stop Bad men doing bad things pls.
    """
    exe = BIN.get(cmdkey)
    if not exe or not os.path.exists(exe):
        return 127, "", f"binary not found: {cmdkey} -> {exe}"
    try:
        p = subprocess.run([exe] + (args or []), input=input, capture_output=True, text=True, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError as e:
        return 127, "", str(e)

def fncGetPveUsersForRealm(realm: str) -> set[str]:
    """Pull PVE users, filter by my realm and allowed UPN domains, map to local usernames."""
    rc, out, err = fncRun("pvesh", ["get", "/access/users", "--output-format", "json"])
    if rc != 0:
        logging.error("pvesh failed: %s", err)
        return set()
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        logging.error("Bad JSON from pvesh: %s", e)
        return set()

    wanted = set()
    for u in data:
        userid = u.get("userid", "")
        if "@" not in userid:
            continue
        # Format is UPN@REALM; but UPN itself contains '@' so need to split on the LAST '@' nor first
        try:
            upn, user_realm = userid.rsplit("@", 1)
        except ValueError:
            continue
        enabled = u.get("enable", 1)
        enabled_bool = (enabled is True) or (enabled == 1) or (str(enabled) == "1")
        # Domain filter
        dom_ok = False
        if "@" in upn:
            dom = upn.split("@", 1)[1].lower()
            dom_ok = dom in ALLOWED_UPN_DOMAINS
        if user_realm == realm and enabled_bool and upn and dom_ok:
            unix = fncUpnToUnix(upn)
            if unix:
                wanted.add(unix)
    return wanted

def fncEnsureGroup(name: str):
    """Create group if it doesn't exist (using getent for the check)."""
    rc, _, _ = fncRun("getent", ["group", name])
    if rc == 0:
        return
    rc, _, err = fncRun("groupadd", [name])
    if rc != 0:
        logging.error("Failed to create group %s: %s", name, err)
    else:
        logging.info("Created group: %s", name)

def fncCurrentGroups(user: str) -> set[str]:
    """Return current supplementary groups for a user."""
    rc, out, _ = fncRun("id", ["-nG", user])
    if rc != 0 or not out:
        return set()
    return set(out.split())

def fncUserExists(user: str) -> bool:
    """Check if a local account exists (no pwd module, just ask id)."""
    rc, _, _ = fncRun("id", ["-u", user])
    return rc == 0

def fncCreateUser(user: str) -> bool:
    """Create a user with a home and my preferred shell."""
    if fncUserExists(user):
        return False
    rc, _, err = fncRun("useradd", ["-m", "-s", DEFAULT_SHELL, user])
    if rc != 0:
        logging.error("Failed to create user %s: %s", user, err)
        return False
    logging.info("Created local user: %s", user)
    return True

def fncAddUserToGroups(user: str, groups: list[str]) -> bool:
    """Group add - only touches what's missing."""
    if not groups:
        return False
    for g in groups:
        if g:
            fncEnsureGroup(g)
    current = fncCurrentGroups(user)
    missing = [g for g in groups if g and g not in current]
    if not missing:
        logging.debug("User %s already in groups %s; no change", user, groups)
        return False
    rc, _, err = fncRun("usermod", ["-aG", ",".join(missing), user])
    if rc != 0:
        logging.error("Failed to add %s to groups %s: %s", user, missing, err)
        return False
    logging.info("Added %s to groups %s", user, missing)
    return True

def fncIsLocked(user: str) -> bool:
    """
    Check if account is already locked.
    """
    rc, out, _ = fncRun("passwd", ["-S", user])
    if rc != 0 or not out:
        return False
    parts = out.split()
    return len(parts) >= 2 and parts[1] == "L"

def fncLockUser(user: str):
    """
        Lock User if they are removed from entra group. - 
        Just a temp thing because there isn't any way to tell if they have been removed yet. 
        I just need to please the people so they stop moaning so much.
    """
    rc, _, err = fncRun("usermod", ["-L", user])
    if rc != 0:
        logging.error("Failed to lock user %s: %s", user, err)
    else:
        logging.info("Locked user: %s", user)

def fncUnlockUser(user: str):
    """
       Quiet if already unlocked (avoids spammy logs).
       Unlock user if they are re-added to the Entra group
    """
    if not fncIsLocked(user):
        logging.debug("User %s not locked; no change", user)
        return
    rc, _, err = fncRun("usermod", ["-U", user])
    if rc != 0:
        logging.error("Failed to unlock user %s: %s", user, err)
    else:
        logging.info("Unlocked user: %s", user)

def fncDeleteUser(user: str):
    """
    Func to delete user after it's been locked for X hours defined under DELETE_AFTER. 
    """
    fncRemoveSudoers(user)
    rc, _, err = fncRun("userdel", ["-r", user])
    if rc != 0:
        logging.error("Failed to delete user %s: %s", user, err)
    else:
        logging.info("Deleted user (and home): %s", user)

def fncGrantSudo(user: str) -> bool:
    """
    Ensure /etc/sudoers.d/<file> has exactly what I want.
    Writes only if content differs; validates with visudo first.

    Safety gate:
        - If fncScriptSecurityCheck() is missing, returns False, or raises,
            we refuse to grant sudo. Standard user only.
        Who ever said this would be bum twitching - not me. Living life on the edge
        """
    # --- Security gate ---
    checker = globals().get("fncScriptSecurityCheck")
    if not callable(checker):
        logging.error("Security check function missing; refusing to grant sudo to %s", user)
        return False
    try:
        if checker() is not True:
            logging.error("Security check failed; refusing to grant sudo to %s", user)
            return False
    except Exception as e:
        logging.error("Security check raised %s; refusing to grant sudo to %s", repr(e), user)
        return False
    # --- end gate ---

    if not GRANT_SUDO:
        return False

    os.makedirs("/etc/sudoers.d", exist_ok=True)
    path = f"{MANAGED_SUDOERS_PREFIX}{user}"
    expected = f"{user} ALL=(ALL) ALL\n" if not SUDO_NOPASSWD else f"{user} ALL=(ALL) NOPASSWD:ALL\n"

    current = ""
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                current = f.read()
        except Exception as e:
            logging.error("Failed to read sudoers for %s: %s", user, e)

    if current == expected:
        logging.debug("Sudoers already correct for %s; no change", user)
        return False

    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w") as f:
            f.write(expected)
        os.chmod(tmp, 0o440)

        rc, _, err = fncRun("visudo", ["-cf", tmp])
        if rc != 0:
            logging.error("visudo validation failed for %s: %s", user, err)
            os.remove(tmp)
            return False

        os.replace(tmp, path)
        logging.info("Updated sudoers for %s at %s", user, path)
        return True
    except Exception as e:
        logging.error("Failed writing sudoers for %s: %s", user, e)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False

def fncRemoveSudoers(user: str):
    """Phew"""
    path = f"{MANAGED_SUDOERS_PREFIX}{user}"
    try:
        if os.path.exists(path):
            os.remove(path)
            logging.info("Removed sudoers file for %s", user)
    except Exception as e:
        logging.error("Failed removing sudoers for %s: %s", user, e)

def fncGeneratePassword(length: int = PASSWORD_LENGTH) -> str:
    """Bad Guy Proof Password Generator"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def fncSetInitialPassword(user: str) -> bool:
    """
    Set a random password and force change on first login.
    Intentionally do NOT print or store the password anywhere because thats just stupid.
    """
    pwd_plain = fncGeneratePassword()
    rc, _, err = fncRun("chpasswd", [], input=f"{user}:{pwd_plain}")
    if rc != 0:
        logging.error("Failed to set initial password for %s: %s", user, err)
        return False
    rc, _, err = fncRun("chage", ["-d", "0", user])
    if rc != 0:
        logging.error("Failed to force password change for %s: %s", user, err)
    logging.info("Initial password set and expired for %s (not stored)", user)
    return True

def fncLoadState() -> dict:
    """Remember who we've seen before and who's in the 24h penalty box."""
    if not os.path.exists(STATE_PATH):
        return {"known_users": [], "disabled": {}}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"known_users": [], "disabled": {}}

def fncSaveState(state: dict):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_PATH)

def fncNowUTC() -> datetime:
    return datetime.now(timezone.utc)

def fncParseISO(ts: str) -> datetime:
    return datetime.fromisoformat(ts)

#====================#
# Microsoft Graph    #
#====================#
#### This is still a WIP and not completed yet.... 
def fncGraphGetToken() -> str | None:
    """
    1) Use a provided bearer token (any of TOKEN_ENV_FALLBACKS)
    2) Else use client credentials (ENTR_TENANT_ID, ENTR_CLNT_ID, ENTR_CLNT_SEC)
    """
    # Path 1: bearer from env
    for name in TOKEN_ENV_FALLBACKS:
        val = os.getenv(name, "").strip()
        if val:
            logging.info("Graph: using provided bearer from %s", name)
            return val

    # Path 2: client credentials
    tenant = os.getenv(ENV_MS_TENANT_ID, "").strip()
    client = os.getenv(ENV_MS_CLIENT_ID, "").strip()
    secret = os.getenv(ENV_MS_CLIENT_SECRET, "").strip()

    # Helpful debug without leaking secrets
    def _seen(v): return "set" if v else "empty"
    logging.debug(
        "Graph env check: TENANT=%s CLIENT=%s SECRET=%s",
        _seen(tenant), _seen(client), _seen(secret)
    )

    if not (tenant and client and secret):
        logging.error(
            "Graph creds missing: set one of %s or (%s,%s,%s)",
            ",".join(TOKEN_ENV_FALLBACKS), ENV_MS_TENANT_ID, ENV_MS_CLIENT_ID, ENV_MS_CLIENT_SECRET
        )
        return None

    url  = f"https://login.microsoftonline.com/{_urlparse.quote(tenant)}/oauth2/v2.0/token"
    data = _urlparse.urlencode({
        "client_id": client,
        "client_secret": secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }).encode()
    req = _urlreq.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with _urlreq.urlopen(req, timeout=GRAPH_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
            tok = body.get("access_token")
            if tok:
                logging.info("Graph: obtained access token via client credentials (tenant=%s, client=%s…)",
                             tenant, client[:6])
                return tok
            logging.error("Graph token response missing access_token: %s", body)
            return None
    except HTTPError as e:
        # Try to pretty-print Graph JSON error
        try:
            err_body = e.read().decode(errors="ignore")
            parsed = json.loads(err_body)
            if isinstance(parsed, dict) and "error" in parsed:
                print(json.dumps(parsed, separators=(',', ':')))
            else:
                print(json.dumps({
                    "error": {
                        "code": f"HTTP_{e.code}",
                        "message": str(e),
                        "innerError": {
                            "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
                            "request-id": e.headers.get("request-id", ""),
                            "client-request-id": e.headers.get("client-request-id", "")
                        }
                    }
                }, separators=(',', ':')))
        except Exception:
            logging.error("Graph token HTTP %s", e.code)
        return None
    except URLError as e:
        logging.error("Graph token network error: %s", e)
        return None
    except Exception as e:
        logging.error("Graph token unexpected error: %s", e)
        return None

def fncGraphListGroupUPNs(group_id: str, token: str) -> set[str] | None:
    """
    Return a set of userPrincipalName values for *user* members only.
    - No fallbacks (mail/identities) — strictly UPN.
    - Skips members with missing/empty UPN and logs a warning.
    - On HTTP/network error: prints one Graph-style JSON error and returns None
      so the caller can fail-open (no user add/remove/lock this run).
    """
    if not token:
        _graph_print_error("InvalidAuthenticationToken", "No access token provided.", None, None)
        logging.warning("Graph: no token; proceeding without enforcement (fail-open).")
        return None

    client_req_id = secrets.token_hex(16)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "client-request-id": client_req_id,
    }

    # Best-effort group meta for nicer logs (don’t print JSON if this fails)
    g_name, g_mail = group_id, "-"
    try:
        meta_req = _urlreq.Request(
            f"https://graph.microsoft.com/v1.0/groups/{group_id}?$select=id,displayName,mail",
            headers=headers
        )
        with _urlreq.urlopen(meta_req, timeout=GRAPH_TIMEOUT) as r:
            meta = json.loads(r.read().decode())
        g_name = meta.get("displayName") or group_id
        g_mail = meta.get("mail") or "-"
    except Exception:
        pass

    # Only users; request only what we need for strict UPN
    url = (f"https://graph.microsoft.com/v1.0/groups/{group_id}"
           f"/members/microsoft.graph.user?$select=id,displayName,userPrincipalName&$top=999")

    upns: set[str] = set()
    pages = 0
    missing_upn_ids: list[str] = []
    domain_filtered = 0

    # Optional domain allow-list (ignore blanks like "" in config)
    allowed_domains = {d.strip().lower() for d in ALLOWED_UPN_DOMAINS if d and d.strip()}

    while url:
        try:
            req = _urlreq.Request(url, headers=headers)
            with _urlreq.urlopen(req, timeout=GRAPH_TIMEOUT) as resp:
                doc = json.loads(resp.read().decode())
        except HTTPError as e:
            rid = e.headers.get("request-id") or e.headers.get("x-ms-request-id")
            # Print Graph’s own error JSON if present; else synthesize one line
            try:
                body = e.read().decode(errors="ignore")
                parsed = json.loads(body)
                if isinstance(parsed, dict) and "error" in parsed:
                    print(json.dumps(parsed, separators=(',', ':')))
                else:
                    _graph_print_error(f"HTTP_{e.code}", str(e), rid, client_req_id)
            except Exception:
                _graph_print_error(f"HTTP_{e.code}", str(e), rid, client_req_id)
            logging.warning("Graph failed; no user changes this run (fail-open).")
            return None
        except (URLError, Exception) as e:
            _graph_print_error("ServiceUnavailable", str(e), None, client_req_id)
            logging.warning("Graph unavailable (%s); no user changes this run (fail-open).", e)
            return None

        pages += 1
        for item in doc.get("value", []):
            raw_upn = (item.get("userPrincipalName") or "").strip()
            if not raw_upn:
                # real user object but no UPN — skip per your requirement
                missing_upn_ids.append(item.get("id") or "?")
                continue

            upn = raw_upn.lower()
            if allowed_domains:
                dom = upn.split("@", 1)[-1]
                if dom not in allowed_domains:
                    domain_filtered += 1
                    continue

            upns.add(upn)

        url = doc.get("@odata.nextLink")

    if missing_upn_ids:
        sample = ", ".join(missing_upn_ids[:10])
        more = "" if len(missing_upn_ids) <= 10 else f" …(+{len(missing_upn_ids)-10} more)"
        logging.warning("Graph: %d user member(s) missing userPrincipalName in '%s' — skipped: %s%s",
                        len(missing_upn_ids), g_name, sample, more)

    logging.info("Graph: group '%s' (%s) members fetched (STRICT UPN): kept=%d, domain_filtered=%d, pages=%d",
                 g_name, g_mail, len(upns), domain_filtered, pages)
    return upns

#====================#
# Sync logic         #
#====================#

def fncSync():
    """Main reconciliation loop. Keep it boring and predictable."""
    # Sanity: make sure the obvious tools exist (using pinned paths because my trust in the bad guys is lost)
    required_bins = ["pvesh","useradd","usermod","userdel","passwd","chage","chpasswd","visudo","getent","id"]
    for key in required_bins:
        if not os.path.exists(BIN.get(key, "")):
            logging.error("Missing required binary: %s -> %s", key, BIN.get(key))

    desired = fncGetPveUsersForRealm(REALM)

    # If Graph enforced, intersect with Graph group UPNs (mapped to same unix scheme)
    if GRAPH_ENFORCE:
        token = fncGraphGetToken()
        if token:
            allowed = fncGraphListGroupUPNs(GRAPH_GROUP_ID, token)
            if allowed is None:
                # Graph request failed - DO NOT lock/disable anyone; keep previous behaviour
                logging.warning("Graph error: proceeding without enforcement (fail-open).")
                fncPrintMessage("Graph error: proceeding without enforcement (fail-open).", "error")
            else:
                before = set(desired)
                allowed_unix = {fncUpnToUnix(u) for u in allowed}
                desired = before & allowed_unix
                dropped = sorted(before - desired)
                if dropped:
                    logging.info("Graph enforcement: excluding users not in group: %s", dropped)
        else:
            logging.warning("Graph token unavailable: proceeding without enforcement (fail-open).")


    state = fncLoadState()
    known = set(state.get("known_users", []))
    disabled = state.get("disabled", {})  # {username: iso_timestamp_locked}

    logging.info("Realm '%s' desired users: %s", REALM, sorted(desired))

    # Ensure desired users exist and are in a good state
    for user in sorted(desired):
        # Don't let IdP trickery clobber system users
        if user in RESERVED_USERS:
            logging.warning("Refusing to manage reserved username: %s", user)
            continue

        created = fncCreateUser(user)
        fncUnlockUser(user)  # quiet if already unlocked

        if EXTRA_GROUPS:
            fnn = [g for g in EXTRA_GROUPS if g]  # keep it clean
            if fnn:
                fncAddUserToGroups(user, fnn)

        if created:
            fncSetInitialPassword(user)

        if user in disabled:
            logging.info("User %s reappeared in realm; clearing disabled state", user)
            disabled.pop(user, None)

        known.add(user)


    for user in sorted(known - desired):
        """
         Anyone we used to know but is no longer desired?
         Will eventually add an API call to Entra to check if the user still exists in the group. 
         Also need to 
        """
        if not fncUserExists(user):
            logging.info("User %s already gone; cleaning state", user)
            disabled.pop(user, None)
            known.discard(user)
            continue

        if user in RESERVED_USERS:
            logging.warning("Refusing to lock/delete reserved username: %s", user)
            disabled.pop(user, None)
            known.discard(user)
            continue

        if user not in disabled:
            fncLockUser(user)
            disabled[user] = fncNowUTC().isoformat()
            logging.info("User %s removed from realm; locked and marked for deletion in %s", user, str(DELETE_AFTER))
        else:
            try:
                locked_at = fncParseISO(disabled[user])
            except Exception:
                locked_at = fncNowUTC()
                disabled[user] = locked_at.isoformat()

            if fncNowUTC() - locked_at >= DELETE_AFTER:
                logging.info("User %s disabled for >= %s; deleting", user, str(DELETE_AFTER))
                fncDeleteUser(user)
                disabled.pop(user, None)
                known.discard(user)
            else:
                remain = DELETE_AFTER - (fncNowUTC() - locked_at)
                logging.info("User %s still in grace; %s remaining", user, str(remain).split(".")[0])

    # Persist
    state["known_users"] = sorted(known)
    state["disabled"] = disabled
    fncSaveState(state)
    logging.info("Sync complete. Known=%d, Desired=%d, Disabled=%d", len(known), len(desired), len(disabled))

#=================#
# Script harness  #
#=================#

def fncMain():
    try:
        fncScriptSecurityCheck()
        fncAdminCheck()
        fncSetupLogging()
        fncAcquireLock()
        fncSync()
    except KeyboardInterrupt:
        fncPrintMessage("Bye then...", "error")
        sys.exit(0)
    except Exception as e:
        logging.exception("Unhandled exception: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    fncCheckPyVersion()
    fncMain()