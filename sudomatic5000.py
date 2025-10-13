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

# ==============================
# Imports
# ==============================

# Standard library
import fcntl
import json
import logging
import os
import re
import secrets
import stat
import string
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from urllib import parse as _urlparse, request as _urlreq
from urllib.error import HTTPError, URLError

# Third-party
from colorama import Fore, Style

#=================#
# Global Settings #
#=================#

MIN_PYTHON_VERSION = (3, 11)
ADMIN_REQUIRED = True   # Script requires root

#-----------------------------#
# Defaults (env-overridable)  #
#-----------------------------#
REALM = "SSOREALMNAME-HERE"         # Must match the Proxmox realm name exactly
DEFAULT_SHELL = "/bin/bash"         # e.g. /bin/bash or /bin/zsh

EXTRA_GROUPS = ["sudo"]             # Supplementary groups (tip: set [] if sudo is role-gated)
GRANT_SUDO = False                  # Per-user sudoers in /etc/sudoers.d
SUDO_NOPASSWD = False               # False = require password for sudo

LOG_FILE = "/var/log/sudomatic5000/thelog.log"
STATE_DIR = "/var/lib/sudomatic5000/pve_oidc_sync"
STATE_PATH = os.path.join(STATE_DIR, "state.json")
LOCK_PATH  = os.path.join(STATE_DIR, ".lock")
MANAGED_SUDOERS_PREFIX = "/etc/sudoers.d/pve_realm-"

DELETE_AFTER = timedelta(hours=24)  # Lock grace period before deletion
PASSWORD_LENGTH = 38                # Random initial password length

# Only allow these UPN domains from IdP.
# NOTE: empty set means "allow all" (see _allowed_domain()).
ALLOWED_UPN_DOMAINS = {"", ""}

# System/builtin users we never manage (create/sudo/delete)
RESERVED_USERS = {
    "root","daemon","bin","sys","sync","games","man","lp","mail","news",
    "uucp","proxy","www-data","backup","list","irc","gnats","nobody"
}

#------------------------------#
# UPN → Unix mapping behaviour #
#------------------------------#
USERNAME_MODE = "useronly"          # "useronly" or "upn_concat"
USERNAME_SEPARATOR = "_"            # Only used with "upn_concat"
USERNAME_LOWERCASE = True
USERNAME_MAXLEN = 32

#------------------------------#
# Pinned binaries for exec     #
#------------------------------#
BIN = {
  "pvesh":    "/usr/bin/pvesh",
  "pveum":    "/usr/sbin/pveum",
  "useradd":  "/usr/sbin/useradd",
  "usermod":  "/usr/sbin/usermod",
  "userdel":  "/usr/sbin/userdel",
  "passwd":   "/usr/bin/passwd",
  "chage":    "/usr/bin/chage",
  "chpasswd": "/usr/sbin/chpasswd",
  "visudo":   "/usr/sbin/visudo",
  "id":       "/usr/bin/id",
  "getent":   "/usr/bin/getent",
  "groupadd": "/usr/sbin/groupadd",
  "gpasswd":  "/usr/bin/gpasswd",
}

#---------------------------------------------#
# Microsoft Graph (client-credentials via env)#
#---------------------------------------------#
GRAPH_ENFORCE = True
GRAPH_FAIL_OPEN = True

GRAPH_GROUP_IDS = []    # Parsed below from ENTRA_* vars
GRAPH_TIMEOUT = 8       # Seconds

# Token envs (bearer OR client creds)
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

#===========================#
# Environment Overlay Utils #
#===========================#

# Lockfile so two runs don't stampede each other
_LOCK_FH = None

def fncAcquireLock():
    """Acquire an exclusive lock to prevent concurrent runs."""
    os.makedirs(STATE_DIR, exist_ok=True)
    global _LOCK_FH
    try:
        _LOCK_FH = open(LOCK_PATH, "w")
        os.chmod(LOCK_PATH, 0o600)
        fcntl.lockf(_LOCK_FH, fcntl.LOCK_EX | fcntl.LOCK_NB)
        logging.debug("Acquired lock: %s", LOCK_PATH)
    except BlockingIOError:
        fncPrintMessage("Another instance of sudomatic5000 is already running.", "warning")
        sys.exit(1)
    except Exception as e:
        fncPrintMessage(f"Failed to acquire lock ({LOCK_PATH}): {e}", "error")
        sys.exit(1)

# Function: _env_bool
# Purpose : Read boolean-like env vars with a default.
# Notes   : Accepts 1/true/yes/y/on (case-insensitive).
def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

# Function: _env_list
# Purpose : Parse a list from env using commas/spaces as separators.
# Notes   : Returns default when env missing/blank.
def _env_list(name: str, default: list[str]) -> list[str]:
    v = os.getenv(name, "")
    if not v.strip():
        return default
    parts = [p.strip() for p in re.split(r"[,\s]+", v) if p.strip()]
    return parts or default

# Function: _env_set
# Purpose : Parse a lowercase set from env using commas/spaces as separators.
# Notes   : Used for allowlists; empty set means "allow all".
def _env_set(name: str, default: set[str]) -> set[str]:
    v = os.getenv(name, "")
    if not v.strip():
        return default
    parts = {p.strip().lower() for p in re.split(r"[,\s]+", v) if p.strip()}
    return parts or default

# Function: _env_str
# Purpose : Return stripped string from env with default fallback.
# Notes   : Keeps empty -> default behaviour consistent.
def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return (v.strip() if v is not None else default)

# Function: _env_json
# Purpose : Parse JSON from an env var (objects/arrays).
# Notes   : Logs and returns default on parse failure.
def _env_json(name: str, default):
    v = os.getenv(name, "").strip()
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception as e:
        logging.error("Bad JSON in %s: %s", name, e)
        return default

# Function: _log_group_members
# Purpose : Summarise group membership without persisting to disk.
# Notes   : INFO shows counts + samples; DEBUG logs full lists.
def _log_group_members(name: str, purpose: str, upns: set[str] | None, sample: int = 20):
    if upns is None:
        logging.info("Graph group '%s' (%s): fetch failed (fail-open)", name, purpose)
        return

    count = len(upns)
    upn_list = sorted(upns)
    unix_list = sorted({fncUpnToUnix(u) for u in upns})

    # INFO: count + small samples
    info_upn_sample = upn_list[:sample]
    info_unix_sample = unix_list[:sample]
    logging.info(
        "Graph group '%s' (%s): members=%d | unix_sample=%s | upn_sample=%s",
        name, purpose, count, info_unix_sample, info_upn_sample
    )

    # DEBUG: full lists
    logging.debug("Graph group '%s' (%s) FULL unix=%s", name, purpose, unix_list)
    logging.debug("Graph group '%s' (%s) FULL upn =%s", name, purpose, upn_list)

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

def _assert_regular_or_missing(p: str | os.PathLike):
    try:
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"{p} is not a regular file")
    except FileNotFoundError:
        return

def _safe_write_atomic(path: str, data: str, mode: int = 0o600):
    d = os.path.dirname(path)
    _assert_regular_or_missing(path)
    # write to a secure temp in same dir
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        os.write(fd, data.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    # refuse to overwrite a symlink
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            os.remove(tmp)
            raise RuntimeError(f"Refusing to overwrite symlink: {path}")
    except FileNotFoundError:
        pass
    os.replace(tmp, path)

def _allowed_domain(dom: str) -> bool:
    dom = (dom or "").lower()
    # Normalize: ignore blanks like "" in the set
    filt = {d.strip().lower() for d in ALLOWED_UPN_DOMAINS if d and d.strip()}
    if not filt:
        return True  # empty filter = allow all
    return dom in filt

def _get_utc_datetime() -> datetime:
    return datetime.now(timezone.utc)

def _parse_iso_datetime(ts: str) -> datetime:
    return datetime.fromisoformat(ts)

#===========================#
# Apply Environment Overrides
#===========================#

REALM          = _env_str ("REALM", REALM)
DEFAULT_SHELL  = _env_str ("DEFAULT_SHELL", DEFAULT_SHELL)

GRANT_SUDO     = _env_bool("GRANT_SUDO", GRANT_SUDO)
SUDO_NOPASSWD  = _env_bool("SUDO_NOPASSWD", SUDO_NOPASSWD)

# Allow overriding EXTRA_GROUPS via env: "sudo wheel" or "sudo,wheel"
EXTRA_GROUPS   = _env_list("EXTRA_GROUPS", EXTRA_GROUPS)

# Space/comma-separated; NOTE: empty set means "allow all"
ALLOWED_UPN_DOMAINS = _env_set("ALLOWED_UPN_DOMAINS", ALLOWED_UPN_DOMAINS)

# Graph toggles from env/file
GRAPH_ENFORCE   = _env_bool("GRAPH_ENFORCE", GRAPH_ENFORCE)
GRAPH_FAIL_OPEN = _env_bool("GRAPH_FAIL_OPEN", GRAPH_FAIL_OPEN)

# Multi-group inputs
GRAPH_GROUP_IDS = _env_list("ENTRA_GROUP_IDS", [])
ENTRA_ROLE_MAP  = _env_json("ENTRA_ROLE_MAP", [])

ENTRA_ALLUSERS_GROUP_ID    = _env_str("ENTRA_ALLUSERS_GROUP_ID", "")
ENTRA_ALLUSERS_PVE_ROLE    = _env_str("ENTRA_ALLUSERS_PVE_ROLE", "")
ENTRA_SUPERADMIN_GROUP_ID  = _env_str("ENTRA_SUPERADMIN_GROUP_ID", "")
ENTRA_SUPERADMIN_PVE_ROLE  = _env_str("ENTRA_SUPERADMIN_PVE_ROLE", "")

# Optional explicit list (comma/space-separated)
ENTRA_GROUP_IDS = _env_list("ENTRA_GROUP_IDS", GRAPH_GROUP_IDS)

# Build the full group-id set we should enforce from all sources
_graph_ids = set(ENTRA_GROUP_IDS)
for m in ENTRA_ROLE_MAP:
    gid = (m.get("group") or "").strip()
    if gid:
        _graph_ids.add(gid)
for gid in (ENTRA_ALLUSERS_GROUP_ID, ENTRA_SUPERADMIN_GROUP_ID):
    if gid:
        _graph_ids.add(gid)

GRAPH_GROUP_IDS = sorted(_graph_ids)

# Map group → PVE role (only non-empty)
PVE_ROLE_BY_GROUP = {
    (m.get("group") or "").strip(): (m.get("pve_role") or "")
    for m in (ENTRA_ROLE_MAP or [])
    if (m.get("group") or "").strip()
}

# Include overrides for AllUsers and SuperAdmin if provided
if ENTRA_ALLUSERS_GROUP_ID and ENTRA_ALLUSERS_PVE_ROLE:
    PVE_ROLE_BY_GROUP[ENTRA_ALLUSERS_GROUP_ID] = ENTRA_ALLUSERS_PVE_ROLE

if ENTRA_SUPERADMIN_GROUP_ID and ENTRA_SUPERADMIN_PVE_ROLE:
    PVE_ROLE_BY_GROUP[ENTRA_SUPERADMIN_GROUP_ID] = ENTRA_SUPERADMIN_PVE_ROLE

#===================#
# Utility / Logging #
#===================#

# Function: fncScriptSecurityCheck
# Purpose : Ensure script is root-owned, root-executed, and locked-down perms.
# Notes   : Exits non-zero with a clear message if any check fails.
def fncScriptSecurityCheck():
    script_path = os.path.realpath(__file__)
    st = os.stat(script_path)

    # 1) Must be executed as root
    if os.geteuid() != 0:
        fncPrintMessage("This script must be run as root.", "error")
        sys.exit(1)

    # 2) Must be owned by root
    if st.st_uid != 0:
        fncPrintMessage("Script must be owned by root.", "error")
        sys.exit(1)

    # 3) Group/other must have no perms
    bad_perms = stat.S_IRWXG | stat.S_IRWXO
    if st.st_mode & bad_perms:
        fncPrintMessage(
            f"Insecure permissions on {script_path}. Only root should have access (chmod 700).",
            "error"
        )
        sys.exit(1)
    return True

# Function: fncBootstrapPaths
# Purpose : Create required directories and apply conservative permissions.
# Notes   : Safe to call multiple times; no-op when present.
def fncBootstrapPaths():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
    os.chmod(os.path.dirname(LOG_FILE), 0o750)
    os.chmod(STATE_DIR, 0o750)

# Function: fncEnsureLogrotate
# Purpose : Drop a logrotate file so the log doesn't grow to wales.
# Notes   : Creates once; ignores errors (warns only).
def fncEnsureLogrotate():
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

# Function: fncSetupLogging
# Purpose : Configure logging to file and stdout; ensure paths & logrotate exist.
# Notes   : INFO for changes; DEBUG for verbose diagnostics.
def fncSetupLogging():
    fncBootstrapPaths()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
    )
    logging.info("---- Script start ----")
    fncEnsureLogrotate()

# Function: fncPrintMessage
# Purpose : Human-friendly colored console messages.
# Notes   : Used for important user-facing prints (not logs).
def fncPrintMessage(message, msg_type="info"):
    styles = {
        "info":    Fore.CYAN  + "{~} ",
        "warning": Fore.RED   + "{!} ",
        "success": Fore.GREEN + "{=]} ",
        "error":   Fore.RED   + "{!} ",
        "disabled":Fore.LIGHTBLACK_EX + "{X} ",
    }
    print(f"{styles.get(msg_type, Fore.WHITE)}{message}{Style.RESET_ALL}")

# Function: fncCheckPyVersion
# Purpose : Fail fast on unsupported Python versions.
# Notes   : Requires Python >= MIN_PYTHON_VERSION.
def fncCheckPyVersion():
    python_version = sys.version.split()[0]
    fncPrintMessage(f"Python Version Detected: {python_version}", "info")
    if sys.version_info < MIN_PYTHON_VERSION:
        fncPrintMessage("This script requires Python 3.11.0 or higher. Please upgrade.", "error")
        sys.exit(1)

# Function: fncAdminCheck
# Purpose : Ensure the process runs as root when ADMIN_REQUIRED is True.
# Notes   : Friendly message; exits if not root.
def fncAdminCheck():
    if ADMIN_REQUIRED and os.geteuid() != 0:
        fncPrintMessage("This needs root. Try sudo; if you don't have sudo then you shouldn't be anywhere near this", "error")
        sys.exit(1)

#====================#
# Proxmox OIDC sync  #
#====================#

# Function: fncSanitiseUnix
# Purpose : Trim/sanitise a string to a safe Unix login.
# Notes   : Replaces non [a-z0-9._-] with "_", lowercases if configured, enforces max length.
def fncSanitiseUnix(name: str) -> str:
    name = name.replace(".", "_")
    if USERNAME_LOWERCASE:
        name = name.lower()
    name = re.sub(r"[^a-z0-9._-]", "_", name)
    return name[:USERNAME_MAXLEN]

# Function: fncUpnToUnix
# Purpose : Map a UPN (user@domain) to the Unix login format you want.
# Notes   : Supports "useronly" or "upn_concat" modes via USERNAME_MODE/USERNAME_SEPARATOR.
def fncUpnToUnix(upn: str) -> str:
    base = upn.replace("@", USERNAME_SEPARATOR) if USERNAME_MODE == "upn_concat" else upn.split("@", 1)[0]
    return fncSanitiseUnix(base)

# Function: fncRun
# Purpose : Execute a pinned binary by logical key; capture rc/stdout/stderr.
# Notes   : Returns (returncode, stdout, stderr). Uses BIN map for safety.
def fncRun(cmdkey: str, args: list[str] | None = None, input: str | None = None) -> tuple[int, str, str]:
    exe = BIN.get(cmdkey)
    if not exe or not os.path.exists(exe):
        return 127, "", f"binary not found: {cmdkey} -> {exe}"
    try:
        p = subprocess.run([exe] + (args or []), input=input, capture_output=True, text=True, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError as e:
        return 127, "", str(e)

# Function: fncGetPveUsersForRealm
# Purpose : List enabled PVE users in REALM, filter by allowed UPN domains, map to Unix usernames.
# Notes   : Uses pvesh; ignores entries without realm or domain not in ALLOWED_UPN_DOMAINS.
def fncGetPveUsersForRealm(realm: str) -> set[str]:
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
        try:
            upn, user_realm = userid.rsplit("@", 1)
        except ValueError:
            continue
        enabled = u.get("enable", 1)
        enabled_bool = (enabled is True) or (enabled == 1) or (str(enabled) == "1")
        dom_ok = True
        if "@" in upn:
            dom_ok = _allowed_domain(upn.split("@", 1)[1])

        if user_realm == realm and enabled_bool and upn and dom_ok:
            unix = fncUpnToUnix(upn)
            if unix:
                wanted.add(unix)
    return wanted

# Function: fncEnsureGroup
# Purpose : Ensure a Unix group exists (create if missing).
# Notes   : Uses getent for existence check; logs creation.
def fncEnsureGroup(name: str):
    rc, _, _ = fncRun("getent", ["group", name])
    if rc == 0:
        return
    rc, _, err = fncRun("groupadd", [name])
    if rc != 0:
        logging.error("Failed to create group %s: %s", name, err)
    else:
        logging.info("Created group: %s", name)

# Function: fncCurrentGroups
# Purpose : Return the set of supplementary groups for a user.
# Notes   : Uses `id -nG`; returns empty set on error.
def fncCurrentGroups(user: str) -> set[str]:
    rc, out, _ = fncRun("id", ["-nG", user])
    if rc != 0 or not out:
        return set()
    return set(out.split())

# Function: fncUserExists
# Purpose : Check whether a local account exists.
# Notes   : Uses `id -u`; avoids importing pwd module.
def fncUserExists(user: str) -> bool:
    rc, _, _ = fncRun("id", ["-u", user])
    return rc == 0

# Function: fncCreateUser
# Purpose : Create a local user with home and configured shell.
# Notes   : Idempotent; returns True if created, False if already exists.
def fncCreateUser(user: str) -> bool:
    if fncUserExists(user):
        return False
    rc, _, err = fncRun("useradd", ["-m", "-s", DEFAULT_SHELL, user])
    if rc != 0:
        logging.error("Failed to create user %s: %s", user, err)
        return False
    logging.info("Created local user: %s", user)
    return True

# Function: fncEnsureUserGroup
# Purpose : Ensure user membership in a single group matches `present`.
# Notes   : Combines add/remove; used by higher-level helpers.
def fncEnsureUserGroup(user: str, group: str, present: bool) -> bool:
    if not group:
        return False
    fncEnsureGroup(group)
    current = fncCurrentGroups(user)
    if present and group not in current:
        rc, _, err = fncRun("usermod", ["-aG", group, user])
        if rc != 0:
            logging.error("Failed to add %s to group %s: %s", user, group, err)
            return False
        logging.info("Added %s to group %s", user, group)
        return True
    if not present and group in current:
        rc, _, err = fncRun("gpasswd", ["-d", user, group])
        if rc != 0:
            logging.error("Failed to remove %s from group %s: %s", user, group, err)
            return False
        logging.info("Removed %s from group %s", user, group)
        return True
    return False

# Function: fncAddUserToGroups
# Purpose : Add user to the list of groups (missing only).
# Notes   : Keeps original API; internally uses ensure-group logic.
def fncAddUserToGroups(user: str, groups: list[str]) -> bool:
    if not groups:
        return False
    changed = False
    for g in groups:
        if g:
            changed |= fncEnsureUserGroup(user, g, present=True)
    if not changed:
        logging.debug("User %s already in groups %s; no change", user, groups)
    return changed

# Function: fncRemoveUserFromGroup
# Purpose : Backwards-compat wrapper to remove a single group.
# Notes   : Delegates to fncEnsureUserGroup(..., present=False).
def fncRemoveUserFromGroup(user: str, group: str) -> bool:
    return fncEnsureUserGroup(user, group, present=False)

# Function: fncResolveUpnForUnix
# Purpose : Given a unix username, find the corresponding UPN in the configured PVE realm.
# Notes   : Scans pvesh /access/users and matches via fncUpnToUnix(upn).
def fncResolveUpnForUnix(unix: str) -> str | None:
    rc, out, err = fncRun("pvesh", ["get", "/access/users", "--output-format", "json"])
    if rc != 0:
        logging.error("pvesh list users failed while resolving upn for %s: %s", unix, err)
        return None
    try:
        for u in json.loads(out):
            userid = u.get("userid", "")
            if "@" not in userid:
                continue
            try:
                upn, realm = userid.rsplit("@", 1)
            except ValueError:
                continue
            if realm != REALM:
                continue
            if fncUpnToUnix(upn) == unix:
                return upn
    except Exception as e:
        logging.error("Failed to parse pvesh output while resolving upn for %s: %s", unix, e)
    return None

# Function: fncIsLocked
# Purpose : Check whether a user account is locked.
# Notes   : Parses `passwd -S` output; returns False on errors.
def fncIsLocked(user: str) -> bool:
    rc, out, _ = fncRun("passwd", ["-S", user])
    if rc != 0 or not out:
        return False
    parts = out.split()
    return len(parts) >= 2 and parts[1] == "L"

# Function: fncSetLocked
# Purpose : Ensure a user account is locked (True) or unlocked (False).
# Notes   : Idempotent; returns when already in desired state.
def fncSetLocked(user: str, locked: bool):
    if locked and fncIsLocked(user):
        logging.debug("User %s already locked; no change", user)
        return
    if not locked and not fncIsLocked(user):
        logging.debug("User %s already unlocked; no change", user)
        return
    rc, _, err = fncRun("usermod", ["-L" if locked else "-U", user])
    if rc != 0:
        logging.error("Failed to %slock user %s: %s", "" if locked else "un", user, err)
    else:
        logging.info("%s user: %s", "Locked" if locked else "Unlocked", user)

# Function: fncLockUser
# Purpose : Backwards-compat helper to lock a user.
# Notes   : Uses fncSetLocked(True).
def fncLockUser(user: str):
    fncSetLocked(user, True)

# Function: fncUnlockUser
# Purpose : Backwards-compat helper to unlock a user.
# Notes   : Uses fncSetLocked(False).
def fncUnlockUser(user: str):
    fncSetLocked(user, False)

# Function: fncDeleteUser
# Purpose : Remove local user and home; clean up sudoers first.
# Notes   : Logs errors; safe if user missing (userdel -r will error, we log).
def fncDeleteUser(user: str):
    fncRemoveSudoers(user)
    rc, _, err = fncRun("userdel", ["-r", user])
    if rc != 0:
        logging.error("Failed to delete user %s: %s", user, err)
    else:
        logging.info("Deleted user (and home): %s", user)

# Function: fncGrantSudo
# Purpose : Ensure a per-user sudoers file exists with desired NOPASSWD policy.
# Notes   : Validates with visudo before atomic replace.
def fncGrantSudo(user: str) -> bool:
    path = f"{MANAGED_SUDOERS_PREFIX}{user}"
    expected = f"{user} ALL=(ALL) {'NOPASSWD:ALL' if SUDO_NOPASSWD else 'ALL'}\n"

    current = ""
    if os.path.exists(path):
        try:
            _assert_regular_or_missing(path)
            with open(path, "r") as f:
                current = f.read()
        except Exception as e:
            logging.error("Failed to read sudoers for %s: %s", user, e)

    if current == expected:
        return False

    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".sudomatic-", dir=d)
    try:
        os.write(fd, expected.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o440)

    rc, _, err = fncRun("visudo", ["-cf", tmp])
    if rc != 0:
        logging.error("visudo validation failed for %s: %s", user, err)
        os.remove(tmp)
        return False

    _assert_regular_or_missing(path)
    os.replace(tmp, path)
    logging.info("Updated sudoers for %s at %s", user, path)
    return True

# Function: fncRemoveSudoers
# Purpose : Remove a managed per-user sudoers file (if present).
# Notes   : No error if missing; logs failures.
def fncRemoveSudoers(user: str):
    path = f"{MANAGED_SUDOERS_PREFIX}{user}"
    try:
        if os.path.exists(path):
            os.remove(path)
            logging.info("Removed sudoers file for %s", user)
    except Exception as e:
        logging.error("Failed removing sudoers for %s: %s", user, e)

# Function: fncGeneratePassword
# Purpose : Generate a random initial password.
# Notes   : Uses secrets.choice over a mixed alphabet; length from PASSWORD_LENGTH.
def fncGeneratePassword(length: int = PASSWORD_LENGTH) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))

# Function: fncSetInitialPassword
# Purpose : Set a random password and force change at next login.
# Notes   : Does not store the password; logs success/fail.
def fncSetInitialPassword(user: str) -> bool:
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

# Function: fncLoadState
# Purpose : Load persistent state (known + disabled users).
# Notes   : Returns defaults on error or missing file.
def fncLoadState() -> dict:
    if not os.path.exists(STATE_PATH):
        return {"known_users": [], "disabled": {}}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"known_users": [], "disabled": {}}

# Function: fncSaveState
# Purpose : Persist state atomically with safe perms.
# Notes   : Uses _safe_write_atomic; keeps a simple tmp swap as belt-and-braces.
def fncSaveState(state: dict):
    data = json.dumps(state, indent=2)
    _safe_write_atomic(STATE_PATH, data, 0o600)

    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_PATH)

# Function: fncPveUseridFromUpn
# Purpose : Build PVE userid ("<upn>@<REALM>") for the configured realm.
# Notes   : Realm must match your Proxmox OpenID realm name.
def fncPveUseridFromUpn(upn: str) -> str:
    return f"{upn}@{REALM}"

# Function: fncPveUserExists
# Purpose : Check if a PVE user exists (fast path via pvesh list).
# Notes   : Avoids 404 spam; scans JSON list instead.
def fncPveUserExists(userid: str) -> bool:
    rc, out, err = fncRun("pvesh", ["get", "/access/users", "--output-format", "json"])
    if rc != 0:
        logging.error("pvesh list users failed: %s", err)
        return False
    try:
        data = json.loads(out)
        return any(u.get("userid") == userid for u in data)
    except Exception:
        return False

# Function: fncPveEnsureUser
# Purpose : Ensure a PVE user exists and is enabled/disabled as requested.
# Notes   : Adds if missing; otherwise delegates to fncPveUserSetEnabled.
def fncPveEnsureUser(upn: str, enabled: bool = True) -> bool:
    userid = fncPveUseridFromUpn(upn)
    if not fncPveUserExists(userid):
        args = ["user", "add", userid, "-enable", "1" if enabled else "0"]
        rc, _, err = fncRun("pveum", args)
        if rc != 0:
            logging.error("PVE user add failed for %s: %s", userid, err)
            return False
        logging.info("PVE user created: %s (enable=%s)", userid, int(enabled))
        return True
    return fncPveUserSetEnabled(upn, enabled)

# Function: fncPveUserSetEnabled
# Purpose : Toggle a PVE users enabled flag if needed.
# Notes   : No-op if already desired state.
def fncPveUserSetEnabled(upn: str, enabled: bool) -> bool:
    userid = fncPveUseridFromUpn(upn)
    rc, out, err = fncRun("pvesh", ["get", "/access/users", "--output-format", "json"])
    if rc != 0:
        logging.error("pvesh list users failed: %s", err)
        return False
    current = None
    try:
        for u in json.loads(out):
            if u.get("userid") == userid:
                v = u.get("enable")
                current = (v is True) or (v == 1) or (str(v) == "1")
                break
    except Exception:
        pass

    if current is not None and current == enabled:
        return False

    rc, _, err = fncRun("pveum", ["user", "modify", userid, "-enable", "1" if enabled else "0"])
    if rc != 0:
        logging.error("PVE user set enabled failed for %s: %s", userid, err)
        return False
    logging.info("PVE user %s set enable=%s", userid, int(enabled))
    return True

# Function: fncPveEnsureAclRoles
# Purpose : Ensure the user has the given PVE roles at path (additive/idempotent).
# Notes   : Does not remove extra roles; safe to re-apply.
def fncPveEnsureAclRoles(userid: str, roles: set[str], path: str = "/") -> None:
    if not roles:
        return
    for role in sorted(roles):
        if not role:
            continue
        rc, _, err = fncRun("pveum", ["acl", "modify", path, "-user", userid, "-role", role])
        if rc != 0:
            logging.error("PVE ACL add failed: user=%s role=%s path=%s err=%s", userid, role, path, err)
        else:
            logging.info("PVE ACL ensured: %s @ %s role=%s", userid, path, role)

#==============================================================#
#                        Microsoft Graph                       #
#==============================================================#
# Function: fncGetGraphClientSecret
# Purpose : Resolve MS Entra client secret from env (plaintext or Fernet-encrypted).
# Notes   : Supports ENTR_CLNT_SEC (plain) or ENTR_CLNT_SEC_ENC="fernet:<token>" with SUDOMATIC_ENC_KEY.
def fncGetGraphClientSecret() -> str | None:
    from cryptography.fernet import Fernet

    plain = os.getenv("ENTR_CLNT_SEC", "").strip()
    if plain:
        return plain
    
    enc = os.getenv("ENTR_CLNT_SEC_ENC", "").strip()
    if enc.startswith("fernet:"):
        key_b64 = os.getenv("SUDOMATIC_ENC_KEY", "").strip()
        if not key_b64:
            logging.error("Missing SUDOMATIC_ENC_KEY for decrypting ENTR_CLNT_SEC_ENC")
            return None
        try:
            token = enc.split(":", 1)[1]
            return Fernet(key_b64.encode()).decrypt(token.encode()).decode()
        except Exception as e:
            logging.error("Failed to decrypt ENTR_CLNT_SEC_ENC: %s", e)
            return None
    if enc:
        logging.error("Unknown ENTR_CLNT_SEC_ENC format (expected 'fernet:...').")
    return None

# Function: fncGraphGetToken
# Purpose : Return a bearer token. Prefer pre-supplied token; else do client-credentials flow.
# Notes   : Logs concise diagnostics; safe error objects are printed for HTTP failures.
def fncGraphGetToken() -> str | None:
    # Prefer a provided bearer
    for name in TOKEN_ENV_FALLBACKS:
        val = os.getenv(name, "").strip()
        if val:
            logging.info("Graph: using provided bearer from %s", name)
            return val

    tenant = os.getenv(ENV_MS_TENANT_ID, "").strip()
    client = os.getenv(ENV_MS_CLIENT_ID, "").strip()
    secret = fncGetGraphClientSecret() or ""

    def _seen(v): return "set" if v else "empty"
    logging.debug("Graph env check: TENANT=%s CLIENT=%s SECRET=%s", _seen(tenant), _seen(client), _seen(secret))

    if not (tenant and client and secret):
        logging.error("Graph creds missing: set one of %s or (%s,%s,%s)",
                      ",".join(TOKEN_ENV_FALLBACKS), ENV_MS_TENANT_ID, ENV_MS_CLIENT_ID, ENV_MS_CLIENT_SECRET)
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

# Function: _graphAuthHeaders
# Purpose : Build standard Graph headers with optional client-request-id.
# Notes   : Keeps Accept JSON and Authorization bearer.
def _graphAuthHeaders(token: str, client_request_id: str | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if client_request_id:
        headers["client-request-id"] = client_request_id
    return headers

# Function: _graphFetchJson
# Purpose : GET JSON from Graph; unify error handling and fail-open policy.
# Notes   : On HTTP errors prints safe JSON error (like fncGraphGetToken) and returns None.
def _graphFetchJson(url: str, headers: dict, client_req_id: str, context: str) -> dict | None:
    try:
        req = _urlreq.Request(url, headers=headers)
        with _urlreq.urlopen(req, timeout=GRAPH_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        rid = e.headers.get("request-id") or e.headers.get("x-ms-request-id")
        try:
            body = e.read().decode(errors="ignore")
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "error" in parsed:
                print(json.dumps(parsed, separators=(',', ':')))
            else:
                _graph_print_error(f"HTTP_{e.code}", f"{context}: {e}", rid, client_req_id)
        except Exception:
            _graph_print_error(f"HTTP_{e.code}", f"{context}: {e}", rid, client_req_id)
        logging.warning("Graph HTTP failure in %s; fail-open.", context)
        return None
    except (URLError, Exception) as e:
        _graph_print_error("ServiceUnavailable", f"{context}: {e}", None, client_req_id)
        logging.warning("Graph unavailable in %s (%s); fail-open.", context, e)
        return None

# Function: fncGraphGetGroupMeta
# Purpose : Return (displayName, mail) for a group; graceful fallback on error.
# Notes   : Uses $select to reduce payload.
def fncGraphGetGroupMeta(group_id: str, token: str) -> tuple[str, str]:
    headers = _graphAuthHeaders(token)
    try:
        meta_req = _urlreq.Request(
            f"https://graph.microsoft.com/v1.0/groups/{group_id}?$select=id,displayName,mail",
            headers=headers
        )
        with _urlreq.urlopen(meta_req, timeout=GRAPH_TIMEOUT) as r:
            meta = json.loads(r.read().decode())
        return meta.get("displayName") or group_id, meta.get("mail") or "-"
    except Exception:
        return group_id, "-"

# Function: fncGraphListGroupUPNs
# Purpose : List user members of a group with enabled flag.
# Notes   : Returns [(upn_lower, accountEnabled_bool)] or None on fail-open.
def fncGraphListGroupUPNs(group_id: str, token: str) -> list[tuple[str, bool]] | None:
    if not token:
        _graph_print_error("InvalidAuthenticationToken", "No access token provided.", None, None)
        logging.warning("Graph: no token; proceeding without enforcement (fail-open).")
        return None

    client_req_id = secrets.token_hex(16)
    headers = _graphAuthHeaders(token, client_req_id)
    url = (
        f"https://graph.microsoft.com/v1.0/groups/{group_id}"
        f"/members/microsoft.graph.user"
        f"?$select=id,displayName,userPrincipalName,accountEnabled&$top=999"
    )

    rows: list[tuple[str, bool]] = []
    allowed_domains = {d.strip().lower() for d in ALLOWED_UPN_DOMAINS if d and d.strip()}

    while url:
        doc = _graphFetchJson(url, headers, client_req_id, context=f"group members {group_id}")
        if doc is None:
            return None

        for item in doc.get("value", []):
            raw_upn = (item.get("userPrincipalName") or "").strip()
            if not raw_upn:
                continue
            upn = raw_upn.lower()
            if allowed_domains:
                dom = upn.split("@", 1)[-1]
                if dom not in allowed_domains:
                    continue
            enabled = bool(item.get("accountEnabled", True))
            rows.append((upn, enabled))

        url = doc.get("@odata.nextLink")

    return rows

# Function: fncGraphFetchGroup
# Purpose : Fetch group metadata + members; map to unix; include upn→enabled map and optional PVE role.
# Notes   : Returns a dict or None (fail-open). Safe to log/report.
def fncGraphFetchGroup(group_id: str, token: str, role_map: dict[str, str] | None = None) -> dict | None:
    name, mail = fncGraphGetGroupMeta(group_id, token)
    rows = fncGraphListGroupUPNs(group_id, token)
    if rows is None:
        _log_group_members(name, "members (FAIL-OPEN)", None)
        return None

    upns = {u for (u, _) in rows}
    _log_group_members(name, "members", upns)
    unix = {fncUpnToUnix(u) for u in upns}
    upn_enabled_map = {u: en for (u, en) in rows}
    pve_role = (role_map or {}).get(group_id, "")

    return {
        "id": group_id,
        "name": name,
        "mail": mail,
        "upns": upns,
        "unix": unix,
        "pve_role": pve_role,
        "upn_enabled": upn_enabled_map,
    }

# Function: fncGraphListManyGroups
# Purpose : Fetch multiple groups with role mapping applied.
# Notes   : Skips groups that fail (fail-open).
def fncGraphListManyGroups(group_ids: list[str], token: str, role_map: dict[str, str] | None = None) -> list[dict]:
    groups: list[dict] = []
    for gid in group_ids:
        gid = gid.strip()
        if not gid:
            continue
        g = fncGraphFetchGroup(gid, token, role_map=role_map)
        if g is not None:
            groups.append(g)
    return groups

# Function: fncPrintGroupReport
# Purpose : Human-readable summary of fetched groups.
# Notes   : Shows role, member count, and a small unix sample.
def fncPrintGroupReport(groups: list[dict]):
    if not groups:
        fncPrintMessage("No Graph groups fetched (fail-open).", "warning")
        return
    fncPrintMessage("Graph Group Report:", "info")
    for g in groups:
        name  = g["name"]
        mail  = g["mail"]
        count = len(g["upns"])
        role  = g.get("pve_role") or "-"
        sample = sorted(list(g["unix"]))[:10]
        fncPrintMessage(f" - {name} <{mail}> role={role} members={count} sample_unix={sample}", "info")

#====================#
# Sync logic         #
#====================#

# Function: _computeDesiredFromGraph
# Purpose : Build the "desired" unix user set and helper maps from fetched Graph groups.
# Notes   : Returns tuple(desired_unix, user_roles_by_upn, unix_to_upn, upn_enabled_map, in_allusers_upn, in_superadmin_upn).
def _computeDesiredFromGraph(groups: list[dict]) -> tuple[set[str], dict[str, set[str]], dict[str, str], dict[str, bool], set[str], set[str]]:
    desired: set[str] = set()
    user_roles_by_upn: dict[str, set[str]] = {}
    unix_to_upn: dict[str, str] = {}
    upn_enabled_global: dict[str, bool] = {}
    in_allusers_upn: set[str] = set()
    in_superadmin_upn: set[str] = set()

    for g in groups or []:
        # Desired unix users is the union of all group unix members
        desired |= set(g.get("unix", set()))

        # Track enabled flags (if any). If a UPN appears in multiple groups, we AND the flags.
        for upn, en in (g.get("upn_enabled") or {}).items():
            upn_enabled_global[upn] = (upn_enabled_global.get(upn, True) and bool(en))

        # Accumulate roles per UPN (only for groups with a mapped role)
        role = (g.get("pve_role") or "").strip()
        for upn in g.get("upns", []):
            if role:
                user_roles_by_upn.setdefault(upn, set()).add(role)
            # map unix back to a representative UPN
            ux = fncUpnToUnix(upn)
            unix_to_upn.setdefault(ux, upn)

        # Track special groups
        if ENTRA_ALLUSERS_GROUP_ID and g.get("id") == ENTRA_ALLUSERS_GROUP_ID:
            in_allusers_upn |= g.get("upns", set())
        if ENTRA_SUPERADMIN_GROUP_ID and g.get("id") == ENTRA_SUPERADMIN_GROUP_ID:
            in_superadmin_upn |= g.get("upns", set())

    return desired, user_roles_by_upn, unix_to_upn, upn_enabled_global, in_allusers_upn, in_superadmin_upn

# Function: _disablePveIfKnown
# Purpose : Try to disable the PVE account for a unix user every run (idempotent).
# Notes   : Resolves UPN via current map or by scanning PVE users; harmless if already disabled.
def _disablePveIfKnown(user: str, unix_to_upn: dict[str, str]):
    upn = unix_to_upn.get(user) or fncResolveUpnForUnix(user)
    if upn:
        if fncPveUserSetEnabled(upn, enabled=False):
            logging.info("PVE user %s disabled (enable=0)", fncPveUseridFromUpn(upn))
        else:
            logging.debug("PVE user already disabled or unchanged: %s", fncPveUseridFromUpn(upn))
    else:
        logging.debug("Could not resolve UPN for unix user %s to disable PVE account.", user)

# Function: _graceDeleteOrCountdown
# Purpose : Enforce the 24h hold → delete lifecycle for users not desired.
# Notes   : Locks when first seen; deletes after DELETE_AFTER; updates disabled/known in-place.
def _graceDeleteOrCountdown(user: str, disabled: dict, known: set, unix_to_upn: dict[str, str]):
    if user in RESERVED_USERS:
        disabled.pop(user, None); known.discard(user); return
    if not fncUserExists(user):
        disabled.pop(user, None); known.discard(user); return

    if user not in disabled:
        fncLockUser(user)
        disabled[user] = _get_utc_datetime().isoformat()
        logging.info("User %s not in Entra allow-groups; locked and marked for deletion in %s",
                     user, str(DELETE_AFTER))
        # NEW: always try to disable PVE now
        _disablePveIfKnown(user, unix_to_upn)
        return

    # Already in grace → keep trying to disable PVE (idempotent) in case mapping failed earlier
    _disablePveIfKnown(user, unix_to_upn)

    # Countdown handling (unchanged)
    try:
        locked_at = _parse_iso_datetime(disabled[user])
    except Exception:
        locked_at = _get_utc_datetime()
        disabled[user] = locked_at.isoformat()

    if _get_utc_datetime() - locked_at >= DELETE_AFTER:
        logging.info("User %s disabled for >= %s; deleting", user, str(DELETE_AFTER))
        fncDeleteUser(user)
        disabled.pop(user, None)
        known.discard(user)
    else:
        remain = DELETE_AFTER - (_get_utc_datetime() - locked_at)
        logging.info("User %s still in grace; %s remaining", user, str(remain).split(".")[0])

# Function: _ensureBaselineGroups
# Purpose : Ensure non-priv groups from EXTRA_GROUPS are present (excluding sudo).
# Notes   : No-ops if EXTRA_GROUPS is empty; avoids adding sudo here on purpose.
def _ensureBaselineGroups(user: str):
    non_priv_groups = [g for g in (EXTRA_GROUPS or []) if g and g != "sudo"]
    if non_priv_groups:
        fncAddUserToGroups(user, non_priv_groups)


# Function: fncSync
# Purpose : Main reconciliation loop. Create/lock/delete local + PVE users according to Entra groups & flags.
# Notes   : Fail-open behavior when Graph not available; preserves existing users in realm to avoid mass-delete.
def fncSync():
    required_bins = ["pvesh","useradd","usermod","userdel","passwd","chage","chpasswd","visudo","getent","id","groupadd","gpasswd"]
    for key in required_bins:
        if not os.path.exists(BIN.get(key, "")):
            logging.error("Missing required binary: %s -> %s", key, BIN.get(key))

    # Load state
    state = fncLoadState()
    known = set(state.get("known_users", []))
    disabled = state.get("disabled", {})  # {username: iso_timestamp_locked}

    # ----------------- Pull Graph -----------------
    groups: list[dict] = []
    token = None
    if GRAPH_ENFORCE and GRAPH_GROUP_IDS:
        token = fncGraphGetToken()
        if token:
            groups = fncGraphListManyGroups(GRAPH_GROUP_IDS, token, role_map=PVE_ROLE_BY_GROUP)
            fncPrintGroupReport(groups)
        else:
            fncPrintMessage("Graph token unavailable: proceeding without enforcement (fail-open).", "warning")

    # Compute desired + helper maps
    desired_unix, user_roles_by_upn, unix_to_upn, upn_enabled_global, in_allusers_upn, in_superadmin_upn = _computeDesiredFromGraph(groups)

    # Fallback if Graph empty/unavailable: keep current realm users to avoid mass-delete
    if not desired_unix:
        desired_unix = fncGetPveUsersForRealm(REALM)
        logging.warning("Graph empty/unavailable; falling back to PVE realm users as desired.")
    logging.info("Desired (unix)=%s", sorted(desired_unix))

    # Candidates we might need to hold if not desired
    realm_present = fncGetPveUsersForRealm(REALM)
    candidates = known | realm_present

    # ----------------- 1) Hold/Delete: users not in any allowed group -----------------
    to_hold = (candidates | known) - desired_unix
    for user in sorted(to_hold):
        _graceDeleteOrCountdown(user, disabled, known, unix_to_upn)

    # ----------------- 2) Ensure/Create: users in allowed groups -----------------
    for user in sorted(desired_unix):
        if user in RESERVED_USERS:
            continue

        # Create if missing, then set initial password
        if not fncUserExists(user):
            if fncCreateUser(user):
                fncSetInitialPassword(user)

        # Map back to UPN for decisions; default to True when flags missing
        upn = unix_to_upn.get(user)
        entra_enabled = upn_enabled_global.get(upn, True) if upn is not None else True

        if not entra_enabled:
            # Entra account disabled but still in groups → disable locally (no delete countdown)
            fncLockUser(user)
            if user not in disabled:
                disabled[user] = _get_utc_datetime().isoformat()
            if upn:
                fncPveUserSetEnabled(upn, enabled=False)
            fncRemoveSudoers(user)
            fncRemoveUserFromGroup(user, "sudo")
            known.add(user)
            continue

        # Entra enabled → ensure unlocked and baseline non-priv groups
        fncUnlockUser(user)
        _ensureBaselineGroups(user)

        # SUDO policy: only superadmins get sudo + optional sudoers file
        is_superadmin = (upn in in_superadmin_upn) if upn else False
        if is_superadmin:
            fncAddUserToGroups(user, ["sudo"])
            if GRANT_SUDO:
                fncGrantSudo(user)
        else:
            fncRemoveSudoers(user)
            fncRemoveUserFromGroup(user, "sudo")

        # PVE user ensure + roles
        if upn:
            try:
                fncPveEnsureUser(upn, enabled=True)
                roles = set(user_roles_by_upn.get(upn, set()))

                # If user ends up only in AllUsers and it has a mapped role, ensure it
                if (upn in in_allusers_upn) and ENTRA_ALLUSERS_PVE_ROLE:
                    if not roles:
                        roles = {ENTRA_ALLUSERS_PVE_ROLE}
                    # else: AllUsers may be additive; leave as-is unless you want exact sync

                if roles:
                    fncPveEnsureAclRoles(fncPveUseridFromUpn(upn), roles, path="/")
                # NOTE: If you want *exact* role sync (remove extras), we can add an ACL prune helper.
            except Exception as e:
                logging.error("PVE provisioning failed for %s: %s", upn, e)

        # Clear “disabled” state if present and mark known
        disabled.pop(user, None)
        known.add(user)

    # ----------------- Persist -----------------
    state["known_users"] = sorted(known)
    state["disabled"] = disabled
    fncSaveState(state)
    logging.info("Sync complete. Known=%d, Desired=%d, Disabled=%d", len(known), len(desired_unix), len(disabled))

#=================#
# Script harness  #
#=================#

# Function: fncMain
# Purpose : Program entrypoint; preflight checks, logging, locking, sync, robust error handling.
# Notes   : Uses umask(077) to protect any new files.
def fncMain():
    try:
        os.umask(0o077)
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
