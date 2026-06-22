#!/usr/bin/env python3
# Script: entramoxreconciler.py
# Developed by Dean with a bit of love and Irn Bru
#
# What this does (for my future self):
# - Pull PVE users from my OpenID realm (e.g. USER@DOMAIN.com@SSOREALM)
# - Map UPN -> sensible Unix username (config)
# - Create local users if missing, set a random password, and expire it immediately 
# - Add groups + per-user sudoers (only writes if needed)
# - If a user disappears from the realm: lock them, then delete after 24h
# - Logs to /var/log/entramoxreconciler/thelog.log

# ==============================
# Imports
# ==============================

# Standard library
import fcntl
import fnmatch
import json
import logging
import os
import re
import secrets
import ssl
import stat
import string
import subprocess
import sys
import tempfile
import time as _time_module
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

LOG_FILE = "/var/log/entramoxreconciler/thelog.log"
STATE_DIR = "/var/lib/entramoxreconciler/pve_oidc_sync"
STATE_PATH = os.path.join(STATE_DIR, "state.json")
LOCK_PATH  = os.path.join(STATE_DIR, ".lock")
MANAGED_SUDOERS_PREFIX = "/etc/sudoers.d/pve_realm-"
TIERED_SSHD_DROPIN = "/etc/ssh/sshd_config.d/99-entramox-tiered.conf"

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
# UPN > Unix mapping behaviour #
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
  "sshd":     "/usr/sbin/sshd",
  "systemctl":"/usr/bin/systemctl",
}

#-----------------------------------------#
# Tiered Accounts (privilege separation)  #
#-----------------------------------------#
# When enabled, superadmin users get a second account with a prefix/suffix
# (e.g. "a-john") that holds sudo and elevated access. The base account
# is left without privileges, enforcing least-privilege separation.
TIERED_ACCOUNTS      = False       # Create a privileged twin account for superadmins
TIERED_ACCOUNT_MODE  = "prefix"    # "prefix" or "suffix"
TIERED_ACCOUNT_VALUE = ""          # e.g. "a-" (prefix) or "-adm" (suffix)
TIERED_ACCOUNT_SCOPE = "linux"     # "linux" (Linux only) or "both" (Linux + Proxmox/PBS/PDM)
TIERED_SSH_DENY_DIRECT = False     # Block direct SSH login for tiered accounts; operators log
                                   # in with the base account and escalate locally (su - <tiered>,
                                   # then sudo -i). Writes a managed sshd_config.d drop-in.

#--------------------------------------------#
# Proxmox Backup Server (PBS) integration    #
#--------------------------------------------#
PBS_ENABLED          = False
PBS_HOST             = ""
PBS_PORT             = 8007
PBS_REALM            = ""          # PBS realm for synced users (leave blank to use REALM)
PBS_API_USER         = ""          # e.g. "root@pam"
PBS_TOKEN_NAME       = ""          # API token name
PBS_TOKEN_VALUE_ENC  = ""          # Fernet-encrypted token value (or plaintext)
PBS_DEFAULT_ROLE     = "DatastoreReader"  # Default PBS role for all users
PBS_ADMIN_ROLE       = "DatastoreAdmin"   # PBS role for superadmins
PBS_VERIFY_TLS       = True        # Set False for self-signed certs

#--------------------------------------------------#
# Proxmox Datacenter Manager (PDM) integration     #
#--------------------------------------------------#
PDM_ENABLED          = False
PDM_HOST             = ""
PDM_PORT             = 8443
PDM_REALM            = ""          # PDM realm (leave blank to use REALM)
PDM_API_USER         = ""
PDM_TOKEN_NAME       = ""
PDM_TOKEN_VALUE_ENC  = ""
PDM_DEFAULT_ROLE     = "DCOperator"
PDM_ADMIN_ROLE       = "DCAdmin"
PDM_VERIFY_TLS       = True

#---------------------------#
# Security audit log        #
#---------------------------#
AUDIT_LOG = "/var/log/entramoxreconciler/audit.log"

#-------------------------------------------#
# Secret rotation / Fernet TTL enforcement  #
#-------------------------------------------#
# Fernet tokens older than this many days will be rejected outright.
# Set to 0 to disable TTL enforcement (not recommended).
FERNET_MAX_AGE_DAYS = 365

#---------------------------------------------#
# Microsoft Graph (client-credentials via env)#
#---------------------------------------------#
GRAPH_ENFORCE = True
GRAPH_FAIL_OPEN = True        # Legacy boolean; prefer GRAPH_FAIL_POLICY below
GRAPH_FAIL_POLICY = "permissive"  # "permissive" (warn+continue) | "strict" (abort on Graph failure)

GRAPH_GROUP_IDS = []    # Parsed below from ENTRA_* vars
GRAPH_TIMEOUT = 8       # Seconds

#----------------------------------------#
# Safety limits                          #
#----------------------------------------#
# Maximum users that may be CREATED in a single run.
# Prevents a compromised Entra group from mass-provisioning accounts.
# Set to 0 to disable (not recommended in production).
MAX_USERS_PER_RUN = 50

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
    """Acquire an exclusive lock to prevent concurrent runs.

    Stale-lock protection: if the lock file is older than STALE_LOCK_SECONDS and
    is not held by any process (LOCK_NB succeeds after removing it), we log a
    warning and proceed.  This prevents permanent deadlock after a crash.
    """
    STALE_LOCK_SECONDS = 600  # 10 minutes - well above any normal run time
    os.makedirs(STATE_DIR, exist_ok=True)
    global _LOCK_FH
    try:
        _LOCK_FH = open(LOCK_PATH, "w")
        os.chmod(LOCK_PATH, 0o600)
        fcntl.lockf(_LOCK_FH, fcntl.LOCK_EX | fcntl.LOCK_NB)
        logging.debug("Acquired lock: %s", LOCK_PATH)
    except BlockingIOError:
        # Check if the existing lock is stale (process crashed without releasing)
        try:
            age = _get_utc_datetime().timestamp() - os.path.getmtime(LOCK_PATH)
            if age > STALE_LOCK_SECONDS:
                logging.warning(
                    "Stale lock detected at %s (age=%.0fs > %ds); removing and retrying.",
                    LOCK_PATH, age, STALE_LOCK_SECONDS
                )
                try:
                    _LOCK_FH.close()
                except Exception:
                    pass
                os.remove(LOCK_PATH)
                _LOCK_FH = open(LOCK_PATH, "w")
                os.chmod(LOCK_PATH, 0o600)
                fcntl.lockf(_LOCK_FH, fcntl.LOCK_EX | fcntl.LOCK_NB)
                logging.info("Acquired lock after stale removal: %s", LOCK_PATH)
                return
        except BlockingIOError:
            pass
        except Exception as e:
            logging.debug("Stale lock check error: %s", e)
        fncPrintMessage("Another instance of entramoxreconciler is already running.", "warning")
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

# Function: _mask_upn
# Purpose : Partially redact a UPN to avoid PII leakage in logs.
# Notes   : Only applied to INFO-level log output; DEBUG may show full UPNs
#           when LOGGING_LEVEL=DEBUG is explicitly set by the operator.
def _mask_upn(upn: str, keep: int = 3) -> str:
    if "@" not in upn:
        return upn[:keep] + "***" if len(upn) > keep else upn
    local, domain = upn.split("@", 1)
    masked_local = local[:keep] + "***" if len(local) > keep else local
    return f"{masked_local}@{domain}"

# Function: _log_group_members
# Purpose : Summarise group membership without persisting to disk.
# Notes   : INFO shows counts + masked UPN samples; DEBUG logs full lists.
def _log_group_members(name: str, purpose: str, upns: set[str] | None, sample: int = 20):
    if upns is None:
        logging.info("Graph group '%s' (%s): fetch failed (fail-open)", name, purpose)
        return

    count = len(upns)
    upn_list = sorted(upns)
    unix_list = sorted({fncUpnToUnix(u) for u in upns})

    # INFO: count + small masked samples (no PII in prod logs)
    masked_upn_sample = [_mask_upn(u) for u in upn_list[:sample]]
    info_unix_sample  = unix_list[:sample]
    logging.info(
        "Graph group '%s' (%s): members=%d | unix_sample=%s | upn_sample=%s",
        name, purpose, count, info_unix_sample, masked_upn_sample
    )

    # DEBUG: full unmasked lists (only emitted when operator sets DEBUG logging)
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

def _http_with_retry(req, timeout: int, context=None, max_retries: int = 3, label: str = ""):
    """Open an HTTP request with exponential backoff retry.

    Retries on transient network/server errors (URLError, 5xx).
    Does NOT retry 4xx responses (auth/client errors are permanent).
    Returns the response object on success, raises on final failure.

    Backoff: 1s, 2s, 4s between attempts (capped at max_retries total calls).
    """
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            return _urlreq.urlopen(req, timeout=timeout, context=context)
        except HTTPError as e:
            if 400 <= e.code < 500:
                raise  # Client errors are permanent; do not retry
            last_exc = e
            if attempt < max_retries:
                wait = 2 ** (attempt - 1)
                logging.warning(
                    "HTTP %s on attempt %d/%d%s; retrying in %ds",
                    e.code, attempt, max_retries,
                    f" [{label}]" if label else "", wait
                )
                _time_module.sleep(wait)
        except URLError as e:
            last_exc = e
            if attempt < max_retries:
                wait = 2 ** (attempt - 1)
                logging.warning(
                    "Network error on attempt %d/%d%s: %s; retrying in %ds",
                    attempt, max_retries,
                    f" [{label}]" if label else "", e, wait
                )
                _time_module.sleep(wait)
        except Exception:
            raise
    raise last_exc  # type: ignore[misc]


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

def _pickSourceGroupName(upn: str, groups: list[dict]) -> str | None:
    """Return the first Graph group displayName that contains this UPN (case-insensitive)."""
    upn_l = (upn or "").strip().lower()
    if not upn_l:
        return None

    for g in groups or []:
        members = g.get("members") or []
        if not isinstance(members, list):
            continue

        for row in members:
            if not isinstance(row, (list, tuple)) or not row:
                continue
            member_upn = (row[0] or "").strip().lower()
            if member_upn == upn_l:
                return (g.get("name") or g.get("id") or None)

    return None

def _pickAllSourceGroupNames(upn: str, groups: list[dict]) -> list[str]:
    """Return ALL Graph group displayNames that contain this UPN (case-insensitive)."""
    upn_l = (upn or "").strip().lower()
    if not upn_l:
        return []
    names: list[str] = []
    for g in groups or []:
        members = g.get("members") or []
        if not isinstance(members, list):
            continue
        for row in members:
            if not isinstance(row, (list, tuple)) or not row:
                continue
            member_upn = (row[0] or "").strip().lower()
            if member_upn == upn_l:
                name = g.get("name") or g.get("id") or None
                if name and name not in names:
                    names.append(name)
                break
    return names

def fncMakeTieredUsername(base_unix: str) -> str:
    """
    Apply the configured prefix or suffix to a base unix username for tiered accounts.
    Returns the base username unchanged if tiered accounts are disabled or value is empty.
    """
    if not TIERED_ACCOUNTS or not TIERED_ACCOUNT_VALUE:
        return base_unix
    if TIERED_ACCOUNT_MODE == "suffix":
        raw = f"{base_unix}{TIERED_ACCOUNT_VALUE}"
    else:
        raw = f"{TIERED_ACCOUNT_VALUE}{base_unix}"
    # Tiered account names are always lowercased, independent of USERNAME_LOWERCASE,
    # so an admin-configured TIERED_ACCOUNT_VALUE with capitals can't leak through.
    return fncSanitiseUnix(raw.lower())

def _tieredSshGlob() -> str | None:
    """
    Build the sshd DenyUsers glob that matches every tiered account, derived
    from TIERED_ACCOUNT_VALUE. The token is sanitised with the same rules as
    fncMakeTieredUsername (lowercase, '.'->'_', disallowed chars -> '_') so the
    pattern matches the names actually created. Returns None when tiered
    accounts are disabled or no non-empty value is configured -- callers MUST
    treat None as "do not write a rule" (never fall back to '*').
    """
    if not TIERED_ACCOUNTS or not TIERED_ACCOUNT_VALUE:
        return None
    tok = TIERED_ACCOUNT_VALUE.replace(".", "_").lower()
    tok = re.sub(r"[^a-z0-9._-]", "_", tok)
    if not tok:
        return None
    return f"*{tok}" if TIERED_ACCOUNT_MODE == "suffix" else f"{tok}*"

def _reloadSshd(reason: str) -> bool:
    """Validate sshd config (sshd -t) then reload; never reload an invalid config."""
    rc, _, err = fncRun("sshd", ["-t"])
    if rc != 0:
        logging.error("sshd config validation failed (%s); NOT reloading: %s", reason, err)
        return False
    rc, _, err = fncRun("systemctl", ["reload", "ssh"])
    if rc != 0:
        logging.error("sshd config valid but 'systemctl reload ssh' failed (%s): %s "
                      "-- rule will apply on next sshd restart", reason, err)
        return False
    logging.info("Reloaded sshd (%s)", reason)
    return True

def _removeTieredSshDeny():
    """Remove the managed sshd drop-in (feature disabled / cleanup) and reload."""
    if not os.path.exists(TIERED_SSHD_DROPIN):
        return
    try:
        _assert_regular_or_missing(TIERED_SSHD_DROPIN)
        os.remove(TIERED_SSHD_DROPIN)
        logging.info("Removed tiered SSH deny drop-in %s", TIERED_SSHD_DROPIN)
        fncAuditEvent("TIERED_SSH_DENY_REMOVED", {"path": TIERED_SSHD_DROPIN})
        _reloadSshd("tiered SSH deny removed")
    except Exception as e:
        logging.error("Failed removing %s: %s", TIERED_SSHD_DROPIN, e)

def fncApplyTieredSshDeny():
    """
    Reconcile the managed sshd drop-in that blocks DIRECT SSH login for tiered
    accounts. The accounts stay fully usable locally (su - <tiered>, then
    sudo -i) -- only the SSH entry point is closed, so privilege escalation
    must go through the unprivileged base account.

    Idempotent: only writes + reloads when the rendered file actually changes.
    Validates with `sshd -t` before reloading and rolls the file back if the
    resulting config is invalid, so a bad pattern can never lock the host out.
    """
    if not TIERED_SSH_DENY_DIRECT:
        _removeTieredSshDeny()
        return

    glob = _tieredSshGlob()
    if not glob or glob == "*":
        # No safe pattern (tiered accounts off, or empty/degenerate value).
        # Refuse rather than emit 'DenyUsers *', which would lock everyone out.
        logging.warning(
            "TIERED_SSH_DENY_DIRECT enabled but no safe tiered pattern could be "
            "derived (check TIERED_ACCOUNTS / TIERED_ACCOUNT_VALUE); not writing %s",
            TIERED_SSHD_DROPIN,
        )
        _removeTieredSshDeny()
        return

    # Lock-out guard: refuse if the pattern would also block root or is too broad.
    if fnmatch.fnmatch("root", glob):
        logging.error(
            "Refusing to write %s: tiered pattern %r also matches 'root' "
            "(pick a more specific TIERED_ACCOUNT_VALUE)",
            TIERED_SSHD_DROPIN, glob,
        )
        return

    content = (
        "# Managed by EntramoxReconciler -- do NOT edit by hand.\n"
        "# Tiered admin accounts must not be reachable via direct SSH.\n"
        "# Operators log in with their unprivileged base account and escalate\n"
        "# locally:  su - <tiered-account>  then  sudo -i\n"
        f"DenyUsers {glob}\n"
    )

    prev_existed = os.path.exists(TIERED_SSHD_DROPIN)
    prev_content = ""
    if prev_existed:
        try:
            _assert_regular_or_missing(TIERED_SSHD_DROPIN)
            with open(TIERED_SSHD_DROPIN, "r") as f:
                prev_content = f.read()
        except Exception as e:
            logging.error("Failed reading %s: %s", TIERED_SSHD_DROPIN, e)

    if prev_existed and prev_content == content:
        return  # already in the desired state -- no write, no reload

    d = os.path.dirname(TIERED_SSHD_DROPIN)
    if not os.path.isdir(d):
        logging.error("sshd drop-in dir %s missing; is OpenSSH installed with "
                      "'Include %s/*.conf'? Skipping tiered SSH deny.", d, d)
        return

    _safe_write_atomic(TIERED_SSHD_DROPIN, content, 0o644)

    rc, _, err = fncRun("sshd", ["-t"])
    if rc != 0:
        # Roll back so a broken include can never break the running sshd.
        logging.error("sshd rejected %s (%s); rolling back", TIERED_SSHD_DROPIN, err)
        try:
            if prev_existed:
                _safe_write_atomic(TIERED_SSHD_DROPIN, prev_content, 0o644)
            else:
                os.remove(TIERED_SSHD_DROPIN)
        except Exception as e:
            logging.error("Rollback of %s failed: %s", TIERED_SSHD_DROPIN, e)
        return

    logging.info("Wrote tiered SSH deny rule to %s (DenyUsers %s)",
                 TIERED_SSHD_DROPIN, glob)
    fncAuditEvent("TIERED_SSH_DENY_APPLIED",
                  {"path": TIERED_SSHD_DROPIN, "pattern": glob})
    _reloadSshd("tiered SSH deny applied")

def _lookupUserMeta(upn: str, groups: list[dict]) -> dict:
    """
    Merge metadata for a user across groups; prefer non-empty fields.
    Expected meta keys: givenName, surname, mail, displayName (but we don't enforce).
    """
    upn_l = (upn or "").strip().lower()
    if not upn_l:
        return {}

    best: dict = {}

    def _prefer(dst: dict, src: dict):
        # Copy any key that is missing/blank in dst but present in src
        for k, v in (src or {}).items():
            if v is None:
                continue
            if isinstance(v, str):
                if not v.strip():
                    continue
                if not str(dst.get(k, "")).strip():
                    dst[k] = v
            else:
                if k not in dst:
                    dst[k] = v

    for g in groups or []:
        members = g.get("members") or []
        if not isinstance(members, list):
            continue

        for row in members:
            if not isinstance(row, (list, tuple)) or len(row) < 3:
                continue

            member_upn = (row[0] or "").strip().lower()
            meta = row[2]
            if member_upn == upn_l and isinstance(meta, dict):
                _prefer(best, meta)

                # fast exit if we already have the main fields
                if all(str(best.get(k, "")).strip() for k in ("mail", "givenName", "surname", "displayName")):
                    return best

    return best

def _graphFailOrWarn(message: str):
    """Enforce GRAPH_FAIL_POLICY.

    permissive: warn and continue using stale state (legacy default).
    strict:     abort the run - stale state must NOT be trusted when Graph
                is unreachable, as group removals would not be detected.
    """
    if GRAPH_FAIL_POLICY == "strict":
        logging.error("GRAPH_FAIL_POLICY=strict: %s - aborting run.", message)
        fncPrintMessage(f"[strict] {message}", "error")
        fncAuditEvent("GRAPH_STRICT_ABORT", {"reason": message})
        sys.exit(2)

    logging.warning("GRAPH_FAIL_POLICY=permissive: %s - continuing with stale state.", message)
    fncPrintMessage(message, "warning")

def _buildPveMetaForUpn(upn: str, groups: list[dict]) -> tuple[dict, str]:
    """
    Return (meta_dict, comment_str) for a UPN using Graph group data.
    The comment lists ALL groups the user was sourced from so the description
    clearly shows which groups granted the account.
    """
    src_labels: list[str] = []
    meta: dict = {}

    try:
        src_labels = _pickAllSourceGroupNames(upn, groups) if groups else []
        meta = _lookupUserMeta(upn, groups) if groups else {}
    except Exception as e:
        logging.debug("Metadata lookup failed for %s: %s", upn, e)

    if src_labels:
        if len(src_labels) == 1:
            comment = f"Synced from Entra via '{src_labels[0]}' Group"
        else:
            groups_str = ", ".join(f"'{n}'" for n in src_labels)
            comment = f"Synced from Entra via Groups: {groups_str}"
    else:
        comment = "Synced from Entra"
    return meta, comment

def _format_remaining(td: timedelta) -> str:
    """
    Format a timedelta as 'Xh Ym'.
    Floors minutes; never shows negatives.
    """
    total_seconds = max(0, int(td.total_seconds()))
    hours, rem = divmod(total_seconds, 3600)
    minutes, _ = divmod(rem, 60)
    return f"{hours}h {minutes}m"

def _setPveDeletionComment(user: str, locked_at: datetime, unix_to_upn: dict[str, str],
                           src_labels: list[str] | None = None):
    upn = unix_to_upn.get(user) or fncResolveUpnForUnix(user)
    if not upn:
        logging.debug("Cannot set deletion comment; no UPN for %s", user)
        return

    now = _get_utc_datetime()
    remaining = DELETE_AFTER - (now - locked_at)
    remaining_str = _format_remaining(remaining)

    if src_labels:
        if len(src_labels) == 1:
            group_part = f"'{src_labels[0]}' Group"
        else:
            group_part = "Groups: " + ", ".join(f"'{n}'" for n in src_labels)
    else:
        group_part = "Entra allow-groups"

    comment = (
        f"User no longer in {group_part} – "
        f"marked for deletion in {remaining_str}"
    )

    try:
        fncPveUserModify(upn, comment=comment)
    except Exception as e:
        logging.error("Failed to set deletion comment for %s: %s", upn, e)


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

# GRAPH_FAIL_POLICY overrides the legacy GRAPH_FAIL_OPEN boolean.
# "strict"     > abort run if Graph is unreachable or returns empty data
# "permissive" > warn and continue using stale state (legacy default)
_gfp = os.getenv("GRAPH_FAIL_POLICY", "").strip().lower()
if _gfp in ("strict", "permissive"):
    GRAPH_FAIL_POLICY = _gfp
    GRAPH_FAIL_OPEN   = (_gfp == "permissive")
else:
    # Back-derive policy from the legacy boolean for backwards compatibility
    GRAPH_FAIL_POLICY = "permissive" if GRAPH_FAIL_OPEN else "strict"

# Safety cap on user creation per run
_mup = os.getenv("MAX_USERS_PER_RUN", "").strip()
if _mup and _mup.isdigit():
    MAX_USERS_PER_RUN = int(_mup)

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

# Tiered accounts
TIERED_ACCOUNTS      = _env_bool("TIERED_ACCOUNTS",      TIERED_ACCOUNTS)
TIERED_ACCOUNT_MODE  = _env_str ("TIERED_ACCOUNT_MODE",  TIERED_ACCOUNT_MODE)
TIERED_ACCOUNT_VALUE = _env_str ("TIERED_ACCOUNT_VALUE", TIERED_ACCOUNT_VALUE)
TIERED_ACCOUNT_SCOPE = _env_str ("TIERED_ACCOUNT_SCOPE", TIERED_ACCOUNT_SCOPE)
TIERED_SSH_DENY_DIRECT = _env_bool("TIERED_SSH_DENY_DIRECT", TIERED_SSH_DENY_DIRECT)

# PBS
PBS_ENABLED         = _env_bool("PBS_ENABLED",         PBS_ENABLED)
PBS_HOST            = _env_str ("PBS_HOST",            PBS_HOST)
PBS_PORT            = int(os.getenv("PBS_PORT",        str(PBS_PORT)) or PBS_PORT)
PBS_REALM           = _env_str ("PBS_REALM",           PBS_REALM)
PBS_API_USER        = _env_str ("PBS_API_USER",        PBS_API_USER)
PBS_TOKEN_NAME      = _env_str ("PBS_TOKEN_NAME",      PBS_TOKEN_NAME)
PBS_TOKEN_VALUE_ENC = _env_str ("PBS_TOKEN_VALUE_ENC", PBS_TOKEN_VALUE_ENC)
PBS_DEFAULT_ROLE    = _env_str ("PBS_DEFAULT_ROLE",    PBS_DEFAULT_ROLE)
PBS_ADMIN_ROLE      = _env_str ("PBS_ADMIN_ROLE",      PBS_ADMIN_ROLE)
PBS_VERIFY_TLS      = _env_bool("PBS_VERIFY_TLS",      PBS_VERIFY_TLS)

# PDM
PDM_ENABLED         = _env_bool("PDM_ENABLED",         PDM_ENABLED)
PDM_HOST            = _env_str ("PDM_HOST",            PDM_HOST)
PDM_PORT            = int(os.getenv("PDM_PORT",        str(PDM_PORT)) or PDM_PORT)
PDM_REALM           = _env_str ("PDM_REALM",           PDM_REALM)
PDM_API_USER        = _env_str ("PDM_API_USER",        PDM_API_USER)
PDM_TOKEN_NAME      = _env_str ("PDM_TOKEN_NAME",      PDM_TOKEN_NAME)
PDM_TOKEN_VALUE_ENC = _env_str ("PDM_TOKEN_VALUE_ENC", PDM_TOKEN_VALUE_ENC)
PDM_DEFAULT_ROLE    = _env_str ("PDM_DEFAULT_ROLE",    PDM_DEFAULT_ROLE)
PDM_ADMIN_ROLE      = _env_str ("PDM_ADMIN_ROLE",      PDM_ADMIN_ROLE)
PDM_VERIFY_TLS      = _env_bool("PDM_VERIFY_TLS",      PDM_VERIFY_TLS)

# Fernet secret rotation enforcement
_fernet_age = os.getenv("FERNET_MAX_AGE_DAYS", "").strip()
if _fernet_age and _fernet_age.isdigit():
    FERNET_MAX_AGE_DAYS = int(_fernet_age)

# Map group > PVE role (only non-empty)
PVE_ROLE_BY_GROUP = {
    (m.get("group") or "").strip(): (m.get("pve_role") or "")
    for m in (ENTRA_ROLE_MAP or [])
    if (m.get("group") or "").strip()
}

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
#           Audit log created 0640 (root:adm) so local users cannot read
#           provisioning events but the adm group can forward them to SIEM.
def fncBootstrapPaths():
    log_dir = os.path.dirname(LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
    os.chmod(log_dir, 0o750)
    os.chmod(STATE_DIR, 0o750)
    # Pre-create the audit log with strict permissions so the first fncAuditEvent()
    # call inherits 0640 rather than the process umask.
    if not os.path.exists(AUDIT_LOG):
        try:
            fd = os.open(AUDIT_LOG, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o640)
            os.close(fd)
        except Exception as e:
            logging.warning("Could not pre-create audit log %s: %s", AUDIT_LOG, e)

# Function: fncEnsureLogrotate
# Purpose : Drop a logrotate file so the log doesn't grow to wales.
# Notes   : Creates once; ignores errors (warns only).
def fncEnsureLogrotate():
    path = "/etc/logrotate.d/entramoxreconciler"
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
    logging.info(
        "Security policy: GRAPH_FAIL_POLICY=%s MAX_USERS_PER_RUN=%s FERNET_MAX_AGE_DAYS=%s",
        GRAPH_FAIL_POLICY,
        str(MAX_USERS_PER_RUN) if MAX_USERS_PER_RUN else "unlimited",
        FERNET_MAX_AGE_DAYS,
    )
    fncEnsureLogrotate()
    # Warn at startup if TLS verification is disabled for any remote system
    if PBS_ENABLED and not PBS_VERIFY_TLS:
        msg = "TLS verification disabled for PBS (PBS_VERIFY_TLS=false) - MITM risk"
        logging.warning(msg)
        fncAuditEvent("TLS_DISABLED", {"system": "PBS", "host": PBS_HOST})
    if PDM_ENABLED and not PDM_VERIFY_TLS:
        msg = "TLS verification disabled for PDM (PDM_VERIFY_TLS=false) - MITM risk"
        logging.warning(msg)
        fncAuditEvent("TLS_DISABLED", {"system": "PDM", "host": PDM_HOST})

# Function: fncAuditEvent
# Purpose : Write a structured security audit event to the audit log (JSON-lines format).
# Notes   : One JSON object per line; suitable for SIEM ingestion.
def fncAuditEvent(event: str, details: dict | None = None):
    record = {
        "ts":    datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "event": event,
    }
    if details:
        record.update(details)
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(record, separators=(',', ':')) + "\n")
    except Exception as e:
        logging.warning("Could not write audit event %s: %s", event, e)

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
    """
    Map a UPN (user@domain) to the Unix login format you want.
    Modes:
      - useronly   : "user@domain"      -> "user"
      - upn_concat : "user@domain"      -> "user<sep>domain"
    """
    upn = (upn or "").strip()
    if not upn:
        return ""

    if "@" not in upn:
        # Not a UPN; just sanitise as-is
        return fncSanitiseUnix(upn)

    user, dom = upn.split("@", 1)
    user = user.strip()
    dom  = dom.strip()

    mode = (USERNAME_MODE or "useronly").strip().lower()

    if mode == "upn_concat":
        sep = USERNAME_SEPARATOR if USERNAME_SEPARATOR else "_"
        raw = f"{user}{sep}{dom}"
        return fncSanitiseUnix(raw)

    # default: useronly
    return fncSanitiseUnix(user)

def fncPveUserModify(upn: str,
                     email: str | None = None,
                     comment: str | None = None,
                     firstname: str | None = None,
                     lastname: str | None = None) -> bool:
    """
    Update PVE user metadata (email/comment/firstname/lastname). No-op if nothing passed.
    """
    args = ["user", "modify", fncPveUseridFromUpn(upn)]
    if email is not None:
        args += ["-email", email]
    if comment:
        args += ["-comment", comment]
    if firstname is not None:
        args += ["-firstname", firstname]
    if lastname is not None:
        args += ["-lastname", lastname]

    if len(args) == 3:  # nothing to change
        return False

    rc, _, err = fncRun("pveum", args)
    if rc != 0:
        logging.error("PVE user modify failed for %s: %s", upn, err)
        return False
    logging.info("PVE user metadata updated: %s (email=%s comment=%s)", upn, bool(email), bool(comment))
    return True

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

def fncGetAllPveUsersForRealm(realm: str) -> set[str]:
    """
    List ALL PVE users in REALM (enabled or disabled), filter by allowed UPN domains, map to unix.
    """
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

        if user_realm != realm or not upn:
            continue

        dom_ok = True
        if "@" in upn:
            dom_ok = _allowed_domain(upn.split("@", 1)[1])
        if not dom_ok:
            continue

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

# Function: fncGetLinuxGecos
# Purpose : Read the GECOS (comment) field from /etc/passwd for a user.
# Notes   : Uses getent to avoid importing the pwd module.
def fncGetLinuxGecos(user: str) -> str:
    rc, out, _ = fncRun("getent", ["passwd", user])
    if rc != 0 or not out:
        return ""
    parts = out.split(":", 6)
    return parts[4] if len(parts) >= 5 else ""

# Function: fncSetLinuxGecos
# Purpose : Update the GECOS (comment) field of a Linux user showing their source group(s).
# Notes   : Idempotent (reads current value first); colons are replaced with semicolons.
def fncSetLinuxGecos(user: str, comment: str) -> bool:
    safe_comment = (comment or "").replace(":", ";").replace("\n", " ").strip()
    if not safe_comment:
        return False
    current = fncGetLinuxGecos(user)
    if current == safe_comment:
        return False
    rc, _, err = fncRun("usermod", ["-c", safe_comment, user])
    if rc != 0:
        logging.error("Failed to set GECOS for %s: %s", user, err)
        return False
    logging.debug("Updated GECOS for %s: %s", user, safe_comment)
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
        fncAuditEvent("GROUP_REMOVED", {"user": user, "group": group})
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
        fncAuditEvent("USER_DELETED", {"user": user})

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
    fd, tmp = tempfile.mkstemp(prefix=".entramoxreconciler-", dir=d)
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
    fncAuditEvent("SUDO_GRANTED", {"user": user, "path": path})
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
            fncAuditEvent("SUDO_REVOKED", {"user": user, "path": path})
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
# Purpose : Load persistent state (known + disabled users + tiered accounts).
# Notes   : Returns defaults when file is absent.
#           ABORTS (CRITICAL) when the file exists but cannot be parsed - a corrupt
#           state file must be investigated rather than silently discarded, because
#           doing so could cause mass re-provisioning or missed deletions.
def fncLoadState() -> dict:
    defaults = {"known_users": [], "disabled": {}, "tiered_users": []}
    if not os.path.exists(STATE_PATH):
        return defaults
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Back-fill any keys missing from older state files
        for k, v in defaults.items():
            data.setdefault(k, v)
        return data
    except json.JSONDecodeError as e:
        logging.critical(
            "State file %s is corrupt and cannot be parsed: %s - "
            "repair or remove the file before restarting. Aborting to avoid data loss.",
            STATE_PATH, e
        )
        sys.exit(3)
    except Exception as e:
        logging.critical("Failed to read state file %s: %s - aborting.", STATE_PATH, e)
        sys.exit(3)

# Function: fncSaveState
# Purpose : Persist state atomically with safe perms.
# Notes   : Uses _safe_write_atomic; keeps a simple tmp swap as belt-and-braces.
def fncSaveState(state: dict):
    data = json.dumps(state, indent=2)
    _safe_write_atomic(STATE_PATH, data, 0o600)


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
# Function: fncPveEnsureUser
# Purpose : Ensure a PVE user exists, set enable, and update optional metadata.
# Notes   : Keeps UPN case for PVE user id; unix login stays lowercase elsewhere.
def fncPveEnsureUser(upn: str,
                     enabled: bool = True,
                     email: str | None = None,
                     comment: str | None = None,
                     firstname: str | None = None,
                     lastname: str | None = None) -> bool:
    userid = fncPveUseridFromUpn(upn)  # preserves case in UPN

    if not fncPveUserExists(userid):
        args = ["user", "add", userid, "-enable", "1" if enabled else "0"]
        if email:
            args += ["-email", email]
        if comment:
            args += ["-comment", comment]
        if firstname:
            args += ["-firstname", firstname]
        if lastname:
            args += ["-lastname", lastname]

        rc, _, err = fncRun("pveum", args)
        if rc != 0:
            logging.error("PVE user add failed for %s: %s", userid, err)
            return False
        logging.info("PVE user created: %s (enable=%s)", userid, int(enabled))
        return True

    # Existing user: ensure enabled flag, then update metadata if provided
    changed = fncPveUserSetEnabled(upn, enabled)
    meta_changed = fncPveUserModify(upn, email=email, comment=comment,
                                    firstname=firstname, lastname=lastname)
    return changed or meta_changed

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

#==================================================================#
#              Remote API client (PBS / PDM shared)               #
#==================================================================#

def _fncDecryptTokenValue(enc_value: str, label: str = "remote API token") -> str:
    """Decrypt a Fernet-encrypted API token value using the key file.

    Security notes:
    - Decryption failure is FATAL: falling back to plaintext would silently
      degrade security and may expose credentials (e.g. if key file removed).
    - Fernet tokens embed a timestamp; we enforce FERNET_MAX_AGE_DAYS so that
      tokens encrypted very long ago are rejected.
    - A near-expiry warning is emitted when less than 30 days remain.
    """
    if not enc_value:
        logging.critical("Empty encrypted value for %s; aborting.", label)
        sys.exit(2)
    if not enc_value.startswith("fernet:"):
        # Plaintext value - acceptable only if not prefixed; still usable but warn
        logging.warning(
            "%s is stored as plaintext (not Fernet-encrypted). "
            "Re-run the installer to encrypt secrets.", label
        )
        return enc_value

    from cryptography.fernet import Fernet, InvalidToken
    import struct, base64, time as _time

    key_b64 = os.getenv("ENTRAMOX_ENC_KEY", "").strip()
    if not key_b64:
        logging.critical(
            "Missing ENTRAMOX_ENC_KEY needed to decrypt %s - "
            "service cannot start without the encryption key. Aborting.", label
        )
        sys.exit(2)

    raw_token = enc_value.split(":", 1)[1].encode()
    max_age_seconds = FERNET_MAX_AGE_DAYS * 86400
    warn_threshold  = max_age_seconds - (30 * 86400)  # 30-day warning window

    # Check token age before decrypting for near-expiry warning
    try:
        padded = raw_token + b"=" * (-len(raw_token) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        if len(decoded) >= 9:
            token_ts = struct.unpack(">Q", decoded[1:9])[0]
            age = int(_time.time()) - token_ts
            if age > warn_threshold:
                days_left = max(0, (max_age_seconds - age) // 86400)
                logging.warning(
                    "%s Fernet token is %d days old; %d days until forced rotation. "
                    "Re-encrypt secrets via the installer.", label, age // 86400, days_left
                )
    except Exception:
        pass  # timestamp decode is best-effort; don't block on it

    try:
        return Fernet(key_b64.encode()).decrypt(raw_token, ttl=max_age_seconds).decode()
    except InvalidToken:
        logging.critical(
            "Failed to decrypt %s - token is invalid, corrupted, or older than "
            "%d days (FERNET_MAX_AGE_DAYS). Re-encrypt via the installer. Aborting.",
            label, FERNET_MAX_AGE_DAYS
        )
        sys.exit(2)
    except Exception as e:
        logging.critical("Unexpected error decrypting %s: %s - aborting.", label, e)
        sys.exit(2)


def _fncRemoteApiRequest(
    base_url: str,
    path: str,
    method: str = "GET",
    data: dict | None = None,
    auth_header: str = "",
    verify_tls: bool = True,
    timeout: int = 10,
) -> dict | None:
    """
    Generic HTTPS REST client for PBS and PDM.
    Returns the parsed JSON response dict or None on error.
    """
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    headers: dict = {"Accept": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header

    body = None
    if data is not None:
        body = _urlparse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = _urlreq.Request(url, data=body, headers=headers, method=method)

    ctx: ssl.SSLContext | None = None
    if not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logging.warning(
            "TLS certificate verification DISABLED for %s %s - "
            "connection is vulnerable to MITM. Set verify_tls=true in production.",
            method, url
        )

    try:
        with _http_with_retry(req, timeout, context=ctx, label=f"{method} {path}") as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        try:
            body_txt = e.read().decode(errors="ignore")
            logging.error("Remote API HTTP %s %s %s: %s", method, url, e.code, body_txt[:200])
        except Exception:
            logging.error("Remote API HTTP %s %s %s", method, url, e.code)
        return None
    except Exception as e:
        logging.error("Remote API request failed %s %s: %s", method, url, e)
        return None


#=======================#
# Proxmox Backup Server #
#=======================#

def _fncPbsBaseUrl() -> str:
    return f"https://{PBS_HOST}:{PBS_PORT}/api2/json"

def _fncPbsAuthHeader() -> str:
    token_val = _fncDecryptTokenValue(PBS_TOKEN_VALUE_ENC)
    if not token_val:
        return ""
    return f"PVEAPIToken={PBS_API_USER}!{PBS_TOKEN_NAME}={token_val}"

def fncPbsUseridFromUpn(upn: str) -> str:
    realm = (PBS_REALM or REALM).strip()
    return f"{upn}@{realm}"

def fncPbsUserExists(userid: str) -> bool:
    resp = _fncRemoteApiRequest(
        _fncPbsBaseUrl(), "access/users",
        auth_header=_fncPbsAuthHeader(), verify_tls=PBS_VERIFY_TLS,
    )
    if resp is None:
        return False
    try:
        return any((u.get("userid") or "") == userid for u in (resp.get("data") or []))
    except Exception:
        return False

def fncPbsEnsureUser(
    upn: str,
    enabled: bool = True,
    email: str | None = None,
    comment: str | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    role: str | None = None,
) -> bool:
    """Create or update a PBS user account, and ensure a role at /."""
    if not PBS_ENABLED or not PBS_HOST:
        return False
    auth = _fncPbsAuthHeader()
    if not auth:
        logging.error("PBS auth header missing; check PBS_API_USER/PBS_TOKEN_NAME/PBS_TOKEN_VALUE_ENC")
        return False

    userid = fncPbsUseridFromUpn(upn)
    base = _fncPbsBaseUrl()
    exists = fncPbsUserExists(userid)

    params: dict = {"enable": 1 if enabled else 0}
    if email:     params["email"]     = email
    if comment:   params["comment"]   = comment
    if firstname: params["firstname"] = firstname
    if lastname:  params["lastname"]  = lastname

    if not exists:
        params["userid"] = userid
        resp = _fncRemoteApiRequest(base, "access/users", method="POST",
                                    data=params, auth_header=auth, verify_tls=PBS_VERIFY_TLS)
        if resp is None:
            logging.error("PBS user create failed for %s", userid)
            return False
        logging.info("PBS user created: %s (enable=%s)", userid, int(enabled))
        fncAuditEvent("PBS_USER_CREATED", {"userid": userid, "enabled": enabled})
    else:
        resp = _fncRemoteApiRequest(
            base, f"access/users/{_urlparse.quote(userid, safe='')}",
            method="PUT", data=params, auth_header=auth, verify_tls=PBS_VERIFY_TLS)
        if resp is None:
            logging.error("PBS user modify failed for %s", userid)
            return False
        logging.info("PBS user updated: %s (enable=%s)", userid, int(enabled))

    # Ensure role at datastore root if enabled and role given
    if enabled and role:
        acl_data = {
            "path": "/",
            "role": role,
            "userid": userid,
            "propagate": 1,
        }
        acl_resp = _fncRemoteApiRequest(base, "access/acl", method="PUT",
                                        data=acl_data, auth_header=auth, verify_tls=PBS_VERIFY_TLS)
        if acl_resp is None:
            logging.error("PBS ACL set failed: user=%s role=%s", userid, role)
        else:
            logging.info("PBS ACL set: %s role=%s @ /", userid, role)

    return True

def fncPbsUserSetEnabled(upn: str, enabled: bool) -> bool:
    """Enable or disable a PBS user account."""
    if not PBS_ENABLED or not PBS_HOST:
        return False
    userid = fncPbsUseridFromUpn(upn)
    auth = _fncPbsAuthHeader()
    if not auth:
        return False
    resp = _fncRemoteApiRequest(
        _fncPbsBaseUrl(), f"access/users/{_urlparse.quote(userid, safe='')}",
        method="PUT", data={"enable": 1 if enabled else 0},
        auth_header=auth, verify_tls=PBS_VERIFY_TLS)
    if resp is None:
        logging.error("PBS user enable-toggle failed for %s", userid)
        return False
    logging.info("PBS user %s set enable=%s", userid, int(enabled))
    fncAuditEvent("PBS_USER_TOGGLED", {"userid": userid, "enabled": enabled})
    return True


#=================================#
# Proxmox Datacenter Manager (PDM)#
#=================================#

def _fncPdmBaseUrl() -> str:
    return f"https://{PDM_HOST}:{PDM_PORT}/api2/json"

def _fncPdmAuthHeader() -> str:
    token_val = _fncDecryptTokenValue(PDM_TOKEN_VALUE_ENC)
    if not token_val:
        return ""
    return f"PVEAPIToken={PDM_API_USER}!{PDM_TOKEN_NAME}={token_val}"

def fncPdmUseridFromUpn(upn: str) -> str:
    realm = (PDM_REALM or REALM).strip()
    return f"{upn}@{realm}"

def fncPdmUserExists(userid: str) -> bool:
    resp = _fncRemoteApiRequest(
        _fncPdmBaseUrl(), "access/users",
        auth_header=_fncPdmAuthHeader(), verify_tls=PDM_VERIFY_TLS,
    )
    if resp is None:
        return False
    try:
        return any((u.get("userid") or "") == userid for u in (resp.get("data") or []))
    except Exception:
        return False

def fncPdmEnsureUser(
    upn: str,
    enabled: bool = True,
    email: str | None = None,
    comment: str | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    role: str | None = None,
) -> bool:
    """Create or update a PDM user account, and ensure a role at /."""
    if not PDM_ENABLED or not PDM_HOST:
        return False
    auth = _fncPdmAuthHeader()
    if not auth:
        logging.error("PDM auth header missing; check PDM_API_USER/PDM_TOKEN_NAME/PDM_TOKEN_VALUE_ENC")
        return False

    userid = fncPdmUseridFromUpn(upn)
    base = _fncPdmBaseUrl()
    exists = fncPdmUserExists(userid)

    params: dict = {"enable": 1 if enabled else 0}
    if email:     params["email"]     = email
    if comment:   params["comment"]   = comment
    if firstname: params["firstname"] = firstname
    if lastname:  params["lastname"]  = lastname

    if not exists:
        params["userid"] = userid
        resp = _fncRemoteApiRequest(base, "access/users", method="POST",
                                    data=params, auth_header=auth, verify_tls=PDM_VERIFY_TLS)
        if resp is None:
            logging.error("PDM user create failed for %s", userid)
            return False
        logging.info("PDM user created: %s (enable=%s)", userid, int(enabled))
        fncAuditEvent("PDM_USER_CREATED", {"userid": userid, "enabled": enabled})
    else:
        resp = _fncRemoteApiRequest(
            base, f"access/users/{_urlparse.quote(userid, safe='')}",
            method="PUT", data=params, auth_header=auth, verify_tls=PDM_VERIFY_TLS)
        if resp is None:
            logging.error("PDM user modify failed for %s", userid)
            return False
        logging.info("PDM user updated: %s (enable=%s)", userid, int(enabled))

    if enabled and role:
        acl_data = {"path": "/", "role": role, "userid": userid, "propagate": 1}
        acl_resp = _fncRemoteApiRequest(base, "access/acl", method="PUT",
                                        data=acl_data, auth_header=auth, verify_tls=PDM_VERIFY_TLS)
        if acl_resp is None:
            logging.error("PDM ACL set failed: user=%s role=%s", userid, role)
        else:
            logging.info("PDM ACL set: %s role=%s @ /", userid, role)

    return True

def fncPdmUserSetEnabled(upn: str, enabled: bool) -> bool:
    """Enable or disable a PDM user account."""
    if not PDM_ENABLED or not PDM_HOST:
        return False
    userid = fncPdmUseridFromUpn(upn)
    auth = _fncPdmAuthHeader()
    if not auth:
        return False
    resp = _fncRemoteApiRequest(
        _fncPdmBaseUrl(), f"access/users/{_urlparse.quote(userid, safe='')}",
        method="PUT", data={"enable": 1 if enabled else 0},
        auth_header=auth, verify_tls=PDM_VERIFY_TLS)
    if resp is None:
        logging.error("PDM user enable-toggle failed for %s", userid)
        return False
    logging.info("PDM user %s set enable=%s", userid, int(enabled))
    fncAuditEvent("PDM_USER_TOGGLED", {"userid": userid, "enabled": enabled})
    return True


#==============================================================#
#                        Microsoft Graph                       #
#==============================================================#
# Function: fncGetGraphClientSecret
# Purpose : Resolve MS Entra client secret from env (plaintext or Fernet-encrypted).
# Notes   : Supports ENTR_CLNT_SEC (plain) or ENTR_CLNT_SEC_ENC="fernet:<token>" with ENTRAMOX_ENC_KEY.
def fncGetGraphClientSecret() -> str | None:
    """Return the Graph client secret.

    Prefers ENTR_CLNT_SEC_ENC (Fernet-encrypted) over ENTR_CLNT_SEC (plaintext).
    Decryption failure is fatal - see _fncDecryptTokenValue for rationale.
    """
    enc = os.getenv("ENTR_CLNT_SEC_ENC", "").strip()
    if enc:
        # Delegates fatal handling and TTL enforcement to _fncDecryptTokenValue
        return _fncDecryptTokenValue(enc, label="Graph client secret (ENTR_CLNT_SEC_ENC)")

    plain = os.getenv("ENTR_CLNT_SEC", "").strip()
    if plain:
        logging.warning(
            "Graph client secret is stored as plaintext (ENTR_CLNT_SEC). "
            "Re-run the installer to encrypt it."
        )
        return plain

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
        with _http_with_retry(req, GRAPH_TIMEOUT, label="Graph token") as resp:
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
        with _http_with_retry(req, GRAPH_TIMEOUT, label=context) as resp:
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
def fncGraphListGroupUPNs(group_id: str, token: str) -> list[tuple[str, bool, dict]] | None:
    if not token:
        _graph_print_error("InvalidAuthenticationToken", "No access token provided.", None, None)
        logging.warning("Graph: no token; proceeding without enforcement (fail-open).")
        return None

    client_req_id = secrets.token_hex(16)
    headers = _graphAuthHeaders(token, client_req_id)
    url = (
        f"https://graph.microsoft.com/v1.0/groups/{group_id}"
        f"/members/microsoft.graph.user"
        f"?$select=id,displayName,userPrincipalName,accountEnabled,givenName,surname,mail&$top=999"
    )

    rows: list[tuple[str, bool, dict]] = []
    allowed_domains = {d.strip().lower() for d in ALLOWED_UPN_DOMAINS if d and d.strip()}

    while url:
        doc = _graphFetchJson(url, headers, client_req_id, context=f"group members {group_id}")
        if doc is None:
            return None

        for item in doc.get("value", []):
            upn_orig = (item.get("userPrincipalName") or "").strip()
            if not upn_orig:
                continue

            # domain filter: case-insensitive
            if allowed_domains:
                dom_l = upn_orig.split("@", 1)[-1].lower()
                if dom_l not in allowed_domains:
                    continue

            enabled = bool(item.get("accountEnabled", True))
            meta = {
                "displayName": item.get("displayName") or "",
                "givenName": item.get("givenName") or "",
                "surname": item.get("surname") or "",
                "mail": item.get("mail") or "",
                "id": item.get("id") or "",
            }
            rows.append((upn_orig, enabled, meta))

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

    members = rows  # [(upn_orig, enabled, meta), ...]

    upns = {u for (u, _, _) in members}
    _log_group_members(name, "members", upns)

    unix = {fncUpnToUnix(u) for u in upns}
    upn_enabled_map = {u: en for (u, en, _) in members}
    pve_role = (role_map or {}).get(group_id, "")

    return {
        "id": group_id,
        "name": name,
        "mail": mail,
        "members": members,
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
def _computeDesiredFromGraph(groups: list[dict]) -> tuple[
    set[str],
    dict[str, set[str]],
    dict[str, str],
    dict[str, bool],
    set[str],
    set[str]
]:
    desired: set[str] = set()
    user_roles_by_upn: dict[str, set[str]] = {}
    unix_to_upn: dict[str, str] = {}
    upn_enabled_global: dict[str, bool] = {}
    in_allusers_upn: set[str] = set()
    in_superadmin_upn: set[str] = set()

    allusers_enabled = bool(ENTRA_ALLUSERS_GROUP_ID.strip())
    superadmin_enabled = bool(ENTRA_SUPERADMIN_GROUP_ID.strip())

    for g in groups or []:
        desired |= set(g.get("unix", set()))

        for upn, en in (g.get("upn_enabled") or {}).items():
            upn_enabled_global[upn] = (upn_enabled_global.get(upn, True) and bool(en))

        role = (g.get("pve_role") or "").strip()
        for upn in g.get("upns", []):
            if role:
                user_roles_by_upn.setdefault(upn, set()).add(role)
            ux = fncUpnToUnix(upn)
            unix_to_upn.setdefault(ux, upn)

        # Only track special groups if configured
        if allusers_enabled and g.get("id") == ENTRA_ALLUSERS_GROUP_ID:
            in_allusers_upn |= g.get("upns", set())

        if superadmin_enabled and g.get("id") == ENTRA_SUPERADMIN_GROUP_ID:
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
        disabled.pop(user, None)
        known.discard(user)
        return

    if not fncUserExists(user):
        disabled.pop(user, None)
        known.discard(user)
        return

    # Always revoke privilege while not desired
    fncRemoveSudoers(user)
    fncRemoveUserFromGroup(user, "sudo")

    now = _get_utc_datetime()

    # FIRST SEEN → enter grace
    if user not in disabled:
        fncLockUser(user)
        disabled[user] = now.isoformat()

        logging.info(
            "User %s not in Entra allow-groups; locked and marked for deletion in %s",
            user, str(DELETE_AFTER)
        )

        # Disable PVE immediately
        _disablePveIfKnown(user, unix_to_upn)

        # Update PVE comment
        upn = unix_to_upn.get(user)
        src_labels = _pickAllSourceGroupNames(upn, []) if upn else []
        _setPveDeletionComment(user, now, unix_to_upn, src_labels)

        return

    # ALREADY IN GRACE
    try:
        locked_at = _parse_iso_datetime(disabled[user])
    except Exception:
        locked_at = now
        disabled[user] = locked_at.isoformat()

    # Keep PVE disabled (idempotent)
    _disablePveIfKnown(user, unix_to_upn)

    # Refresh comment every run (keeps timestamp accurate if state file edited)
    upn = unix_to_upn.get(user)
    src_labels = _pickAllSourceGroupNames(upn, []) if upn else []
    _setPveDeletionComment(user, locked_at, unix_to_upn, src_labels)

    # Expiry check
    if now - locked_at >= DELETE_AFTER:
        logging.info("User %s disabled for >= %s; deleting", user, str(DELETE_AFTER))
        fncDeleteUser(user)
        disabled.pop(user, None)
        known.discard(user)
    else:
        remain = DELETE_AFTER - (now - locked_at)
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
    required_bins = ["pvesh", "pveum", "useradd", "usermod", "userdel", "passwd", "chage", "chpasswd", "visudo", "getent", "id", "groupadd", "gpasswd"]
    for key in required_bins:
        if not os.path.exists(BIN.get(key, "")):
            logging.error("Missing required binary: %s -> %s", key, BIN.get(key))

    # Load state
    state = fncLoadState()
    known        = set(state.get("known_users", []))
    disabled     = state.get("disabled", {})      # {username: iso_timestamp_locked}
    tiered_known = set(state.get("tiered_users", []))  # tiered account names

    # ── Pull Graph ─────────────────────────────────────────────────────────────
    groups: list[dict] = []
    token = None
    graph_required = bool(GRAPH_ENFORCE and GRAPH_GROUP_IDS)

    if graph_required:
        token = fncGraphGetToken()
        if not token:
            _graphFailOrWarn("Graph token unavailable while GRAPH_ENFORCE is enabled.")
        else:
            groups = fncGraphListManyGroups(GRAPH_GROUP_IDS, token, role_map=PVE_ROLE_BY_GROUP)
            if not groups:
                _graphFailOrWarn("Graph group fetch returned no data while GRAPH_ENFORCE is enabled.")
            else:
                fncPrintGroupReport(groups)

    # Compute desired + helper maps
    desired_unix, user_roles_by_upn, unix_to_upn, upn_enabled_global, in_allusers_upn, in_superadmin_upn = _computeDesiredFromGraph(groups)

    # Fallback if Graph empty/unavailable: keep current realm users to avoid mass-delete
    if not desired_unix:
        if graph_required and not GRAPH_FAIL_OPEN:
            _graphFailOrWarn("Graph produced empty desired user set; refusing to fall back (fail-closed).")
        desired_unix = fncGetPveUsersForRealm(REALM)
        logging.warning("Graph empty/unavailable; falling back to PVE realm users as desired.")
    logging.info("Desired (unix)=%s", sorted(desired_unix))

    # ── Compute desired tiered accounts (superadmins only) ─────────────────────
    desired_tiered_unix: set[str] = set()
    if TIERED_ACCOUNTS and TIERED_ACCOUNT_VALUE:
        for _upn in in_superadmin_upn:
            _base = fncUpnToUnix(_upn)
            if _base and _base not in RESERVED_USERS:
                _tiered = fncMakeTieredUsername(_base)
                if _tiered and _tiered != _base and _tiered not in RESERVED_USERS:
                    desired_tiered_unix.add(_tiered)
        if desired_tiered_unix:
            logging.info("Desired tiered accounts: %s", sorted(desired_tiered_unix))

    # Candidates we might need to hold if not desired
    realm_present = fncGetAllPveUsersForRealm(REALM)
    candidates    = known | realm_present

    # ── 1) Hold/Delete: users not in any allowed group ─────────────────────────
    # Exclude tiered accounts from the grace-delete logic (handled separately).
    to_hold = (candidates | known) - desired_unix - tiered_known
    for user in sorted(to_hold):
        _graceDeleteOrCountdown(user, disabled, known, unix_to_upn)

    # ── 1b) Tiered account cleanup: remove if user is no longer a superadmin ───
    orphaned_tiered = tiered_known - desired_tiered_unix
    for tiered_user in sorted(orphaned_tiered):
        if fncUserExists(tiered_user):
            fncRemoveSudoers(tiered_user)
            fncRemoveUserFromGroup(tiered_user, "sudo")
            fncLockUser(tiered_user)
            fncDeleteUser(tiered_user)
            logging.info("Tiered account removed (no longer superadmin): %s", tiered_user)
            fncAuditEvent("TIERED_ACCOUNT_DELETED", {"tiered_user": tiered_user})
        disabled.pop(tiered_user, None)
        tiered_known.discard(tiered_user)

    # ── Safety cap: abort if too many new accounts would be created ───────────
    if MAX_USERS_PER_RUN > 0:
        to_create = {u for u in desired_unix if u not in known and u not in RESERVED_USERS and not fncUserExists(u)}
        if len(to_create) > MAX_USERS_PER_RUN:
            msg = (
                f"MAX_USERS_PER_RUN exceeded: {len(to_create)} accounts would be created "
                f"(limit={MAX_USERS_PER_RUN}). Possible compromised Entra group. "
                "Increase MAX_USERS_PER_RUN or investigate before re-running."
            )
            logging.critical(msg)
            fncAuditEvent("MAX_USERS_EXCEEDED", {
                "would_create": len(to_create),
                "limit": MAX_USERS_PER_RUN,
            })
            sys.exit(4)

    # ── 2) Ensure/Create: users in allowed groups ──────────────────────────────
    for user in sorted(desired_unix):
        if user in RESERVED_USERS:
            continue

        # Create if missing, then set initial password
        is_new = not fncUserExists(user)
        if is_new:
            if fncCreateUser(user):
                fncSetInitialPassword(user)
                fncAuditEvent("USER_CREATED", {"user": user})

        # Map back to UPN for decisions; default to True when flags missing
        upn          = unix_to_upn.get(user)
        entra_enabled = upn_enabled_global.get(upn, True) if upn is not None else True
        is_superadmin = (upn in in_superadmin_upn) if upn else False

        # Build group names for description (used in GECOS + PVE comment)
        src_labels: list[str] = _pickAllSourceGroupNames(upn, groups) if upn and groups else []

        # ── Entra-disabled: in group but account disabled in Entra ──────────────
        if not entra_enabled:
            fncLockUser(user)
            disabled.pop(user, None)
            fncRemoveSudoers(user)
            fncRemoveUserFromGroup(user, "sudo")

            if upn:
                try:
                    meta, comment = _buildPveMetaForUpn(upn, groups)
                    fncPveEnsureUser(
                        upn,
                        enabled=False,
                        email=meta.get("mail"),
                        comment=comment,
                        firstname=meta.get("givenName"),
                        lastname=meta.get("surname"),
                    )
                except Exception as e:
                    logging.error("PVE disable/update failed for %s: %s", upn, e)

                if PBS_ENABLED:
                    fncPbsUserSetEnabled(upn, False)
                if PDM_ENABLED:
                    fncPdmUserSetEnabled(upn, False)
            else:
                logging.debug("Entra-disabled user %s: could not map to UPN for PVE/PBS/PDM disable.", user)

            known.add(user)
            continue

        # ── Entra enabled ────────────────────────────────────────────────────────
        fncUnlockUser(user)
        _ensureBaselineGroups(user)

        # Set Linux GECOS to show which Entra group(s) granted the account
        if src_labels:
            if len(src_labels) == 1:
                gecos = f"Synced via '{src_labels[0]}' Group"
            else:
                gecos = "Synced via Groups: " + ", ".join(f"'{n}'" for n in src_labels)
        else:
            gecos = "Synced from Entra"
        fncSetLinuxGecos(user, gecos)

        # ── SUDO policy ──────────────────────────────────────────────────────────
        # When tiered accounts are active the BASE account gets NO sudo — privileges
        # live exclusively in the tiered account (created below).
        tiered_active = TIERED_ACCOUNTS and bool(TIERED_ACCOUNT_VALUE)
        if is_superadmin:
            if tiered_active:
                # Base account: strip sudo (tiered account carries it)
                fncRemoveSudoers(user)
                fncRemoveUserFromGroup(user, "sudo")
            else:
                fncAddUserToGroups(user, ["sudo"])
                if GRANT_SUDO:
                    fncGrantSudo(user)  # fncGrantSudo emits SUDO_GRANTED audit event
        else:
            fncRemoveSudoers(user)
            fncRemoveUserFromGroup(user, "sudo")

        # ── PVE user ensure + roles ──────────────────────────────────────────────
        if upn:
            try:
                meta, comment = _buildPveMetaForUpn(upn, groups)
                fncPveEnsureUser(
                    upn,
                    enabled=True,
                    email=meta.get("mail"),
                    comment=comment,
                    firstname=meta.get("givenName"),
                    lastname=meta.get("surname"),
                )

                roles = set(user_roles_by_upn.get(upn, set()))

                # AllUsers baseline role
                if ENTRA_ALLUSERS_GROUP_ID and ENTRA_ALLUSERS_PVE_ROLE:
                    if (upn in in_allusers_upn) and not roles:
                        roles = {ENTRA_ALLUSERS_PVE_ROLE}

                # Tiered scope "linux": superadmin PVE role is NOT granted via base account.
                # Scope "both": grant PVE admin role as well (user also gets the tiered Linux account).
                if is_superadmin and tiered_active and TIERED_ACCOUNT_SCOPE != "both":
                    roles.discard(ENTRA_SUPERADMIN_PVE_ROLE)

                if roles:
                    fncPveEnsureAclRoles(fncPveUseridFromUpn(upn), roles, path="/")

            except Exception as e:
                logging.error("PVE provisioning failed for %s: %s", upn, e)

            # ── PBS sync ─────────────────────────────────────────────────────────
            if PBS_ENABLED:
                try:
                    meta, comment = _buildPveMetaForUpn(upn, groups)
                    pbs_role = PBS_ADMIN_ROLE if is_superadmin else PBS_DEFAULT_ROLE
                    fncPbsEnsureUser(upn, enabled=True, email=meta.get("mail"),
                                     comment=comment, firstname=meta.get("givenName"),
                                     lastname=meta.get("surname"), role=pbs_role)
                except Exception as e:
                    logging.error("PBS provisioning failed for %s: %s", upn, e)

            # ── PDM sync ─────────────────────────────────────────────────────────
            if PDM_ENABLED:
                try:
                    meta, comment = _buildPveMetaForUpn(upn, groups)
                    pdm_role = PDM_ADMIN_ROLE if is_superadmin else PDM_DEFAULT_ROLE
                    fncPdmEnsureUser(upn, enabled=True, email=meta.get("mail"),
                                     comment=comment, firstname=meta.get("givenName"),
                                     lastname=meta.get("surname"), role=pdm_role)
                except Exception as e:
                    logging.error("PDM provisioning failed for %s: %s", upn, e)

        disabled.pop(user, None)
        known.add(user)

    # ── 3) Tiered account create/update (superadmins only) ─────────────────────
    if TIERED_ACCOUNTS and TIERED_ACCOUNT_VALUE:
        for base_user in sorted(desired_unix):
            if base_user in RESERVED_USERS:
                continue
            upn = unix_to_upn.get(base_user)
            if not upn or upn not in in_superadmin_upn:
                continue

            tiered_user = fncMakeTieredUsername(base_user)
            if not tiered_user or tiered_user == base_user or tiered_user in RESERVED_USERS:
                continue

            entra_enabled = upn_enabled_global.get(upn, True)

            if not fncUserExists(tiered_user):
                if fncCreateUser(tiered_user):
                    fncSetInitialPassword(tiered_user)
                    logging.info("Created tiered account '%s' for base user '%s'", tiered_user, base_user)
                    fncAuditEvent("TIERED_ACCOUNT_CREATED", {"tiered_user": tiered_user, "base_user": base_user})
                else:
                    # Creation failed (see the useradd error logged above). Don't fall
                    # through to unlock/sudo/GECOS on a user that doesn't exist, and
                    # don't record it in tiered_known so it's retried next run.
                    logging.error(
                        "Skipping tiered account '%s' for '%s': user could not be created",
                        tiered_user, base_user,
                    )
                    continue

            if entra_enabled:
                fncUnlockUser(tiered_user)
                _ensureBaselineGroups(tiered_user)
                fncAddUserToGroups(tiered_user, ["sudo"])
                if GRANT_SUDO:
                    fncGrantSudo(tiered_user)

                # GECOS for tiered account
                src_labels_t = _pickAllSourceGroupNames(upn, groups) if groups else []
                tier_gecos = f"Admin tier for {base_user}"
                if src_labels_t:
                    tier_gecos += " (via " + ", ".join(f"'{n}'" for n in src_labels_t) + ")"
                fncSetLinuxGecos(tiered_user, tier_gecos)
            else:
                fncLockUser(tiered_user)
                fncRemoveSudoers(tiered_user)
                fncRemoveUserFromGroup(tiered_user, "sudo")

            disabled.pop(tiered_user, None)
            tiered_known.add(tiered_user)

    # ── Tiered SSH lockdown ──────────────────────────────────────────────────────
    # Reconcile the managed sshd drop-in (apply when enabled, clean up when not).
    # Static glob on the configured prefix/suffix -- no per-user state needed.
    fncApplyTieredSshDeny()

    # ── Persist ─────────────────────────────────────────────────────────────────
    state["known_users"]  = sorted(known)
    state["disabled"]     = disabled
    state["tiered_users"] = sorted(tiered_known)
    fncSaveState(state)
    logging.info(
        "Sync complete. Known=%d, Desired=%d, Disabled=%d, Tiered=%d",
        len(known), len(desired_unix), len(disabled), len(tiered_known)
    )

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
