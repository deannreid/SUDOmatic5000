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
import shutil
import random
import logging
import secrets
import string
import subprocess
import stat
import fcntl
from datetime import datetime, timedelta, timezone
from colorama import Fore, Style

#===========#
# Variables #
#===========#
VERSION = "1.3.4"
MIN_PYTHON_VERSION = (3, 10)
ADMIN_REQUIRED = True   # yes, this needs root

# --- Tweakers ---
REALM = "SSOREALMNAME-HERE"         # Must match the Proxmox realm name exactly or shit breaks.
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
GRAPH_GROUP_ID = "GROUP_ID_HERE"  # the group I care about
GRAPH_TIMEOUT = 8               # seconds

# Token via either a pre-baked access token or client creds in env (client credentials flow)
ENV_GRAPH_ACCESS_TOKEN = "GRAPH_ACCESS_TOKEN"

ENV_MS_TENANT_ID       = "MS_TENANT_ID"
ENV_MS_CLIENT_ID       = "MS_CLIENT_ID"
ENV_MS_CLIENT_SECRET   = "MS_CLIENT_SECRET"

BANNER = r"""
   _____ _    _ _____   ____  __  __       _______ _____ _____   _____  ___   ___   ___  
  / ____| |  | |  __ \ / __ \|  \/  |   /\|__   __|_   _/ ____| | ____|/ _ \ / _ \ / _ \ 
 | (___ | |  | | |  | | |  | | \  / |  /  \  | |    | || |      | |__ | | | | | | | | | |
  \___ \| |  | | |  | | |  | | |\/| | / /\ \ | |    | || |      |___ \| | | | | | | | | |
  ____) | |__| | |__| | |__| | |  | |/ ____ \| |   _| || |____   ___) | |_| | |_| | |_| |
 |_____/ \____/|_____/ \____/|_|  |_/_/    \_\_|  |_____\_____| |____/ \___/ \___/ \___/ 
                Turning realms into real users, one sudo at a time.
                ------------------------------------------------
                ::        %INSERT RELEVANT DISCORD HERE       ::
                :: https://github.com/deannreid/SUDOmatic5000 ::
                ------------------------------------------------
"""

VERSION_INFO = f"""
==============================================
| Deano's Sudomatic 5000                      |
| Version: {VERSION}                          |
|                                             |
| Syncs Proxmox OIDC users to local Linux:    |
| creates accounts with expired random        |
| passwords, manages groups/sudoers           |
| locks & deletes after 24h,                  |
| logs changes to log for siem tracking.      |
==============================================
| Script Information:                         |
| Proxmox OIDC > Unix user sync               |
==============================================
| Updates:                                    |
| 20/08/2025: Initial Code from Boilerplate   |
|             Added code to do code things    |
|             Cleanup imports, no pwd/grp     |
| 21/08/2025: Pinned bins, lockfile,          |
|             reserved users, domain filter,  |
|             sudo allow-list, logrotate.     |
==============================================
"""

BLURBS = [
    "Summoning realm users: Because PVE doesn't believe in magic.\n",
    "Forging Unix accounts: Turning corporate IDs into shiny new shells.\n",
    "Bestowing sudo powers: Like a knighthood, but with more root.\n",
    "Expiring passwords: Because security theatre needs intermissions too.\n",
    "Mapping UPNs: Translating bureaucrat-speak into bash-friendly names.\n",
    "Brewing credentials: Stirring realms into a frothy /etc/passwd.\n",
    "Auditing sudoers: Because even root needs a gatekeeper.\n",
    "Realm wrangling: Herding users into PVE like digital cattle.\n",
    "UPN transmogrification: Fancy word, simple trick - new username.\n",
    "Provisioning accounts: Like cloud, but with more sweat.\n",
    "Taming the realm: Because identity management loves drama.\n",
    "Dropping sudo crumbs: Hansel and Gretel, but for sysadmins.\n",
    "Binding groups: Social networking for your local /etc/group.\n",
    "Scribing users: Writing your destiny straight into /etc/passwd.\n",
    "Password roulette: Everyone's a winner.. until they log in.\n"
]


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

def fncPrintBanner():
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    print(random.choice(BLURBS))

def fncPrintVersion():
    print(Fore.CYAN + VERSION_INFO + Style.RESET_ALL)

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

    Who ever said this would be bum twitching - not me. Living life on the edge
    """
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
    Get a Graph access token from:
    1) GRAPH_ACCESS_TOKEN env (already a bearer)
    2) client credentials in env -> fetch a token
    """
    token = os.getenv(ENV_GRAPH_ACCESS_TOKEN, "").strip()
    if token:
        return token

    tenant = os.getenv(ENV_MS_TENANT_ID, "").strip()
    client = os.getenv(ENV_MS_CLIENT_ID, "").strip()
    secret = os.getenv(ENV_MS_CLIENT_SECRET, "").strip()
    if not (tenant and client and secret):
        logging.error("Graph creds missing: set %s or (%s,%s,%s)",
                      ENV_GRAPH_ACCESS_TOKEN, ENV_MS_TENANT_ID, ENV_MS_CLIENT_ID, ENV_MS_CLIENT_SECRET)
        return None

    url = f"https://login.microsoftonline.com/{_urlparse.quote(tenant)}/oauth2/v2.0/token"
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
            return body.get("access_token")
    except (URLError, HTTPError) as e:
        logging.error("Graph token fetch failed: %s", e)
        return None
    except Exception as e:
        logging.error("Graph token unexpected error: %s", e)
        return None

def fncGraphListGroupUPNs(group_id: str, token: str) -> set[str]:
    """
    Pull userPrincipalName values from the Graph group (direct members).
    Skips non-user objects. Handles pagination via @odata.nextLink.
    """
    if not token:
        return set()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    # select just what we need; $top large-ish to reduce pages
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=userPrincipalName,accountEnabled&$top=999"

    upns: set[str] = set()
    while url:
        req = _urlreq.Request(url, headers=headers)
        try:
            with _urlreq.urlopen(req, timeout=GRAPH_TIMEOUT) as resp:
                doc = json.loads(resp.read().decode())
        except HTTPError as e:
            logging.error("Graph members fetch HTTP %s: %s", e.code, e)
            break
        except URLError as e:
            logging.error("Graph members fetch network error: %s", e)
            break
        except Exception as e:
            logging.error("Graph members unexpected error: %s", e)
            break

        for item in doc.get("value", []):
            upn = item.get("userPrincipalName")
            if not upn:
                continue  # not a user (service principal / group / device)
            upn = upn.strip()
            if not upn:
                continue
            # domain allow-list (defence-in-depth)
            dom = upn.split("@", 1)[-1].lower() if "@" in upn else ""
            if dom not in ALLOWED_UPN_DOMAINS:
                continue
            upns.add(upn.lower())

        url = doc.get("@odata.nextLink")

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
            group_upns = fncGraphListGroupUPNs(GRAPH_GROUP_ID, token)
            allowed_unix = { fncUpnToUnix(upn) for upn in group_upns }
            before = set(desired)
            desired = desired & allowed_unix
            dropped = sorted(before - desired)
            if dropped:
                logging.info("Graph enforcement: excluding users not in group: %s", dropped)
        else:
            msg = "Graph enforcement skipped: token unavailable"
            if GRAPH_FAIL_OPEN:
                logging.warning(msg + " (fail-open)")
            else:
                logging.error(msg + " (fail-closed -> no members)")
                desired = set()

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
        #fncScriptSecurityCheck()
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
    # Banner + vibe check
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    print(random.choice(BLURBS))

    if len(sys.argv) > 1 and sys.argv[1] in ['--version', '-v', '-V']:
        fncPrintVersion()
        sys.exit(0)

    fncCheckPyVersion()
    fncMain()