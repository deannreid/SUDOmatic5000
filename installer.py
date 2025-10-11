#!/usr/bin/env python3
import os
import sys
import shutil
import hashlib
import subprocess
import random
import argparse
from pathlib import Path
import json
from colorama import init as _cinit, Fore as F, Style as S
import re
from datetime import datetime

# ============================
# Paths & constants
# ============================
ROOT_DIR = Path(__file__).resolve().parent
SCRIPT_SRC = ROOT_DIR / "sudomatic5000.py"
REQS = ROOT_DIR / "requirements.txt"
VERSION = "1.4.1a"

# System paths
SCRIPT_DST = Path("/usr/local/sbin/sudomatic5000.py")
CHECKER = Path("/usr/local/sbin/sudomatic_check.sh")
SERVICE = Path("/etc/systemd/system/sudomatic.service")
TIMER = Path("/etc/systemd/system/sudomatic.timer")
LOGDIR = Path("/var/log/sudomatic5000")
ENVFILE = Path("/etc/sudomatic5000.env")
KEYFILE = Path("/etc/sudomatic5000.key")      # separate env file, 0600
ENC_KEY_ENV = "SUDOMATIC_ENC_KEY"             # the env var name holding the Fernet key
ENV_ASSIGN_RE = re.compile(r"""^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^']*)'|"([^"]*)"|([^\s#]+))\s*(?:#.*)?$""")

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

# ============================
# Colour / output helpers
# ============================
_cinit(autoreset=True)

_COLOR_MONO = False

def fncSetColorMode(monochrome: bool):
    """Call once after parsing args to disable colours when needed."""
    global _COLOR_MONO
    _COLOR_MONO = bool(monochrome)

def fncWantColor(stream=sys.stdout):
    """Decide if we should output ANSI colours."""
    if _COLOR_MONO:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return stream.isatty()
    except Exception:
        return False

def fncColor(text: str, *styles: str) -> str:
    """fncColor('Hello', 'green', 'bold') -> styled text (or plain if disabled)."""
    if not fncWantColor() or not styles:
        return text
    m = {
        "red": F.RED, "green": F.GREEN, "yellow": F.YELLOW, "blue": F.BLUE,
        "magenta": F.MAGENTA, "cyan": F.CYAN, "white": F.WHITE, "gray": F.LIGHTBLACK_EX,
        "bold": S.BRIGHT, "dim": S.DIM,
    }
    seq = "".join(m.get(s, "") for s in styles)
    return f"{seq}{text}{S.RESET_ALL}"

def fncHeading(msg: str): print(fncColor(msg, "magenta", "bold"))
def fncInfo(msg: str):    print(fncColor("[*] ", "cyan") + msg)
def fncOk(msg: str):      print(fncColor("[+] ", "green") + msg)
def fncWarn(msg: str):    print(fncColor("[!] ", "yellow") + msg)
def fncErr(msg: str):     print(fncColor("[-] ", "red") + msg)

# ============================
# Core helpers
# ============================
def fncRequireRoot():
    if os.geteuid() != 0:
        print("[-] This script must be run as root (try sudo)")
        sys.exit(1)

def fncSha256Sum(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def fncRun(cmd: list[str]):
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def fncInstallRequirements():
    if REQS.exists():
        print(f"[*] Found {REQS}, installing dependencies...")
        try:
            fncRun(["pip3", "install", "-r", str(REQS), "--break-system-packages"])
            print("[+] Requirements installed successfully")
        except subprocess.CalledProcessError:
            print("[-] Failed to install requirements.txt")
            sys.exit(1)
    else:
        print("[i] No requirements.txt found, skipping dependency installation.")

def fncPrintBanner():
    print(F.CYAN + BANNER + S.RESET_ALL)
    print(random.choice(BLURBS))

def fncPrintVersion():
    print(F.CYAN + VERSION_INFO + S.RESET_ALL)

def fncShQuote(val: str) -> str:
    """Safe-ish single-quoted value for env files."""
    if val is None:
        val = ""
    return "'" + val.replace("'", "'\"'\"'") + "'"

def fncEnsureKeyfile():
    """Ensure /etc/sudomatic5000.key exists with a Fernet key (mode 0600)."""
    from base64 import urlsafe_b64encode
    try:
        if KEYFILE.exists():
            os.chmod(KEYFILE, 0o600)
            return
        raw = os.urandom(32)                       # 32 bytes -> 44-char base64 urlsafe Fernet key
        key_b64 = urlsafe_b64encode(raw).decode()
        KEYFILE.write_text(f"{ENC_KEY_ENV}={key_b64}\n")
        os.chmod(KEYFILE, 0o600)
        fncOk(f"Created encryption key file {KEYFILE} (mode 0600)")
    except Exception as e:
        fncErr(f"Could not create {KEYFILE}: {e}")
        sys.exit(1)

def _fncParseKeyfile(path: Path) -> str | None:
    try:
        if not path.exists():
            return None
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"): 
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                if k.strip() == ENC_KEY_ENV:
                    return v.strip()
    except Exception:
        return None
    return None

def fncLoadEncKey() -> str | None:
    """Prefer env (runtime), else the keyfile (installer/update)."""
    val = os.environ.get(ENC_KEY_ENV, "").strip()
    if val:
        return val
    return _fncParseKeyfile(KEYFILE)

def fncEncryptSecretFernet(secret: str, key_b64: str) -> str:
    from cryptography.fernet import Fernet
    token = Fernet(key_b64.encode()).encrypt(secret.encode()).decode()
    return f"fernet:{token}"

def fncEnvBackupPath(p: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return p.with_suffix(p.suffix + f".bak-{ts}")

def fncEncryptIfNeededInEnv(env_path: Path = ENVFILE):
    """
    If ENTR_CLNT_SEC (plaintext) exists, encrypt it to ENTR_CLNT_SEC_ENC using SUDOMATIC_ENC_KEY
    and blank ENTR_CLNT_SEC.
    Preserves comments/formatting as much as possible.
    """
    if not env_path.exists():
        fncInfo(f"No env at {env_path}; nothing to migrate.")
        return

    enc_key = fncLoadEncKey()
    if not enc_key:
        fncErr(f"Missing encryption key for migration. Expected {KEYFILE} with {ENC_KEY_ENV}. Aborting migration.")
        return

    lines = env_path.read_text().splitlines(keepends=False)
    changed = False

    # Discover current values/positions
    plain_val, plain_idx = None, None
    enc_val, enc_idx = None, None

    for idx, line in enumerate(lines):
        m = ENV_ASSIGN_RE.match(line)
        if not m:
            continue
        key = m.group(1)
        val = m.group(2) or m.group(3) or m.group(4) or ""

        if key == "ENTR_CLNT_SEC":
            if val.strip():
                plain_val, plain_idx = val, idx
        elif key == "ENTR_CLNT_SEC_ENC":
            if val.strip():
                enc_val, enc_idx = val, idx

    # If plaintext, ensure encrypted + blank plaintext
    if plain_val is not None:
        if enc_idx is None:
            # create encrypted value
            try:
                enc_blob = fncEncryptSecretFernet(plain_val, enc_key)  # 'fernet:<token>'
            except Exception as e:
                fncErr(f"Failed to encrypt existing ENTR_CLNT_SEC: {e}")
                return
            # Append encrypted var near the bottom
            lines.append("")
            lines.append(f"ENTR_CLNT_SEC_ENC={fncShQuote(enc_blob)}")
            changed = True
        else:
            # Already had encrypted value;
            pass

        # Blank the plaintext line if present
        if plain_idx is not None and not lines[plain_idx].startswith("#"):
            lines[plain_idx] = "ENTR_CLNT_SEC=''"
            changed = True

    if not changed:
        fncInfo("Env examined; no changes required.")
        return

    # Backup and write
    backup = fncEnvBackupPath(env_path)
    try:
        shutil.copy2(env_path, backup)
        fncInfo(f"Backed up env to {fncColor(str(backup), 'white', 'bold')}")
    except Exception as e:
        fncWarn(f"Could not backup env file ({e}); proceeding carefully.")

    env_path.write_text("\n".join(lines) + "\n")
    os.chmod(env_path, 0o600)
    fncOk("Env migration complete: plaintext secret removed, encrypted value stored, deprecated vars cleaned.")

# ============================
# Interactive prompts
# ============================
def fncPromptUseGraph() -> bool:
    fncHeading("\n== Sudomatic 5000 — Membership Source ==")
    print(f"{fncColor('[1]', 'white')} Use {fncColor('Microsoft Graph', 'cyan')} (enforce members from an Entra group)")
    print(f"{fncColor('[2]', 'white')} Rely on {fncColor('PVE realm accounts only', 'yellow')} (no Graph enforcement)")
    while True:
        choice = input(f"{fncColor('?', 'cyan')} Choose {fncColor('1', 'white')} or {fncColor('2', 'white')} [{fncColor('2', 'green')}]: ").strip() or "2"
        if choice in ("1", "2"):
            return choice == "1"
        fncWarn("Please enter 1 or 2.")

def fncPromptAuthMode() -> str:
    fncHeading("\n== Microsoft Graph authentication mode ==")
    print(f"{fncColor('[1]', 'white')} Access Token ({fncColor('GRAPH_ACCESS_TOKEN', 'magenta')}) — quick testing; short-lived")
    print(f"{fncColor('[2]', 'white')} Application Tokens (Client Credentials) — "
          f"{fncColor('ENTR_TENANT_ID', 'magenta')}/{fncColor('ENTR_CLNT_ID', 'magenta')}/{fncColor('ENTR_CLNT_SEC', 'magenta')}")
    while True:
        choice = input(f"{fncColor('?', 'cyan')} Choose {fncColor('1', 'white')} or {fncColor('2', 'white')} [{fncColor('2', 'green')}]: ").strip() or "2"
        if choice in ("1", "2"):
            return "access" if choice == "1" else "application"
        fncWarn("Please enter 1 or 2.")

def fncGetPveRoles() -> list[str]:
    """Return available PVE roles using pvesh; fall back to defaults."""
    try:
        out = subprocess.run(
            ["/usr/bin/pvesh", "get", "/access/roles", "--output-format", "json"],
            check=True, capture_output=True, text=True
        ).stdout
        data = json.loads(out)
        roles = sorted({item.get("roleid") for item in data if item.get("roleid")})
        if roles:
            fncOk("Detected PVE roles: " + ", ".join(roles))
            return roles
        fncWarn("No roles returned by pvesh; falling back to defaults.")
        return ["PVEAdmin", "PVEAuditor", "PVEUser"]
    except Exception:
        fncWarn("Could not query pvesh; using default roles.")
        return ["PVEAdmin", "PVEAuditor", "PVEUser"]

def fncChooseFromList(prompt_title: str, options: list[str], allow_none: bool = True, default: str | None = None) -> str | None:
    """Indexed chooser for small lists; returns selected item or None."""
    opts = list(options)
    if allow_none:
        opts = ["<none>"] + opts

    fncHeading(f"\n== {prompt_title} ==")
    for i, o in enumerate(opts, 1):
        is_default = default is not None and o == default
        mark = f" {fncColor('(default)', 'green')}" if is_default else ""
        label = f"{fncColor(f'[{i}]', 'white')} " + (fncColor(o, 'cyan') if o != "<none>" else fncColor(o, 'yellow'))
        print(f"{label}{mark}")

    hint = f" [{fncColor(str(opts.index(default)+1), 'green')}]" if default in opts else ""
    while True:
        raw = input(f"{fncColor('?', 'cyan')} Choose {fncColor(f'1-{len(opts)}', 'white')}{hint}: ").strip()
        if not raw and default in opts:
            return None if (allow_none and default == "<none>") else default
        if raw.isdigit():
            i = int(raw)
            if 1 <= i <= len(opts):
                choice = opts[i-1]
                return None if (allow_none and choice == "<none>") else choice
        fncWarn("Invalid selection, try again.")

def fncPromptSuperAdminGroup() -> tuple[str, bool]:
    """Ask for optional Super Admin group; optionally auto-sudo just for that group."""
    fncHeading("\n== Optional Super Admin group ==")
    print("Provide the Entra group " + fncColor("Object ID", "bold") + " (GUID) for Super Admins.")
    print(fncColor("This does NOT affect other users. Leave blank to skip.", "yellow"))
    gid = input(f"{fncColor('?', 'cyan')} Super Admin Group Object ID (GUID): ").strip()
    auto = False
    if gid:
        auto = input(f"{fncColor('?', 'cyan')} Auto-grant {fncColor('sudo', 'bold')} to Super Admin members? [{fncColor('Y', 'green')}/n]: ").strip().lower() in ("", "y", "yes")
    return gid, auto

def fncPromptAllUsersGroup() -> tuple[str | None, str | None]:
    """Optional All Users group (baseline); map it to a PVE role."""
    fncHeading("\n== Optional 'All Users' group ==")
    print("Provide an Entra group Object ID that grants baseline access to *all* its members on this host.")
    print(fncColor("Leave blank to skip.", "yellow"))
    gid = input(f"{fncColor('?', 'cyan')} All Users Group Object ID (GUID): ").strip()
    if not gid:
        return None, None
    roles = fncGetPveRoles()
    chosen = fncChooseFromList("Select baseline PVE role for All Users", roles, allow_none=True,
                               default="PVEUser" if "PVEUser" in roles else None)
    return gid, chosen

def fncPromptRoleMappings() -> list[dict]:
    """Zero or more Entra group → PVE role mappings."""
    mappings = []
    roles = fncGetPveRoles()
    fncHeading("\n== Entra Group → PVE Role mappings (optional) ==")
    print("You can add multiple role mappings. Leave Group ID empty to finish.")
    while True:
        gid = input(f"{fncColor('?', 'cyan')} Entra Group Object ID for role mapping {fncColor('(blank to finish)', 'white')}: ").strip()
        if not gid:
            break
        role = fncChooseFromList(f"Choose PVE role for {gid}", roles, allow_none=False,
                                 default="PVEAuditor" if "PVEAuditor" in roles else None)
        mappings.append({"group": gid, "pve_role": role})
        fncOk(f"Added mapping: {gid} → {role}")
    return mappings

# ============================
# Actions
# ============================
def fncDoUninstall(purge: bool = False):
    fncRequireRoot()
    fncHeading("[*] Uninstalling Sudomatic 5000...")

    # Stop & disable units (ignore failures if not present)
    for unit in ("sudomatic.timer", "sudomatic.service"):
        try:
            fncRun(["systemctl", "stop", unit])
            fncInfo(f"Stopped {unit}")
        except subprocess.CalledProcessError:
            fncWarn(f"{unit} was not running")
        try:
            fncRun(["systemctl", "disable", unit])
            fncInfo(f"Disabled {unit}")
        except subprocess.CalledProcessError:
            fncWarn(f"{unit} was not enabled")

    # Remove unit files
    for p in (TIMER, SERVICE):
        try:
            if p.exists():
                p.unlink()
                fncOk(f"Removed {p}")
            else:
                fncInfo(f"Not present: {p}")
        except Exception as e:
            fncWarn(f"Could not remove {p}: {e}")

    # Reload systemd after unit removals
    try:
        fncRun(["systemctl", "daemon-reload"])
        fncInfo("systemd daemon reloaded")
    except subprocess.CalledProcessError:
        fncWarn("Failed to reload systemd daemon")

    # Remove installed script & checker
    for p in (SCRIPT_DST, CHECKER):
        try:
            if p.exists():
                p.unlink()
                fncOk(f"Removed {p}")
            else:
                fncInfo(f"Not present: {p}")
        except Exception as e:
            fncWarn(f"Could not remove {p}: {e}")

    # Remove logrotate snippet if present
    LOGROTATE = Path("/etc/logrotate.d/sudomatic5000")
    try:
        if LOGROTATE.exists():
            LOGROTATE.unlink()
            fncOk(f"Removed {LOGROTATE}")
        else:
            fncInfo(f"Not present: {LOGROTATE}")
    except Exception as e:
        fncWarn(f"Could not remove {LOGROTATE}: {e}")

    # Optional removals
    state_root = Path("/var/lib/sudomatic5000")  # parent of pve_oidc_sync
    targets = [
        ("env file", ENVFILE),
        ("log dir", LOGDIR),
        ("state dir", state_root),
    ]

    def ask(q: str) -> bool:
        a = input(fncColor(q + " [y/N]: ", "cyan")).strip().lower()
        return a in ("y", "yes")

    if purge:
        fncHeading("Purging configuration, logs, and state...")
        for label, path in targets:
            try:
                if path.is_file():
                    path.unlink()
                    fncOk(f"Purged {label}: {path}")
                elif path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                    fncOk(f"Purged {label}: {path}")
                else:
                    fncInfo(f"Not present: {label} ({path})")
            except Exception as e:
                fncWarn(f"Failed to purge {label} {path}: {e}")
    else:
        fncHeading("Optional cleanup")
        for label, path in targets:
            try:
                if path.exists() and ask(f"Remove {label} {path}?"):
                    if path.is_file():
                        path.unlink()
                    else:
                        shutil.rmtree(path, ignore_errors=True)
                    fncOk(f"Removed {label}: {path}")
                elif not path.exists():
                    fncInfo(f"Not present: {label} ({path})")
            except Exception as e:
                fncWarn(f"Failed to remove {label} {path}: {e}")

    fncOk("Uninstall complete.")
    fncInfo("If you re-install later, run: "
            + fncColor("systemctl daemon-reload && systemctl enable --now sudomatic.timer", "white", "bold"))

def fncBuildEnvfileContent() -> str:
    """
    Build /etc/sudomatic5000.env content:
    - Runtime: REALM, DEFAULT_SHELL, ALLOWED_UPN_DOMAINS
    - Membership source: Graph vs PVE-only (and Graph auth details)
    """
    import re
    from getpass import getpass

    # ---- tiny inline helpers (keep installer tidy) ----
    def ask_bool(q: str, default: bool = True) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            a = input(f"{fncColor(q, 'cyan', 'bold')} {fncColor(f'[{hint}]', 'gray')}: ").strip().lower()
            if not a:
                return default
            if a in ("y", "yes"):
                return True
            if a in ("n", "no"):
                return False
            fncWarn("Please answer y or n.")

    def ask_nonempty(q: str, default: str | None = None) -> str:
        while True:
            prompt = f"{fncColor(q, 'cyan', 'bold')}{fncColor(f' [{default}]', 'gray') if default else ''}: "
            a = input(prompt).strip()
            if a:
                return a
            if default is not None:
                return default
            fncWarn("Value cannot be empty.")

    def ask_domains() -> str:
        """
        Ask for allowed UPN domains; returns a single space-separated string.
        Empty input means 'allow all'.
        """
        raw = input(fncColor("Allowed UPN domains (space/comma-separated, empty = allow all): ",
                             "cyan", "bold")).strip()
        if not raw:
            return ""
        parts = [p.strip().lower() for p in re.split(r"[,\s]+", raw) if p.strip()]
        return " ".join(sorted(set(parts)))

    # ---- runtime basics ----
    print()
    fncHeading("== Sudomatic 5000 — Runtime configuration ==")
    realm = ask_nonempty("Proxmox Realm name (must match PVE exactly)")
    shell = ask_nonempty("Default shell for new users", default="/bin/bash")
    domains = ask_domains()  # "" => no filtering

    # No global 'grant sudo' — enforce via Super Admin group only
    lines = [
        "# Autogenerated by Sudomatic installer",
        "# Keep this file 0600, owner root",
        "",
        f"REALM={fncShQuote(realm)}",
        f"DEFAULT_SHELL={fncShQuote(shell)}",
        "GRANT_SUDO='false'",            # do NOT grant sudo to all users
        "SUDO_NOPASSWD='false'",         # irrelevant when GRANT_SUDO=false
        f"ALLOWED_UPN_DOMAINS={fncShQuote(domains)}",  # space-separated list or empty
        "",
    ]

    # ---- membership source ----
    if not fncPromptUseGraph():
        fncWarn("Graph enforcement disabled — relying on PVE realm only.")
        lines += [
            "GRAPH_ENFORCE='false'",
            "GRAPH_FAIL_OPEN='true'",  # harmless here
            "# GRAPH_ACCESS_TOKEN=''   # not used when GRAPH_ENFORCE=false",
            "# ENTR_TENANT_ID=''       # not used when GRAPH_ENFORCE=false",
            "# ENTR_CLNT_ID=''         # not used when GRAPH_ENFORCE=false",
            "# ENTR_CLNT_SEC=''        # not used when GRAPH_ENFORCE=false",
        ]
        return "\n".join(lines) + "\n"

    fncOk("Graph enforcement enabled.")
    lines.append("GRAPH_ENFORCE='true'")

    roles = fncGetPveRoles()

    # REQUIRED: All Users / baseline access group
    print()
    fncHeading("== All Users (baseline) group ==")
    all_gid = ask_nonempty("All Users Entra group — Object ID (ENTRA_ALLUSERS_GROUP_ID)")
    lines.append(f"ENTRA_ALLUSERS_GROUP_ID={fncShQuote(all_gid)}")

    # Pick the PVE role for All Users
    all_role = fncChooseFromList(
        "Select PVE role for All Users group",
        roles,
        allow_none=False,
        default="PVEUser" if "PVEUser" in roles else None
    )
    lines.append(f"ENTRA_ALLUSERS_PVE_ROLE={fncShQuote(all_role)}")

    fail_open = ask_bool("Fail OPEN if Graph is unavailable?", default=True)
    lines.append(f"GRAPH_FAIL_OPEN={fncShQuote('true' if fail_open else 'false')}")

    # Optional Super Admin group (sudo-capable; pick PVE role too)
    print()
    fncHeading("== Optional Super Admin group ==")
    fncInfo("Provide the Entra group Object ID (GUID) for Super Admins.")
    fncInfo("This does NOT affect baseline access. Leave blank to skip.")
    sa_gid = input(fncColor("Super Admin Group Object ID (GUID): ", "cyan", "bold")).strip()
    if sa_gid:
        lines.append(f"ENTRA_SUPERADMIN_GROUP_ID={fncShQuote(sa_gid)}")
        sa_role = fncChooseFromList(
            "Select PVE role for Super Admin group",
            roles,
            allow_none=False,
            default="PVEAdmin" if "PVEAdmin" in roles else None
        )
        lines.append(f"ENTRA_SUPERADMIN_PVE_ROLE={fncShQuote(sa_role)}")
        auto = ask_bool("Auto-grant sudo to Super Admin group members?", default=True)
        lines.append(f"SUPERADMIN_GROUP_AUTO_SUDO={'true' if auto else 'false'}")
    else:
        lines.append("ENTRA_SUPERADMIN_GROUP_ID=''")
        lines.append("ENTRA_SUPERADMIN_PVE_ROLE=''")
        lines.append("SUPERADMIN_GROUP_AUTO_SUDO='false'")

    # Optional: additional Entra group → PVE role mappings
    print()
    fncHeading("== Additional Entra Group → PVE Role mappings (optional) ==")
    role_maps = fncPromptRoleMappings()  # already asks for a PVE role per group
    role_maps_json = json.dumps(role_maps, separators=(',', ':'))
    lines.append(f"ENTRA_ROLE_MAP={fncShQuote(role_maps_json)}")

    # Auth mode
    print()
    fncHeading("== Microsoft Graph authentication mode ==")
    mode = fncPromptAuthMode()
    if mode == "access":
        fncInfo("You chose Access Token mode.")
        fncWarn("Delegated tokens are short-lived (~1 hour). Good for testing; not ideal for timers.")
        token = getpass(fncColor("Paste GRAPH_ACCESS_TOKEN (input hidden, can be empty): ", "cyan", "bold")).strip()
        lines.append(f"GRAPH_ACCESS_TOKEN={fncShQuote(token)}")
        lines.append("AUTH_MODE='access'")
    else:
        fncInfo("You chose Application Tokens (client credentials).")
        tenant = ask_nonempty("ENTR_TENANT_ID (Tenant ID GUID)")
        client = ask_nonempty("ENTR_CLNT_ID (App / Client ID GUID)")
        secret = getpass(fncColor("ENTR_CLNT_SEC (Client Secret) [input hidden]: ", "cyan", "bold")).strip()

        # Load the key generated earlier by fncEnsureKeyfile()
        enc_key = fncLoadEncKey()
        if not enc_key:
            fncErr(f"Missing encryption key. Expected {KEYFILE} with {ENC_KEY_ENV}. Aborting to avoid writing plaintext.")
            sys.exit(1)

        try:
            enc = fncEncryptSecretFernet(secret, enc_key)   # -> 'fernet:<token>'
        except Exception as e:
            fncErr(f"Encryption failed ({e}). Aborting to avoid writing plaintext.")
            sys.exit(1)

        lines += [
            f"ENTR_TENANT_ID={fncShQuote(tenant)}",
            f"ENTR_CLNT_ID={fncShQuote(client)}",
            "ENTR_CLNT_SEC=''",                       # never store plaintext
            f"ENTR_CLNT_SEC_ENC={fncShQuote(enc)}",   # encrypted blob
            "AUTH_MODE='application'",
        ]
        fncOk("Encrypted ENTR_CLNT_SEC and stored ENTR_CLNT_SEC_ENC in env.")

    return "\n".join(lines) + "\n"

def fncWriteEnvfile(content: str):
    if ENVFILE.exists():
        fncInfo(f"Updating {ENVFILE}")
    else:
        fncOk(f"Creating {ENVFILE}")
    ENVFILE.write_text(content)
    os.chmod(ENVFILE, 0o600)
    fncOk("Wrote secrets/config to "
          + fncColor("/etc/sudomatic5000.env", "white", "bold")
          + " (mode 0600)")

def fncWriteChecker(expected_sha: str):
    # capture current env/key hashes at generation time (used as baselines)
    try:
        expected_env_sha = fncSha256Sum(ENVFILE) if ENVFILE.exists() else ""
    except Exception:
        expected_env_sha = ""
    try:
        expected_key_sha = fncSha256Sum(KEYFILE) if KEYFILE.exists() else ""
    except Exception:
        expected_key_sha = ""

    checker_script = f"""#!/bin/bash
set -euo pipefail

SCRIPT="{SCRIPT_DST}"
ENVFILE="{ENVFILE}"
KEYFILE="{KEYFILE}"

EXPECTED_SHA="{expected_sha}"
EXPECTED_ENV_SHA="{expected_env_sha}"
EXPECTED_KEY_SHA="{expected_key_sha}"

log_warn() {{
    logger -t sudomatic_runner "$1" || true
    echo "$1" >&2
}}

fail() {{
    logger -t sudomatic_runner "$1" || true
    echo "$1" >&2
    exit 1
}}

check_secure_file() {{
    # $1=path
    local p="$1"
    if [[ ! -e "$p" ]]; then
        log_warn "Integrity: missing file: $p"
        return 0
    fi
    # refuse symlinks
    if [[ -L "$p" ]]; then
        fail "Integrity: refusing to use symlink: $p"
    fi
    # root-owned?
    local uid
    uid=$(stat -Lc %u "$p" 2>/dev/null || echo 99999)
    if [[ "$uid" != "0" ]]; then
        fail "Integrity: $p not owned by root (uid=$uid)"
    fi
    # perms <= 0600
    local mode
    mode=$(stat -Lc %a "$p" 2>/dev/null || echo 777)
    mode=${{mode: -3}}  # last three digits
    if (( 10#"$mode" > 600 )); then
        fail "Integrity: $p permissions too broad (have $mode, want <= 600)"
    fi
}}

sha256_file() {{
    /usr/bin/sha256sum "$1" | awk '{{print $1}}'
}}

# --- 1) Check main script checksum (hard fail on mismatch) ---
ACTUAL_SHA=$(sha256_file "$SCRIPT")
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
    fail "Checksum mismatch! Potential tampering detected in $SCRIPT (have=$ACTUAL_SHA expect=$EXPECTED_SHA)"
fi

# --- 2) Verify ENVFILE hardening; warn if checksum changed ---
check_secure_file "$ENVFILE"
if [[ -e "$ENVFILE" && -n "$EXPECTED_ENV_SHA" ]]; then
    ACTUAL_ENV_SHA=$(sha256_file "$ENVFILE")
    if [[ "$ACTUAL_ENV_SHA" != "$EXPECTED_ENV_SHA" ]]; then
        log_warn "Integrity: env checksum changed: $ENVFILE (have=$ACTUAL_ENV_SHA expect=$EXPECTED_ENV_SHA)"
    fi
fi

# --- 3) Verify KEYFILE hardening; warn if checksum changed ---
check_secure_file "$KEYFILE"
if [[ -e "$KEYFILE" && -n "$EXPECTED_KEY_SHA" ]]; then
    ACTUAL_KEY_SHA=$(sha256_file "$KEYFILE")
    if [[ "$ACTUAL_KEY_SHA" != "$EXPECTED_KEY_SHA" ]]; then
        log_warn "Integrity: key checksum changed: $KEYFILE (have=$ACTUAL_KEY_SHA expect=$EXPECTED_KEY_SHA)"
    fi
fi

exit 0
"""
    CHECKER.write_text(checker_script)
    os.chmod(CHECKER, 0o700)
    fncOk(f"Created/updated checker script at {CHECKER}")

def fncWriteUnits():
    # Service with env file
    service_unit = f"""[Unit]
Description=Sudomatic 5000 — Proxmox OIDC to Linux user sync
After=network-online.target pve-cluster.service
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-{ENVFILE}
EnvironmentFile=-{KEYFILE}
ExecCondition={CHECKER}
ExecStart=/usr/bin/python3 {SCRIPT_DST}
User=root
"""
    SERVICE.write_text(service_unit)
    fncOk(f"Wrote service unit: {SERVICE}")

    timer_unit = """[Unit]
Description=Run Sudomatic 5000 every 30 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=30min
Unit=sudomatic.service
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
"""
    TIMER.write_text(timer_unit)
    fncOk(f"Wrote timer unit: {TIMER}")

def fncDoInstall():
    fncRequireRoot()
    fncHeading("[*] Installing Sudomatic 5000...")

    fncInstallRequirements()
    fncEnsureKeyfile()  # <<< generate the key first

    # Install Python script
    shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
    os.chmod(SCRIPT_DST, 0o700)
    fncOk(f"Installed script to {SCRIPT_DST}")

    # Calculate SHA256 and write checker
    expected_sha = fncSha256Sum(SCRIPT_DST)
    fncInfo(f"Calculated SHA256: {fncColor(expected_sha, 'white', 'bold')}")
    fncWriteChecker(expected_sha)

    # Log directory
    LOGDIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    fncOk(f"Ensured log directory {LOGDIR}")

    # Build env (this will encrypt using the key)
    env_content = fncBuildEnvfileContent()
    fncWriteEnvfile(env_content)

    # Units
    fncWriteUnits()

    # Enable timer
    fncRun(["systemctl", "daemon-reload"])
    fncOk("systemd daemon reloaded")
    fncRun(["systemctl", "enable", "--now", "sudomatic.timer"])
    fncOk("Enabled and started timer: sudomatic.timer")

    fncOk("Installation complete.")
    fncInfo("Check logs: " + fncColor("journalctl -u sudomatic.service -n 200 --no-pager", "white", "bold"))
    fncInfo("Edit config: " + fncColor("/etc/sudomatic5000.env", "white", "bold")
            + " then: " + fncColor("systemctl daemon-reload && systemctl restart sudomatic.service", "white", "bold"))

def fncDoUpdate(auto_restart: bool = False):
    fncRequireRoot()
    fncHeading("[*] Updating Sudomatic 5000...]")

    if not SCRIPT_DST.exists():
        fncErr("Installed script not found, did you run install first?")
        sys.exit(1)
    if not SCRIPT_SRC.exists():
        fncErr(f"Local source not found: {SCRIPT_SRC}")
        sys.exit(1)
    if not CHECKER.exists():
        fncErr("Checker not found, did you run install first?")
        sys.exit(1)

    # Ensure encryption key exists for potential migration
    fncEnsureKeyfile()

    local_sha = fncSha256Sum(SCRIPT_SRC)
    installed_sha = fncSha256Sum(SCRIPT_DST)

    fncInfo(f"Local SHA     : {fncColor(local_sha, 'white', 'bold')}")
    fncInfo(f"Installed SHA : {fncColor(installed_sha, 'white', 'bold')}")

    # ----- Offer to (re)generate /etc/sudomatic5000.env -----
    def ask_yes_no(prompt: str, default_yes: bool = False) -> bool:
        hint = "Y/n" if default_yes else "y/N"
        while True:
            ans = input(f"{fncColor(prompt, 'cyan', 'bold')} {fncColor(f'[{hint}]', 'gray')}: ").strip().lower()
            if not ans:
                return default_yes
            if ans in ("y", "yes"): return True
            if ans in ("n", "no"):  return False
            fncWarn("Please answer y or n.")

    if ENVFILE.exists():
        if ask_yes_no("Re-run config wizard and overwrite /etc/sudomatic5000.env?", default_yes=False):
            # Backup existing file
            ts = __import__("datetime").datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = ENVFILE.with_suffix(ENVFILE.suffix + f".bak-{ts}")
            try:
                shutil.copy2(ENVFILE, backup)
                fncInfo(f"Backed up existing env to {fncColor(str(backup), 'white', 'bold')}")
            except Exception as e:
                fncWarn(f"Could not backup env file ({e}); proceeding anyway.")
            content = fncBuildEnvfileContent()
            fncWriteEnvfile(content)
        else:
            fncInfo("Keeping existing env file.")
            # Migrate plaintext -> encrypted in-place, remove deprecated vars
            fncEncryptIfNeededInEnv(ENVFILE)
    else:
        if ask_yes_no("/etc/sudomatic5000.env not found. Create it now?", default_yes=True):
            content = fncBuildEnvfileContent()
            fncWriteEnvfile(content)
        else:
            fncWarn("Skipping env creation; service may not have credentials/config.")

    # ----- Update script if needed -----
    if local_sha == installed_sha:
        fncWarn("Current installed version already matches local — no update needed.")
    else:
        fncInfo("Updating installed script...")
        shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
        os.chmod(SCRIPT_DST, 0o700)

        new_installed_sha = fncSha256Sum(SCRIPT_DST)
        if new_installed_sha != local_sha:
            fncErr("Post-copy SHA mismatch! Aborting.")
            sys.exit(1)

        fncWriteChecker(new_installed_sha)
        fncOk("Script updated and checksum refreshed.")

    if auto_restart:
        fncRun(["systemctl", "restart", "sudomatic.service"])
        fncOk("Service restarted.")
    else:
        fncInfo("Restart the service with: "
                + fncColor("sudo systemctl restart sudomatic.service", "white", "bold"))

# ============================
# Entry point
# ============================
def fncMain():
    parser = argparse.ArgumentParser(description="Installer/Updater for Sudomatic 5000")
    parser.add_argument("action", choices=["install", "update", "uninstall"], help="Action to perform")
    parser.add_argument("--restart", action="store_true", help="Auto-restart service after update")
    parser.add_argument("--purge", action="store_true", help="Remove env, logs, and state without prompts (DANGEROUS)")
    # If you later add a monochrome flag, call fncSetColorMode(args.blackandwhite) here.
    args = parser.parse_args()

    if args.action == "install":
        fncPrintBanner()
        fncDoInstall()
    elif args.action == "update":
        fncPrintBanner()
        fncDoUpdate(auto_restart=args.restart)
    elif args.action == "uninstall":
        fncPrintBanner()
        fncDoUninstall(purge=args.purge)

if __name__ == "__main__":
    fncMain()
