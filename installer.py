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

# Paths (all relative to current dir = project root)
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

def require_root():
    if os.geteuid() != 0:
        print("[-] This script must be run as root (try sudo)")
        exit(1)

def sha256sum(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd: list[str]):
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def install_requirements():
    if REQS.exists():
        print(f"[*] Found {REQS}, installing dependencies...")
        try:
            run(["pip3", "install", "-r", str(REQS),"--break-system-packages"])
            print("[+] Requirements installed successfully")
        except subprocess.CalledProcessError:
            print("[-] Failed to install requirements.txt")
            exit(1)
    else:
        print("[i] No requirements.txt found, skipping dependency installation.")

_cinit(autoreset=True)

# runtime override (set from argparse)
_COLOR_MONO = False

def set_color_mode(monochrome: bool):
    """Call once after parsing args: set_color_mode(args.blackandwhite)."""
    global _COLOR_MONO
    _COLOR_MONO = bool(monochrome)

def _want_color(stream=sys.stdout):
    # default = color ON; honor NO_COLOR, and runtime override
    if _COLOR_MONO:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    # If you want to force color even when piped: export FORCE_COLOR=1
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return stream.isatty()
    except Exception:
        return False

def c(text: str, *styles: str) -> str:
    """c('Hello', 'green', 'bold') -> styled text (or plain if disabled)."""
    if not _want_color() or not styles:
        return text
    m = {
        "red": F.RED, "green": F.GREEN, "yellow": F.YELLOW, "blue": F.BLUE,
        "magenta": F.MAGENTA, "cyan": F.CYAN, "white": F.WHITE, "gray": F.LIGHTBLACK_EX,
        "bold": S.BRIGHT, "dim": S.DIM,
    }
    seq = "".join(m.get(s, "") for s in styles)
    return f"{seq}{text}{S.RESET_ALL}"

# Convenience printers
def heading(msg: str): print(c(msg, "magenta", "bold"))
def info(msg: str):    print(c("[*] ", "cyan") + msg)
def ok(msg: str):      print(c("[+] ", "green") + msg)
def warn(msg: str):    print(c("[!] ", "yellow") + msg)
def err(msg: str):     print(c("[-] ", "red") + msg)

def fncPrintBanner():
    print(F.CYAN + BANNER + S.RESET_ALL)
    print(random.choice(BLURBS))

def fncPrintVersion():
    print(F.CYAN + VERSION_INFO + S.RESET_ALL)

def sha256sum(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd: list[str]):
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def sh_quote(val: str) -> str:
    """Safe-ish single-quoted value for env files."""
    if val is None:
        val = ""
    return "'" + val.replace("'", "'\"'\"'") + "'"

def prompt_use_graph() -> bool:
    heading("\n== Sudomatic 5000 — Membership Source ==")
    print(f"{c('[1]', 'white')} Use {c('Microsoft Graph', 'cyan')} (enforce members from an Entra group)")
    print(f"{c('[2]', 'white')} Rely on {c('PVE realm accounts only', 'yellow')} (no Graph enforcement)")
    while True:
        choice = input(f"{c('?', 'cyan')} Choose {c('1', 'white')} or {c('2', 'white')} [{c('2', 'green')}]: ").strip() or "2"
        if choice in ("1", "2"):
            return choice == "1"
        warn("Please enter 1 or 2.")

def prompt_auth_mode() -> str:
    heading("\n== Microsoft Graph authentication mode ==")
    print(f"{c('[1]', 'white')} Access Token ({c('GRAPH_ACCESS_TOKEN', 'magenta')}) — quick testing; short-lived")
    print(f"{c('[2]', 'white')} Application Tokens (Client Credentials) — "
          f"{c('ENTR_TENANT_ID', 'magenta')}/{c('ENTR_CLNT_ID', 'magenta')}/{c('ENTR_CLNT_SEC', 'magenta')}")
    while True:
        choice = input(f"{c('?', 'cyan')} Choose {c('1', 'white')} or {c('2', 'white')} [{c('2', 'green')}]: ").strip() or "2"
        if choice in ("1", "2"):
            return "access" if choice == "1" else "application"
        warn("Please enter 1 or 2.")

def _pvesh_roles() -> list[str]:
    """Return available PVE roles using pvesh; fall back to defaults."""
    try:
        out = subprocess.run(
            ["/usr/bin/pvesh", "get", "/access/roles", "--output-format", "json"],
            check=True, capture_output=True, text=True
        ).stdout
        data = json.loads(out)
        roles = sorted({item.get("roleid") for item in data if item.get("roleid")})
        if roles:
            ok("Detected PVE roles: " + ", ".join(roles))
            return roles
        warn("No roles returned by pvesh; falling back to defaults.")
        return ["PVEAdmin", "PVEAuditor", "PVEUser"]
    except Exception:
        warn("Could not query pvesh; using default roles.")
        return ["PVEAdmin", "PVEAuditor", "PVEUser"]

def _choose_from_list(prompt_title: str, options: list[str], allow_none: bool = True, default: str | None = None) -> str | None:
    """Indexed chooser for small lists; returns selected item or None."""
    opts = list(options)
    if allow_none:
        opts = ["<none>"] + opts

    heading(f"\n== {prompt_title} ==")
    for i, o in enumerate(opts, 1):
        is_default = default is not None and o == default
        mark = f" {c('(default)', 'green')}" if is_default else ""
        label = f"{c(f'[{i}]', 'white')} " + (c(o, 'cyan') if o != "<none>" else c(o, 'yellow'))
        print(f"{label}{mark}")

    hint = f" [{c(str(opts.index(default)+1), 'green')}]" if default in opts else ""
    while True:
        raw = input(f"{c('?', 'cyan')} Choose {c(f'1-{len(opts)}', 'white')}{hint}: ").strip()
        if not raw and default in opts:
            return None if (allow_none and default == "<none>") else default
        if raw.isdigit():
            i = int(raw)
            if 1 <= i <= len(opts):
                choice = opts[i-1]
                return None if (allow_none and choice == "<none>") else choice
        warn("Invalid selection, try again.")

def prompt_super_admin_group() -> tuple[str, bool]:
    """Ask for optional Super Admin group; optionally auto-sudo just for that group."""
    heading("\n== Optional Super Admin group ==")
    print("Provide the Entra group " + c("Object ID", "bold") + " (GUID) for Super Admins.")
    print(c("This does NOT affect other users. Leave blank to skip.", "yellow"))
    gid = input(f"{c('?', 'cyan')} Super Admin Group Object ID (GUID): ").strip()
    auto = False
    if gid:
        auto = input(f"{c('?', 'cyan')} Auto-grant {c('sudo', 'bold')} to Super Admin members? [{c('Y', 'green')}/n]: ").strip().lower() in ("", "y", "yes")
    return gid, auto

def prompt_all_users_group() -> tuple[str | None, str | None]:
    """Optional All Users group (baseline); map it to a PVE role."""
    heading("\n== Optional 'All Users' group ==")
    print("Provide an Entra group Object ID that grants baseline access to *all* its members on this host.")
    print(c("Leave blank to skip.", "yellow"))
    gid = input(f"{c('?', 'cyan')} All Users Group Object ID (GUID): ").strip()
    if not gid:
        return None, None
    roles = _pvesh_roles()
    chosen = _choose_from_list("Select baseline PVE role for All Users", roles, allow_none=True,
                               default="PVEUser" if "PVEUser" in roles else None)
    return gid, chosen

def prompt_role_mappings() -> list[dict]:
    """Zero or more Entra group → PVE role mappings."""
    mappings = []
    roles = _pvesh_roles()
    heading("\n== Entra Group → PVE Role mappings (optional) ==")
    print("You can add multiple role mappings. Leave Group ID empty to finish.")
    while True:
        gid = input(f"{c('?', 'cyan')} Entra Group Object ID for role mapping {c('(blank to finish)', 'white')}: ").strip()
        if not gid:
            break
        role = _choose_from_list(f"Choose PVE role for {gid}", roles, allow_none=False,
                                 default="PVEAuditor" if "PVEAuditor" in roles else None)
        mappings.append({"group": gid, "pve_role": role})
        ok(f"Added mapping: {gid} → {role}")
    return mappings

def do_uninstall(purge: bool = False):
    require_root()
    heading("[*] Uninstalling Sudomatic 5000...")

    # Stop & disable units (ignore failures if not present)
    for unit in ("sudomatic.timer", "sudomatic.service"):
        try:
            run(["systemctl", "stop", unit])
            info(f"Stopped {unit}")
        except subprocess.CalledProcessError:
            warn(f"{unit} was not running")
            pass
        try:
            run(["systemctl", "disable", unit])
            info(f"Disabled {unit}")
        except subprocess.CalledProcessError:
            warn(f"{unit} was not enabled")
            pass

    # Remove unit files
    for p in (TIMER, SERVICE):
        try:
            if p.exists():
                p.unlink()
                ok(f"Removed {p}")
            else:
                info(f"Not present: {p}")
        except Exception as e:
            warn(f"Could not remove {p}: {e}")

    # Reload systemd after unit removals
    try:
        run(["systemctl", "daemon-reload"])
        info("systemd daemon reloaded")
    except subprocess.CalledProcessError:
        warn("Failed to reload systemd daemon")
        pass

    # Remove installed script & checker
    for p in (SCRIPT_DST, CHECKER):
        try:
            if p.exists():
                p.unlink()
                ok(f"Removed {p}")
            else:
                info(f"Not present: {p}")
        except Exception as e:
            warn(f"Could not remove {p}: {e}")

    # Remove logrotate snippet if present
    LOGROTATE = Path("/etc/logrotate.d/sudomatic5000")
    try:
        if LOGROTATE.exists():
            LOGROTATE.unlink()
            ok(f"Removed {LOGROTATE}")
        else:
            info(f"Not present: {LOGROTATE}")
    except Exception as e:
        warn(f"Could not remove {LOGROTATE}: {e}")

    # Optional removals
    state_root = Path("/var/lib/sudomatic5000")  # parent of pve_oidc_sync
    targets = [
        ("env file", ENVFILE),
        ("log dir", LOGDIR),
        ("state dir", state_root),
    ]

    def ask(q: str) -> bool:
        a = input(c(q + " [y/N]: ", "cyan")).strip().lower()
        return a in ("y", "yes")

    if purge:
        heading("Purging configuration, logs, and state...")
        for label, path in targets:
            try:
                if path.is_file():
                    path.unlink()
                    ok(f"Purged {label}: {path}")
                elif path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                    ok(f"Purged {label}: {path}")
                else:
                    info(f"Not present: {label} ({path})")
            except Exception as e:
                warn(f"Failed to purge {label} {path}: {e}")
    else:
        heading("Optional cleanup")
        for label, path in targets:
            try:
                if path.exists() and ask(f"Remove {label} {path}?"):
                    if path.is_file():
                        path.unlink()
                    else:
                        shutil.rmtree(path, ignore_errors=True)
                    ok(f"Removed {label}: {path}")
                elif not path.exists():
                    info(f"Not present: {label} ({path})")
            except Exception as e:
                warn(f"Failed to remove {label} {path}: {e}")

    ok("Uninstall complete.")
    info("If you re-install later, run: "
         + c("systemctl daemon-reload && systemctl enable --now sudomatic.timer", "white", "bold"))

def build_envfile_content() -> str:
    """
    Build /etc/sudomatic5000.env content:
    - Runtime: REALM, DEFAULT_SHELL, ALLOWED_UPN_DOMAINS
    - Membership source: Graph vs PVE-only (and Graph auth details)
    """
    import re
    from getpass import getpass

    # ---- tiny inline helpers (keep installer.py tidy) ----
    def ask_bool(q: str, default: bool = True) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            a = input(f"{c(q, 'cyan', 'bold')} {c(f'[{hint}]', 'gray')}: ").strip().lower()
            if not a:
                return default
            if a in ("y", "yes"):
                return True
            if a in ("n", "no"):
                return False
            warn("Please answer y or n.")

    def ask_nonempty(q: str, default: str | None = None) -> str:
        while True:
            prompt = f"{c(q, 'cyan', 'bold')}{c(f' [{default}]', 'gray') if default else ''}: "
            a = input(prompt).strip()
            if a:
                return a
            if default is not None:
                return default
            warn("Value cannot be empty.")

    def ask_domains() -> str:
        """
        Ask for allowed UPN domains; returns a single space-separated string.
        Empty input means 'allow all'.
        """
        raw = input(c("Allowed UPN domains (space/comma-separated, empty = allow all): ",
                      "cyan", "bold")).strip()
        if not raw:
            return ""
        parts = [p.strip().lower() for p in re.split(r"[,\s]+", raw) if p.strip()]
        return " ".join(sorted(set(parts)))

    # ---- runtime basics ----
    print()
    heading("== Sudomatic 5000 — Runtime configuration ==")
    realm = ask_nonempty("Proxmox Realm name (must match PVE exactly)")
    shell = ask_nonempty("Default shell for new users", default="/bin/bash")
    domains = ask_domains()  # "" => no filtering

    # No global 'grant sudo' — enforce via Super Admin group only
    lines = [
        "# Autogenerated by Sudomatic installer",
        "# Keep this file 0600, owner root",
        "",
        f"REALM={sh_quote(realm)}",
        f"DEFAULT_SHELL={sh_quote(shell)}",
        "GRANT_SUDO='false'",            # do NOT grant sudo to all users
        "SUDO_NOPASSWD='false'",         # irrelevant when GRANT_SUDO=false
        f"ALLOWED_UPN_DOMAINS={sh_quote(domains)}",  # space-separated list or empty
        "",
    ]

    # ---- membership source ----
    if not prompt_use_graph():
        warn("Graph enforcement disabled — relying on PVE realm only.")
        lines += [
            "GRAPH_ENFORCE='false'",
            "GRAPH_FAIL_OPEN='true'",  # harmless here
            "# ENTR_SUPERUSR_ID=''     # not used when GRAPH_ENFORCE=false",
            "# GRAPH_ACCESS_TOKEN=''   # not used when GRAPH_ENFORCE=false",
            "# ENTR_TENANT_ID=''       # not used when GRAPH_ENFORCE=false",
            "# ENTR_CLNT_ID=''         # not used when GRAPH_ENFORCE=false",
            "# ENTR_CLNT_SEC=''        # not used when GRAPH_ENFORCE=false",
        ]
        return "\n".join(lines) + "\n"

    ok("Graph enforcement enabled.")
    lines.append("GRAPH_ENFORCE='true'")

    roles = _pvesh_roles()

    # REQUIRED: All Users / baseline access group
    print()
    heading("== All Users (baseline) group ==")
    all_gid = ask_nonempty("All Users Entra group — Object ID (ENTRA_ALLUSERS_GROUP_ID)")
    lines.append(f"ENTRA_ALLUSERS_GROUP_ID={sh_quote(all_gid)}")

    # Pick the PVE role for All Users
    all_role = _choose_from_list(
        "Select PVE role for All Users group",
        roles,
        allow_none=False,
        default="PVEUser" if "PVEUser" in roles else None
    )
    lines.append(f"ENTRA_ALLUSERS_PVE_ROLE={sh_quote(all_role)}")

    # Back-compat: also populate ENTR_SUPERUSR_ID with the same ID
    lines.append(f"ENTR_SUPERUSR_ID={sh_quote(all_gid)}  # DEPRECATED alias; using ENTRA_ALLUSERS_GROUP_ID")

    fail_open = ask_bool("Fail OPEN if Graph is unavailable?", default=True)
    lines.append(f"GRAPH_FAIL_OPEN={sh_quote('true' if fail_open else 'false')}")

    # Optional Super Admin group (sudo-capable; pick PVE role too)
    print()
    heading("== Optional Super Admin group ==")
    info("Provide the Entra group Object ID (GUID) for Super Admins.")
    info("This does NOT affect baseline access. Leave blank to skip.")
    sa_gid = input(c("Super Admin Group Object ID (GUID): ", "cyan", "bold")).strip()
    if sa_gid:
        lines.append(f"ENTRA_SUPERADMIN_GROUP_ID={sh_quote(sa_gid)}")
        sa_role = _choose_from_list(
            "Select PVE role for Super Admin group",
            roles,
            allow_none=False,
            default="PVEAdmin" if "PVEAdmin" in roles else None
        )
        lines.append(f"ENTRA_SUPERADMIN_PVE_ROLE={sh_quote(sa_role)}")
        auto = ask_bool("Auto-grant sudo to Super Admin group members?", default=True)
        lines.append(f"SUPERADMIN_GROUP_AUTO_SUDO={'true' if auto else 'false'}")
    else:
        lines.append("ENTRA_SUPERADMIN_GROUP_ID=''")
        lines.append("ENTRA_SUPERADMIN_PVE_ROLE=''")
        lines.append("SUPERADMIN_GROUP_AUTO_SUDO='false'")

    # Optional: additional Entra group → PVE role mappings
    print()
    heading("== Additional Entra Group → PVE Role mappings (optional) ==")
    role_maps = prompt_role_mappings()  # already asks for a PVE role per group
    role_maps_json = json.dumps(role_maps, separators=(',', ':'))
    lines.append(f"ENTRA_ROLE_MAP={sh_quote(role_maps_json)}")

    # Auth mode
    print()
    heading("== Microsoft Graph authentication mode ==")
    mode = prompt_auth_mode()
    if mode == "access":
        info("You chose Access Token mode.")
        warn("Delegated tokens are short-lived (~1 hour). Good for testing; not ideal for timers.")
        token = getpass(c("Paste GRAPH_ACCESS_TOKEN (input hidden, can be empty): ", "cyan", "bold")).strip()
        lines.append(f"GRAPH_ACCESS_TOKEN={sh_quote(token)}")
        lines.append("AUTH_MODE='access'")
    else:
        info("You chose Application Tokens (client credentials).")
        tenant = ask_nonempty("ENTR_TENANT_ID (Tenant ID GUID)")
        client = ask_nonempty("ENTR_CLNT_ID (App / Client ID GUID)")
        secret = getpass(c("ENTR_CLNT_SEC (Client Secret) [input hidden]: ", "cyan", "bold")).strip()
        lines += [
            f"ENTR_TENANT_ID={sh_quote(tenant)}",
            f"ENTR_CLNT_ID={sh_quote(client)}",
            f"ENTR_CLNT_SEC={sh_quote(secret)}",
            "AUTH_MODE='application'",
        ]

    return "\n".join(lines) + "\n"

def write_envfile(content: str):
    if ENVFILE.exists():
        info(f"Updating {ENVFILE}")
    else:
        ok(f"Creating {ENVFILE}")
    ENVFILE.write_text(content)
    os.chmod(ENVFILE, 0o600)
    ok("Wrote secrets/config to "
       + c("/etc/sudomatic5000.env", "white", "bold")
       + " (mode 0600)")

def write_checker(expected_sha: str):
    checker_script = f"""#!/bin/bash
SCRIPT="{SCRIPT_DST}"
EXPECTED_SHA="{expected_sha}"
ACTUAL_SHA=$(sha256sum "$SCRIPT" | awk '{{print $1}}')

if [ "$ACTUAL_SHA" = "$EXPECTED_SHA" ]; then
    exit 0
else
    MSG="Checksum mismatch! Potential tampering detected in $SCRIPT"
    echo "$MSG" >&2
    logger -t sudomatic_runner "$MSG"
    exit 1
fi
"""
    CHECKER.write_text(checker_script)
    os.chmod(CHECKER, 0o700)
    ok(f"Created/updated checker script at {CHECKER}")

def write_units():
    # Service with env file
    service_unit = f"""[Unit]
Description=Sudomatic 5000 — Proxmox OIDC to Linux user sync
After=network-online.target pve-cluster.service
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-{ENVFILE}
ExecCondition={CHECKER}
ExecStart=/usr/bin/python3 {SCRIPT_DST}
User=root
"""
    SERVICE.write_text(service_unit)
    ok(f"Wrote service unit: {SERVICE}")

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
    ok(f"Wrote timer unit: {TIMER}")

def do_install():
    require_root()
    heading("[*] Installing Sudomatic 5000...")

    install_requirements()

    # Install Python script
    shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
    os.chmod(SCRIPT_DST, 0o700)
    ok(f"Installed script to {SCRIPT_DST}")

    # Calculate SHA256 and write checker
    expected_sha = sha256sum(SCRIPT_DST)
    info(f"Calculated SHA256: {c(expected_sha, 'white', 'bold')}")
    write_checker(expected_sha)

    # Log directory
    LOGDIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    ok(f"Ensured log directory {LOGDIR}")

    # Build env file (Graph vs PVE-only)
    env_content = build_envfile_content()
    write_envfile(env_content)

    # Units
    write_units()

    # Enable timer
    run(["systemctl", "daemon-reload"])
    ok("systemd daemon reloaded")
    run(["systemctl", "enable", "--now", "sudomatic.timer"])
    ok("Enabled and started timer: sudomatic.timer")

    ok("Installation complete.")
    info("Check logs: " + c("journalctl -u sudomatic.service -n 200 --no-pager", "white", "bold"))
    info("Edit config: " + c("/etc/sudomatic5000.env", "white", "bold")
         + " then: " + c("systemctl daemon-reload && systemctl restart sudomatic.service", "white", "bold"))

def do_update(auto_restart: bool = False):
    require_root()
    heading("[*] Updating Sudomatic 5000...")

    if not SCRIPT_DST.exists():
        err("Installed script not found, did you run install first?")
        exit(1)
    if not SCRIPT_SRC.exists():
        err(f"Local source not found: {SCRIPT_SRC}")
        exit(1)
    if not CHECKER.exists():
        err("Checker not found, did you run install first?")
        exit(1)

    local_sha = sha256sum(SCRIPT_SRC)
    installed_sha = sha256sum(SCRIPT_DST)

    info(f"Local SHA     : {c(local_sha, 'white', 'bold')}")
    info(f"Installed SHA : {c(installed_sha, 'white', 'bold')}")

    # ----- Offer to (re)generate /etc/sudomatic5000.env -----
    def ask_yes_no(prompt: str, default_yes: bool = False) -> bool:
        hint = "Y/n" if default_yes else "y/N"
        while True:
            ans = input(f"{c(prompt, 'cyan', 'bold')} {c(f'[{hint}]', 'gray')}: ").strip().lower()
            if not ans:
                return default_yes
            if ans in ("y", "yes"): return True
            if ans in ("n", "no"):  return False
            warn("Please answer y or n.")

    if ENVFILE.exists():
        if ask_yes_no("Re-run config wizard and overwrite /etc/sudomatic5000.env?", default_yes=False):
            # Backup existing file
            ts = __import__("datetime").datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = ENVFILE.with_suffix(ENVFILE.suffix + f".bak-{ts}")
            try:
                shutil.copy2(ENVFILE, backup)
                info(f"Backed up existing env to {c(str(backup), 'white', 'bold')}")
            except Exception as e:
                warn(f"Could not backup env file ({e}); proceeding anyway.")
            content = build_envfile_content()
            write_envfile(content)
        else:
            info("Keeping existing env file.")
    else:
        if ask_yes_no("/etc/sudomatic5000.env not found. Create it now?", default_yes=True):
            content = build_envfile_content()
            write_envfile(content)
        else:
            warn("Skipping env creation; service may not have credentials/config.")

    # ----- Update script if needed -----
    if local_sha == installed_sha:
        warn("Current installed version already matches local — no update needed.")
    else:
        info("Updating installed script...")
        shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
        os.chmod(SCRIPT_DST, 0o700)

        new_installed_sha = sha256sum(SCRIPT_DST)
        if new_installed_sha != local_sha:
            err("Post-copy SHA mismatch! Aborting.")
            exit(1)

        write_checker(new_installed_sha)
        ok("Script updated and checksum refreshed.")

    if auto_restart:
        run(["systemctl", "restart", "sudomatic.service"])
        ok("Service restarted.")
    else:
        info("Restart the service with: "
             + c("sudo systemctl restart sudomatic.service", "white", "bold"))

def main():
    parser = argparse.ArgumentParser(description="Installer/Updater for Sudomatic 5000")
    parser.add_argument("action", choices=["install", "update", "uninstall"], help="Action to perform")
    parser.add_argument("--restart", action="store_true", help="Auto-restart service after update")
    parser.add_argument("--purge", action="store_true", help="Remove env, logs, and state without prompts (DANGEROUS)")
    args = parser.parse_args()

    if args.action == "install":
        fncPrintBanner()
        do_install()
    elif args.action == "update":
        fncPrintBanner()
        do_update(auto_restart=args.restart)
    elif args.action == "uninstall":
        fncPrintBanner()
        do_uninstall(purge=args.purge)
    elif args.action == "version":
        fncPrintVersion()
        sys.exit(0)

if __name__ == "__main__":
    main()
