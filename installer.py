#!/usr/bin/env python3
import os
import sys
import shutil
import hashlib
import subprocess
import random
import secrets
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
SCRIPT_SRC = ROOT_DIR / "entramoxreconciler.py"
REQS = ROOT_DIR / "requirements.txt"
VERSION = "2.5.0"

# ============================================================
# NEW: entramoxreconciler (current installation target)
# ============================================================
SCRIPT_DST = Path("/usr/local/sbin/entramoxreconciler.py")
CHECKER    = Path("/usr/local/sbin/entramox_check.sh")
SERVICE    = Path("/etc/systemd/system/entramoxreconciler.service")
TIMER      = Path("/etc/systemd/system/entramoxreconciler.timer")
LOGDIR     = Path("/var/log/entramoxreconciler")
ENVFILE    = Path("/etc/entramoxreconciler.env")
KEYFILE    = Path("/etc/entramoxreconciler.key")

# Per-service credential directory - secrets split from the main env file.
# Each file is mode 0600 so a compromise of one service's token does not
# expose the others. The directory itself is mode 0700.
CONF_DIR    = Path("/etc/entramoxreconciler")
GRAPH_ENVFILE = CONF_DIR / "graph.env"   # ENTR_CLNT_SEC_ENC / GRAPH_ACCESS_TOKEN
PBS_ENVFILE   = CONF_DIR / "pbs.env"     # PBS_TOKEN_VALUE_ENC
PDM_ENVFILE   = CONF_DIR / "pdm.env"     # PDM_TOKEN_VALUE_ENC
SSH_ENVFILE   = CONF_DIR / "ssh.env"     # SSH_KEY_PASSPHRASE_ENC

# SSH key used to reach the remote Proxmox services (PBS/PDM). The private key
# and its (encrypted) passphrase stay on this host; the public key is handed to
# the operator to install on each remote host.
SSH_KEYDIR      = CONF_DIR / "ssh"
SSH_KEY_PATH    = SSH_KEYDIR / "id_ed25519"
SSH_PUBKEY_NAME = "entramox_ssh_ed25519.pub"   # copy dropped in the CWD

# Separate baseline file - stores expected hashes independently of the
# checker script so an attacker cannot just replace both atomically.
BASELINE   = CONF_DIR / "baseline.sha256"

# Vars extracted into per-service files (stripped from the main env)
_GRAPH_SECRET_VARS = {"ENTR_CLNT_SEC_ENC", "GRAPH_ACCESS_TOKEN"}
_PBS_SECRET_VARS   = {"PBS_TOKEN_VALUE_ENC"}
_PDM_SECRET_VARS   = {"PDM_TOKEN_VALUE_ENC"}
_SSH_SECRET_VARS   = {"SSH_KEY_PASSPHRASE_ENC"}

# Encryption key env var name
ENC_KEY_ENV = "ENTRAMOX_ENC_KEY"

ENV_ASSIGN_RE = re.compile(
    r"""^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^']*)'|"([^"]*)"|([^\s#]+))\s*(?:#.*)?$"""
)

BANNER = r"""
  ______       _                                   _____                           _ _
 |  ____|     | |                                 |  __ \                         (_) |
 | |__   _ __ | |_ _ __ __ _ _ __ ___   _____  __ | |__) |___  ___ ___  _ __   ___ _| | ___ _ __
 |  __| | '_ \| __| '__/ _` | '_ ` _ \ / _ \ \/ / |  _  // _ \/ __/ _ \| '_ \ / __| | |/ _ \ '__|
 | |____| | | | |_| | | (_| | | | | | | (_) >  <  | | \ \  __/ (_| (_) | | | | (__| | |  __/ |
 |______|_| |_|\__|_|  \__,_|_| |_| |_|\___/_/\_\ |_|  \_\___|\___\___/|_| |_|\___|_|_|\___|_|
                Turning realms into real users, one sudo at a time.
                ------------------------------------------------
                ::        %INSERT RELEVANT DISCORD HERE       ::
                :: https://github.com/deannreid/EntramoxReconciler ::
                ------------------------------------------------
"""

VERSION_INFO = f"""
==============================================
| Deano's Entramox Reconciler                 |
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
| 26/12/2025: Renamed Script to something     |
|             useful.                         |
| 09/04/2026: v2.5 - PBS + PDM integration,   |
|             tiered account support,         |
|             multi-group user descriptions,  |
|             structured SIEM audit log,      |
|             improved security model.        |
| 10/04/2026: Security hardening - Fernet TTL,|
|             split credential files, retry  |
|             backoff, MAX_USERS_PER_RUN,     |
|             GRAPH_FAIL_POLICY, stale lock   |
|             cleanup, audit log 0640.        |
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

def fncEnvBackupPath(p: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return p.with_suffix(p.suffix + f".bak-{ts}")

# ============================
# Key helpers
# ============================
def fncEnsureKeyfile():
    """Ensure KEYFILE exists with a Fernet key (mode 0600). Writes ENC_KEY_ENV going forward."""
    from base64 import urlsafe_b64encode
    try:
        if KEYFILE.exists():
            os.chmod(KEYFILE, 0o600)
            return
        raw = os.urandom(32)
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
    """Prefer env (runtime), else the keyfile."""
    val = os.environ.get(ENC_KEY_ENV, "").strip()
    if val:
        return val
    return _fncParseKeyfile(KEYFILE)

def fncEncryptSecretFernet(secret: str, key_b64: str) -> str:
    from cryptography.fernet import Fernet
    token = Fernet(key_b64.encode()).encrypt(secret.encode()).decode()
    return f"fernet:{token}"

def fncEncryptIfNeededInEnv(env_path: Path = ENVFILE):
    """
    If ENTR_CLNT_SEC (plaintext) exists, encrypt it to ENTR_CLNT_SEC_ENC using ENC_KEY_ENV/KEYFILE
    and blank ENTR_CLNT_SEC. Preserves comments/formatting as much as possible.
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

    plain_val, plain_idx = None, None
    enc_idx = None

    for idx, line in enumerate(lines):
        m = ENV_ASSIGN_RE.match(line)
        if not m:
            continue
        key = m.group(1)
        val = m.group(2) or m.group(3) or m.group(4) or ""

        if key == "ENTR_CLNT_SEC" and val.strip():
            plain_val, plain_idx = val, idx
        elif key == "ENTR_CLNT_SEC_ENC" and val.strip():
            enc_idx = idx

    if plain_val is not None:
        if enc_idx is None:
            try:
                enc_blob = fncEncryptSecretFernet(plain_val, enc_key)
            except Exception as e:
                fncErr(f"Failed to encrypt existing ENTR_CLNT_SEC: {e}")
                return
            lines.append("")
            lines.append(f"ENTR_CLNT_SEC_ENC={fncShQuote(enc_blob)}")
            changed = True

        if plain_idx is not None and not lines[plain_idx].startswith("#"):
            lines[plain_idx] = "ENTR_CLNT_SEC=''"
            changed = True

    if not changed:
        fncInfo("Env examined; no changes required.")
        return

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
    fncHeading("\n== Entramox Reconciler - Membership Source ==")
    print(f"{fncColor('[1]', 'white')} Use {fncColor('Microsoft Graph', 'cyan')} (enforce members from an Entra group)")
    print(f"{fncColor('[2]', 'white')} Rely on {fncColor('PVE realm accounts only', 'yellow')} (no Graph enforcement)")
    while True:
        choice = input(f"{fncColor('?', 'cyan')} Choose {fncColor('1', 'white')} or {fncColor('2', 'white')} [{fncColor('2', 'green')}]: ").strip() or "2"
        if choice in ("1", "2"):
            return choice == "1"
        fncWarn("Please enter 1 or 2.")

def fncPromptAuthMode() -> str:
    fncHeading("\n== Microsoft Graph authentication mode ==")
    print(f"{fncColor('[1]', 'white')} Access Token ({fncColor('GRAPH_ACCESS_TOKEN', 'magenta')}) - quick testing; short-lived")
    print(f"{fncColor('[2]', 'white')} Application Tokens (Client Credentials) - "
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

def fncPromptRoleMappings() -> list[dict]:
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
# Build env content
# ============================
def _read_env_var_from_file(path: Path, key: str) -> str | None:
    """Return the value of KEY=... from an env file (quoted or bare), or None."""
    try:
        if not path.exists():
            return None
        for line in path.read_text().splitlines():
            m = ENV_ASSIGN_RE.match(line.strip())
            if m and m.group(1) == key:
                return m.group(2) or m.group(3) or m.group(4) or ""
    except Exception:
        return None
    return None


def fncProvisionSshKey(targets: list[tuple[str, str, str]]) -> list[str]:
    """
    Provision a passphrase-protected ed25519 SSH key for reaching the remote
    hosts that need it (PBS/PDM and/or fan-out nodes).

    The private key and its passphrase stay on this host: the passphrase is
    Fernet-encrypted into the env (SSH_KEY_PASSPHRASE_ENC), the keypair lives
    under CONF_DIR/ssh, the public key is also dropped in the current directory,
    and the operator is shown how to install it on each remote host.

    `targets` is a list of (label, host, ssh_user) tuples for the hosts that need
    the key installed. Returns env lines to merge into the generated env content.
    Non-fatal: any failure warns and returns [] so the install still completes.
    """
    print()
    fncHeading("== SSH key for remote hosts (PBS/PDM and/or fan-out nodes) ==")

    if not shutil.which("ssh-keygen"):
        fncWarn("ssh-keygen not found (install openssh-client). Skipping SSH key generation.")
        return []

    enc_key = fncLoadEncKey()
    if not enc_key:
        fncErr(f"Missing encryption key. Expected {KEYFILE} with {ENC_KEY_ENV}. Skipping SSH key.")
        return []

    try:
        SSH_KEYDIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CONF_DIR, 0o700)
        os.chmod(SSH_KEYDIR, 0o700)
    except Exception as e:
        fncErr(f"Could not create SSH key directory {SSH_KEYDIR}: {e}")
        return []

    pub_path = SSH_KEY_PATH.with_suffix(".pub")
    env_lines = [
        "",
        "# SSH key for remote Proxmox services (PBS/PDM)",
        f"SSH_KEY_PATH={fncShQuote(str(SSH_KEY_PATH))}",
    ]

    if SSH_KEY_PATH.exists():
        # Wizard re-run: keep the existing key (its passphrase can't be
        # recovered to re-encrypt) and preserve the already-stored passphrase
        # so re-writing the env files doesn't drop it.
        fncWarn(f"SSH key already exists at {SSH_KEY_PATH}; keeping it.")
        fncInfo("Delete it and re-run the wizard if you want a fresh key.")
        existing = _read_env_var_from_file(SSH_ENVFILE, "SSH_KEY_PASSPHRASE_ENC")
        if existing:
            env_lines.append(f"SSH_KEY_PASSPHRASE_ENC={fncShQuote(existing)}")
        else:
            fncWarn("Could not find the stored passphrase for the existing key.")
    else:
        passphrase = secrets.token_urlsafe(32)
        proc = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-a", "100",
             "-N", passphrase, "-C", "entramoxreconciler",
             "-f", str(SSH_KEY_PATH)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            fncErr(f"ssh-keygen failed: {(proc.stderr or proc.stdout).strip()}")
            return []
        try:
            os.chmod(SSH_KEY_PATH, 0o600)
            os.chmod(pub_path, 0o644)
        except Exception:
            pass
        try:
            enc_pass = fncEncryptSecretFernet(passphrase, enc_key)
        except Exception as e:
            fncErr(f"Failed to encrypt SSH passphrase: {e}")
            return []
        env_lines.append(f"SSH_KEY_PASSPHRASE_ENC={fncShQuote(enc_pass)}")
        fncOk(f"Generated ed25519 SSH key: {fncColor(str(SSH_KEY_PATH), 'white', 'bold')}")
        fncOk("SSH key passphrase encrypted and stored.")

    # Read the public key and drop a copy in the current working directory.
    try:
        pub_text = pub_path.read_text().strip()
    except Exception as e:
        fncWarn(f"Could not read public key {pub_path}: {e}")
        return env_lines

    cwd_pub = Path.cwd() / SSH_PUBKEY_NAME
    try:
        cwd_pub.write_text(pub_text + "\n")
        os.chmod(cwd_pub, 0o644)
        fncOk("Public key copied to " + fncColor(str(cwd_pub), "white", "bold"))
    except Exception as e:
        fncWarn(f"Could not write public key to {cwd_pub}: {e}")

    # Operator instructions
    print()
    fncHeading("== ACTION REQUIRED: install this public key on the remote host(s) ==")
    fncInfo("Append the key below to ~/.ssh/authorized_keys for the login user on each host:")
    print(fncColor("  " + pub_text, "green"))
    for label, host, ssh_user in targets:
        if not host:
            continue
        fncInfo(f"{label} ({host}): "
                + fncColor(f"ssh-copy-id -i {pub_path} {ssh_user}@{host}", "white", "bold"))
    fncInfo("(or paste it manually if password SSH login is disabled on the remote).")

    return env_lines


def fncBuildEnvfileContent() -> str:
    import re
    from getpass import getpass

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
        raw = input(fncColor("Allowed UPN domains (space/comma-separated, empty = allow all): ",
                             "cyan", "bold")).strip()
        if not raw:
            return ""
        parts = [p.strip().lower() for p in re.split(r"[,\s]+", raw) if p.strip()]
        return " ".join(sorted(set(parts)))

    print()
    fncHeading("== Entramox Reconciler - Runtime configuration ==")
    realm = ask_nonempty("Proxmox Realm name (must match PVE exactly)")
    shell = ask_nonempty("Default shell for new users", default="/bin/bash")
    domains = ask_domains()

    lines = [
        "# Autogenerated by Entramox Reconciler installer",
        "# Keep this file 0600, owner root",
        "",
        f"REALM={fncShQuote(realm)}",
        f"DEFAULT_SHELL={fncShQuote(shell)}",
        "GRANT_SUDO='false'",
        "SUDO_NOPASSWD='false'",
        f"ALLOWED_UPN_DOMAINS={fncShQuote(domains)}",
        "",
    ]

    if not fncPromptUseGraph():
        fncWarn("Graph enforcement disabled - relying on PVE realm only.")
        lines += [
            "GRAPH_ENFORCE='false'",
            "GRAPH_FAIL_OPEN='true'",
            "# GRAPH_ACCESS_TOKEN=''   # not used when GRAPH_ENFORCE=false",
            "# ENTR_TENANT_ID=''       # not used when GRAPH_ENFORCE=false",
            "# ENTR_CLNT_ID=''         # not used when GRAPH_ENFORCE=false",
            "# ENTR_CLNT_SEC=''        # not used when GRAPH_ENFORCE=false",
        ]
        return "\n".join(lines) + "\n"

    fncOk("Graph enforcement enabled.")
    lines.append("GRAPH_ENFORCE='true'")

    roles = fncGetPveRoles()

    print()
    fncHeading("== All Users (baseline) group ==")
    all_gid = ask_nonempty("All Users Entra group - Object ID (ENTRA_ALLUSERS_GROUP_ID)")
    lines.append(f"ENTRA_ALLUSERS_GROUP_ID={fncShQuote(all_gid)}")

    all_role = fncChooseFromList(
        "Select PVE role for All Users group",
        roles,
        allow_none=False,
        default="PVEUser" if "PVEUser" in roles else None
    )
    lines.append(f"ENTRA_ALLUSERS_PVE_ROLE={fncShQuote(all_role)}")

    fail_open = ask_bool("Fail OPEN if Graph is unavailable?", default=True)
    lines.append(f"GRAPH_FAIL_OPEN={fncShQuote('true' if fail_open else 'false')}")

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

    print()
    fncHeading("== Additional Entra Group → PVE Role mappings (optional) ==")
    role_maps = fncPromptRoleMappings()
    role_maps_json = json.dumps(role_maps, separators=(',', ':'))
    lines.append(f"ENTRA_ROLE_MAP={fncShQuote(role_maps_json)}")

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

        enc_key = fncLoadEncKey()
        if not enc_key:
            fncErr(f"Missing encryption key. Expected {KEYFILE} with {ENC_KEY_ENV}. Aborting to avoid writing plaintext.")
            sys.exit(1)

        try:
            enc = fncEncryptSecretFernet(secret, enc_key)
        except Exception as e:
            fncErr(f"Encryption failed ({e}). Aborting to avoid writing plaintext.")
            sys.exit(1)

        lines += [
            f"ENTR_TENANT_ID={fncShQuote(tenant)}",
            f"ENTR_CLNT_ID={fncShQuote(client)}",
            "ENTR_CLNT_SEC=''",
            f"ENTR_CLNT_SEC_ENC={fncShQuote(enc)}",
            "AUTH_MODE='application'",
        ]
        fncOk("Encrypted ENTR_CLNT_SEC and stored ENTR_CLNT_SEC_ENC in env.")

    # ── Tiered accounts ────────────────────────────────────────────────────────
    print()
    fncHeading("== Tiered Accounts (privilege separation) ==")
    fncInfo("Tiered accounts create a second privileged login for superadmin users.")
    fncInfo(f"Example: base account {fncColor('john', 'cyan')} (no sudo) + tiered account "
            f"{fncColor('a-john', 'cyan')} (with sudo).")
    fncInfo("This enforces least-privilege - daily work uses the regular account.")

    tiered = ask_bool("Enable tiered accounts for superadmin users?", default=False)
    if tiered:
        print()
        fncHeading("== Tiered Account: Prefix or Suffix? ==")
        print(f"{fncColor('[1]', 'white')} Prefix - e.g. {fncColor('a-john', 'cyan')} (prefix {fncColor('a-', 'yellow')})")
        print(f"{fncColor('[2]', 'white')} Suffix - e.g. {fncColor('john-adm', 'cyan')} (suffix {fncColor('-adm', 'yellow')})")
        while True:
            tier_mode_raw = input(
                f"{fncColor('?', 'cyan')} Choose {fncColor('[1/2]', 'white')} [{fncColor('1', 'green')}]: "
            ).strip() or "1"
            if tier_mode_raw in ("1", "2"):
                break
            fncWarn("Please enter 1 or 2.")
        tier_mode = "prefix" if tier_mode_raw == "1" else "suffix"

        mode_label = "prefix" if tier_mode == "prefix" else "suffix"
        default_val = "a-" if tier_mode == "prefix" else "-adm"
        tier_value = ask_nonempty(
            f"Enter the {mode_label} value (e.g. {fncColor(default_val, 'yellow')})",
            default=default_val,
        )

        print()
        fncHeading("== Tiered Account Scope ==")
        fncInfo("Choose whether the tiered account applies to Linux only, or also to Proxmox (PVE/PBS/PDM).")
        fncInfo(f"{fncColor('Linux only', 'cyan')}: tiered user gets sudo; Proxmox admin role is unchanged.")
        fncInfo(f"{fncColor('Linux + Proxmox', 'cyan')}: tiered user gets sudo AND Proxmox admin role.")
        print(f"{fncColor('[1]', 'white')} Linux only")
        print(f"{fncColor('[2]', 'white')} Linux and Proxmox")
        while True:
            scope_raw = input(
                f"{fncColor('?', 'cyan')} Choose {fncColor('[1/2]', 'white')} [{fncColor('1', 'green')}]: "
            ).strip() or "1"
            if scope_raw in ("1", "2"):
                break
            fncWarn("Please enter 1 or 2.")
        tier_scope = "linux" if scope_raw == "1" else "both"

        print()
        fncHeading("== Tiered Account: SSH Lockdown ==")
        fncInfo("Optionally block DIRECT SSH login for tiered accounts. Operators then")
        fncInfo(f"log in with their base account and escalate locally "
                f"({fncColor('su - <tiered>', 'cyan')}, then {fncColor('sudo -i', 'cyan')}).")
        fncInfo("A managed sshd_config.d drop-in is written and sshd is reloaded "
                "(validated first).")
        ssh_deny = ask_bool("Block direct SSH login for tiered accounts?", default=False)

        lines += [
            "",
            "# Tiered accounts",
            "TIERED_ACCOUNTS='true'",
            f"TIERED_ACCOUNT_MODE={fncShQuote(tier_mode)}",
            f"TIERED_ACCOUNT_VALUE={fncShQuote(tier_value)}",
            f"TIERED_ACCOUNT_SCOPE={fncShQuote(tier_scope)}",
            f"TIERED_SSH_DENY_DIRECT={fncShQuote('true' if ssh_deny else 'false')}",
        ]
        fncOk(f"Tiered accounts enabled: {tier_mode} '{tier_value}', scope={tier_scope}, "
              f"ssh_deny={'true' if ssh_deny else 'false'}")
    else:
        lines += [
            "",
            "# Tiered accounts (disabled)",
            "TIERED_ACCOUNTS='false'",
            "TIERED_ACCOUNT_MODE='prefix'",
            "TIERED_ACCOUNT_VALUE=''",
            "TIERED_ACCOUNT_SCOPE='linux'",
            "TIERED_SSH_DENY_DIRECT='false'",
        ]

    # ── Proxmox Backup Server (PBS) ───────────────────────────────────────────
    print()
    fncHeading("== Proxmox Backup Server (PBS) Integration ==")
    fncInfo("Optionally sync users into a PBS instance so they can log in to manage backups.")

    pbs = ask_bool("Enable PBS user synchronisation?", default=False)
    if pbs:
        pbs_host     = ask_nonempty("PBS hostname or IP (PBS_HOST)")
        pbs_port     = input(fncColor(f"PBS API port [{fncColor('8007', 'green')}]: ", "cyan", "bold")).strip() or "8007"
        pbs_realm    = input(fncColor("PBS realm for synced users (blank = use PVE realm): ", "cyan", "bold")).strip()
        pbs_api_user = ask_nonempty("PBS API user (e.g. root@pam)", default="root@pam")
        pbs_tok_name = ask_nonempty("PBS API token name")
        pbs_tok_val  = getpass(fncColor("PBS API token value [input hidden]: ", "cyan", "bold")).strip()

        # Encrypt token
        enc_key = fncLoadEncKey()
        if not enc_key:
            fncErr(f"Missing encryption key. Expected {KEYFILE} with {ENC_KEY_ENV}. Aborting to avoid writing PBS token as plaintext.")
            sys.exit(1)
        try:
            pbs_tok_enc = fncEncryptSecretFernet(pbs_tok_val, enc_key)
            fncOk("PBS API token encrypted.")
        except Exception as e:
            fncErr(f"Encryption failed ({e}). Aborting to avoid writing PBS token as plaintext.")
            sys.exit(1)

        pbs_verify = ask_bool("Verify TLS certificate for PBS?", default=True)
        pbs_default_role = input(fncColor("Default PBS role for all users [DatastoreReader]: ", "cyan", "bold")).strip() or "DatastoreReader"
        pbs_admin_role   = input(fncColor("PBS role for superadmins [DatastoreAdmin]: ", "cyan", "bold")).strip() or "DatastoreAdmin"

        lines += [
            "",
            "# Proxmox Backup Server",
            "PBS_ENABLED='true'",
            f"PBS_HOST={fncShQuote(pbs_host)}",
            f"PBS_PORT={fncShQuote(pbs_port)}",
            f"PBS_REALM={fncShQuote(pbs_realm)}",
            f"PBS_API_USER={fncShQuote(pbs_api_user)}",
            f"PBS_TOKEN_NAME={fncShQuote(pbs_tok_name)}",
            f"PBS_TOKEN_VALUE_ENC={fncShQuote(pbs_tok_enc)}",
            f"PBS_VERIFY_TLS={fncShQuote('true' if pbs_verify else 'false')}",
            f"PBS_DEFAULT_ROLE={fncShQuote(pbs_default_role)}",
            f"PBS_ADMIN_ROLE={fncShQuote(pbs_admin_role)}",
        ]
        fncOk(f"PBS integration enabled: {pbs_api_user}@{pbs_host}:{pbs_port}")
    else:
        lines += [
            "",
            "# Proxmox Backup Server (disabled)",
            "PBS_ENABLED='false'",
        ]

    # ── Proxmox Datacenter Manager (PDM) ─────────────────────────────────────
    print()
    fncHeading("== Proxmox Datacenter Manager (PDM) Integration ==")
    fncInfo("Optionally sync users into a PDM instance for centralised datacenter management access.")

    pdm = ask_bool("Enable PDM user synchronisation?", default=False)
    if pdm:
        pdm_host     = ask_nonempty("PDM hostname or IP (PDM_HOST)")
        pdm_port     = input(fncColor(f"PDM API port [{fncColor('8443', 'green')}]: ", "cyan", "bold")).strip() or "8443"
        pdm_realm    = input(fncColor("PDM realm for synced users (blank = use PVE realm): ", "cyan", "bold")).strip()
        pdm_api_user = ask_nonempty("PDM API user (e.g. root@pam)", default="root@pam")
        pdm_tok_name = ask_nonempty("PDM API token name")
        pdm_tok_val  = getpass(fncColor("PDM API token value [input hidden]: ", "cyan", "bold")).strip()

        enc_key = fncLoadEncKey()
        if not enc_key:
            fncErr(f"Missing encryption key. Expected {KEYFILE} with {ENC_KEY_ENV}. Aborting to avoid writing PDM token as plaintext.")
            sys.exit(1)
        try:
            pdm_tok_enc = fncEncryptSecretFernet(pdm_tok_val, enc_key)
            fncOk("PDM API token encrypted.")
        except Exception as e:
            fncErr(f"Encryption failed ({e}). Aborting to avoid writing PDM token as plaintext.")
            sys.exit(1)

        pdm_verify = ask_bool("Verify TLS certificate for PDM?", default=True)
        pdm_default_role = input(fncColor("Default PDM role for all users [DCOperator]: ", "cyan", "bold")).strip() or "DCOperator"
        pdm_admin_role   = input(fncColor("PDM role for superadmins [DCAdmin]: ", "cyan", "bold")).strip() or "DCAdmin"

        lines += [
            "",
            "# Proxmox Datacenter Manager",
            "PDM_ENABLED='true'",
            f"PDM_HOST={fncShQuote(pdm_host)}",
            f"PDM_PORT={fncShQuote(pdm_port)}",
            f"PDM_REALM={fncShQuote(pdm_realm)}",
            f"PDM_API_USER={fncShQuote(pdm_api_user)}",
            f"PDM_TOKEN_NAME={fncShQuote(pdm_tok_name)}",
            f"PDM_TOKEN_VALUE_ENC={fncShQuote(pdm_tok_enc)}",
            f"PDM_VERIFY_TLS={fncShQuote('true' if pdm_verify else 'false')}",
            f"PDM_DEFAULT_ROLE={fncShQuote(pdm_default_role)}",
            f"PDM_ADMIN_ROLE={fncShQuote(pdm_admin_role)}",
        ]
        fncOk(f"PDM integration enabled: {pdm_api_user}@{pdm_host}:{pdm_port}")
    else:
        lines += [
            "",
            "# Proxmox Datacenter Manager (disabled)",
            "PDM_ENABLED='false'",
        ]

    # ── Multi-host fan-out ────────────────────────────────────────────────────
    print()
    fncHeading("== Multi-host fan-out (replicate Linux accounts to other machines) ==")
    fncInfo("By default every machine runs the reconciler independently.")
    fncInfo("Alternatively, THIS host can push the same Linux user / sudo / tiered")
    fncInfo("accounts to other machines over SSH whenever it syncs.")
    fncWarn("Requires the SSH port (default 22) open from THIS host to each node,")
    fncWarn("and the generated public key installed on each node (shown below).")
    fanout = ask_bool("Fan out account changes to other machines over SSH?", default=False)
    fanout_nodes: list[str] = []
    fanout_user = "root"
    if fanout:
        raw_nodes = ask_nonempty("Target nodes - hostnames/IPs (space/comma-separated)")
        fanout_nodes = [n for n in re.split(r"[,\s]+", raw_nodes) if n]
        fanout_user = ask_nonempty("SSH user on the nodes (needs root or sudo to manage users)", default="root")
        fanout_port = input(fncColor(f"SSH port to the nodes [{fncColor('22', 'green')}]: ", "cyan", "bold")).strip() or "22"
        lines += [
            "",
            "# Multi-host fan-out",
            "FANOUT_ENABLED='true'",
            f"FANOUT_NODES={fncShQuote(' '.join(fanout_nodes))}",
            f"FANOUT_SSH_USER={fncShQuote(fanout_user)}",
            f"FANOUT_SSH_PORT={fncShQuote(fanout_port)}",
        ]
        fncOk(f"Fan-out enabled to {len(fanout_nodes)} node(s): {', '.join(fanout_nodes)}")
    else:
        lines += [
            "",
            "# Multi-host fan-out (disabled - each host runs independently)",
            "FANOUT_ENABLED='false'",
        ]

    # ── SSH access key ────────────────────────────────────────────────────────
    # Generated when any remote host needs it: PBS/PDM (handoff) or fan-out nodes
    # (the reconciler uses the key to push account changes). The reconciler reads
    # SSH_KEY_PATH + SSH_KEY_PASSPHRASE_ENC emitted by fncProvisionSshKey.
    ssh_targets: list[tuple[str, str, str]] = []
    if pbs:
        ssh_targets.append(("PBS", pbs_host, "root"))
    if pdm:
        ssh_targets.append(("PDM", pdm_host, "root"))
    if fanout:
        for n in fanout_nodes:
            ssh_targets.append(("Fan-out node", n, fanout_user))
    if ssh_targets:
        lines += fncProvisionSshKey(ssh_targets)
    elif fanout:
        fncErr("Fan-out enabled but no nodes/SSH key were provisioned; fan-out will be inactive.")

    return "\n".join(lines) + "\n"

# ============================
# Writers
# ============================

def fncSplitEnvfileIntoServices(content: str) -> tuple[str, str, str, str, str]:
    """Split env file content into (main, graph, pbs, pdm, ssh) strings.

    Secret vars (token values, client secrets, the SSH key passphrase) are moved
    into their own per-service files.  The main file retains all non-secret
    config so a read of it alone reveals no usable credentials.

    Returns five strings: (main, graph_content, pbs_content, pdm_content, ssh_content).
    """
    main_lines: list[str] = []
    graph_lines: list[str] = ["# Entramox Reconciler - Graph credentials (mode 0600)"]
    pbs_lines:   list[str] = ["# Entramox Reconciler - PBS credentials (mode 0600)"]
    pdm_lines:   list[str] = ["# Entramox Reconciler - PDM credentials (mode 0600)"]
    ssh_lines:   list[str] = ["# Entramox Reconciler - SSH key passphrase (mode 0600)"]

    # Track which service files got at least one real assignment
    graph_has_vars = pbs_has_vars = pdm_has_vars = ssh_has_vars = False

    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        # Match KEY=value assignment (handles quoted and unquoted values)
        m = ENV_ASSIGN_RE.match(stripped)
        if m:
            key = m.group(1)
            if key in _GRAPH_SECRET_VARS:
                graph_lines.append(raw_line)
                graph_has_vars = True
                # Leave a comment placeholder in the main file
                main_lines.append(f"# {key} - moved to {GRAPH_ENVFILE}")
                continue
            if key in _PBS_SECRET_VARS:
                pbs_lines.append(raw_line)
                pbs_has_vars = True
                main_lines.append(f"# {key} - moved to {PBS_ENVFILE}")
                continue
            if key in _PDM_SECRET_VARS:
                pdm_lines.append(raw_line)
                pdm_has_vars = True
                main_lines.append(f"# {key} - moved to {PDM_ENVFILE}")
                continue
            if key in _SSH_SECRET_VARS:
                ssh_lines.append(raw_line)
                ssh_has_vars = True
                main_lines.append(f"# {key} - moved to {SSH_ENVFILE}")
                continue
        main_lines.append(raw_line)

    graph_content = "\n".join(graph_lines) + "\n" if graph_has_vars else ""
    pbs_content   = "\n".join(pbs_lines)   + "\n" if pbs_has_vars  else ""
    pdm_content   = "\n".join(pdm_lines)   + "\n" if pdm_has_vars  else ""
    ssh_content   = "\n".join(ssh_lines)   + "\n" if ssh_has_vars  else ""
    return "\n".join(main_lines) + "\n", graph_content, pbs_content, pdm_content, ssh_content


def _ensure_conf_dir():
    """Ensure /etc/entramoxreconciler/ exists with mode 0700."""
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONF_DIR, 0o700)


def _write_secret_file(path: Path, content: str, label: str):
    """Write a per-service secret file with mode 0600.

    The content always begins with a header comment, so we must look for at
    least one real (non-comment, non-blank) assignment line to decide whether
    there's anything worth writing -- checking only the first character would
    always see the '#' header and skip the file.
    """
    has_assignment = any(
        line.strip() and not line.strip().startswith("#")
        for line in content.splitlines()
    )
    if has_assignment:
        path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
        fncOk(f"Wrote {label} to " + fncColor(str(path), "white", "bold") + " (mode 0600)")
    else:
        # Nothing to write (service not configured); remove stale file if present
        if path.exists():
            path.unlink()
            fncInfo(f"Removed stale {label} file: {path}")


def fncWriteEnvfile(content: str):
    """Write the main env file and split secrets into per-service files."""
    _ensure_conf_dir()
    main_content, graph_content, pbs_content, pdm_content, ssh_content = fncSplitEnvfileIntoServices(content)

    # Write main config (no secrets)
    if ENVFILE.exists():
        fncInfo(f"Updating {ENVFILE}")
    else:
        fncOk(f"Creating {ENVFILE}")
    ENVFILE.write_text(main_content, encoding="utf-8")
    os.chmod(ENVFILE, 0o600)
    fncOk("Wrote main config to " + fncColor(str(ENVFILE), "white", "bold") + " (mode 0600)")

    # Write per-service credential files
    _write_secret_file(GRAPH_ENVFILE, graph_content, "Graph credentials")
    _write_secret_file(PBS_ENVFILE,   pbs_content,   "PBS credentials")
    _write_secret_file(PDM_ENVFILE,   pdm_content,   "PDM credentials")
    _write_secret_file(SSH_ENVFILE,   ssh_content,   "SSH key passphrase")

    fncInfo(
        "Secrets split into separate files: "
        + fncColor(str(GRAPH_ENVFILE), "white") + ", "
        + fncColor(str(PBS_ENVFILE),   "white") + ", "
        + fncColor(str(PDM_ENVFILE),   "white") + ", "
        + fncColor(str(SSH_ENVFILE),   "white")
    )

def fncWriteChecker(expected_sha: str):
    """Write the integrity checker script and the separate baseline hash file.

    Security rationale for the separate baseline file:
      Previously the expected hashes were embedded directly in the checker script.
      This meant an attacker who swapped the reconciler binary could also rewrite
      the checker with matching expected hashes in the same operation.

      By storing the baseline in a separate file (mode 0400, never rewritten by
      the running service) an attacker must compromise two independent files to
      defeat the check.  The checker reads its expected values from the baseline
      at runtime rather than from hardcoded strings.
    """
    try:
        expected_env_sha = fncSha256Sum(ENVFILE) if ENVFILE.exists() else ""
    except Exception:
        expected_env_sha = ""
    try:
        expected_key_sha = fncSha256Sum(KEYFILE) if KEYFILE.exists() else ""
    except Exception:
        expected_key_sha = ""

    # Compute hashes for per-service credential files (may not exist yet)
    try:
        expected_graph_sha = fncSha256Sum(GRAPH_ENVFILE) if GRAPH_ENVFILE.exists() else ""
    except Exception:
        expected_graph_sha = ""
    try:
        expected_pbs_sha = fncSha256Sum(PBS_ENVFILE) if PBS_ENVFILE.exists() else ""
    except Exception:
        expected_pbs_sha = ""
    try:
        expected_pdm_sha = fncSha256Sum(PDM_ENVFILE) if PDM_ENVFILE.exists() else ""
    except Exception:
        expected_pdm_sha = ""
    try:
        expected_ssh_sha = fncSha256Sum(SSH_ENVFILE) if SSH_ENVFILE.exists() else ""
    except Exception:
        expected_ssh_sha = ""

    # Write baseline file (separate from checker script)
    _ensure_conf_dir()
    baseline_content = (
        f"script={expected_sha}\n"
        f"env={expected_env_sha}\n"
        f"key={expected_key_sha}\n"
        f"graph_env={expected_graph_sha}\n"
        f"pbs_env={expected_pbs_sha}\n"
        f"pdm_env={expected_pdm_sha}\n"
        f"ssh_env={expected_ssh_sha}\n"
    )
    BASELINE.write_text(baseline_content, encoding="utf-8")
    os.chmod(BASELINE, 0o400)  # read-only by root; never rewritten by service
    fncOk(f"Wrote baseline hash file: {BASELINE} (mode 0400)")

    checker_script = f"""#!/bin/bash
set -euo pipefail

SCRIPT="{SCRIPT_DST}"
ENVFILE="{ENVFILE}"
KEYFILE="{KEYFILE}"
GRAPH_ENVFILE="{GRAPH_ENVFILE}"
PBS_ENVFILE="{PBS_ENVFILE}"
PDM_ENVFILE="{PDM_ENVFILE}"
SSH_ENVFILE="{SSH_ENVFILE}"
BASELINE="{BASELINE}"
LOGFILE="{LOGDIR}/thelog.log"

# Write a timestamped line to the shared application log file so that the
# reconciler's own log (and any SIEM monitoring it) captures integrity events.
log_to_file() {{
    local level="$1"
    local msg="$2"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$ts $level [entramox_check] $msg" >> "$LOGFILE" 2>/dev/null || true
}}

log_warn() {{
    log_to_file "WARNING " "$1"
    logger -t entramox_check "$1" || true
    echo "$1" >&2
}}

fail() {{
    log_to_file "CRITICAL" "$1"
    logger -t entramox_check "$1" || true
    echo "$1" >&2
    exit 1
}}

# ── Baseline file checks ──────────────────────────────────────────────────
# Read expected hashes from the separate baseline file (not from this script).
# This means an attacker must tamper with TWO files to defeat the check.
if [[ ! -e "$BASELINE" ]]; then
    fail "Integrity: baseline file missing path=$BASELINE"
fi
if [[ -L "$BASELINE" ]]; then
    fail "Integrity: baseline is a symlink path=$BASELINE"
fi

read_baseline() {{
    local key="$1"
    grep -E "^${{key}}=" "$BASELINE" 2>/dev/null | head -1 | cut -d= -f2-
}}

EXPECTED_SHA=$(read_baseline "script")
EXPECTED_ENV_SHA=$(read_baseline "env")
EXPECTED_KEY_SHA=$(read_baseline "key")

if [[ -z "$EXPECTED_SHA" ]]; then
    fail "Integrity: baseline missing 'script' entry path=$BASELINE"
fi

check_secure_file() {{
    local p="$1"
    if [[ ! -e "$p" ]]; then
        log_warn "Integrity: missing file path=$p"
        return 0
    fi
    if [[ -L "$p" ]]; then
        fail "Integrity: symlink refused path=$p"
    fi
    local uid
    uid=$(stat -Lc %u "$p" 2>/dev/null || echo 99999)
    if [[ "$uid" != "0" ]]; then
        fail "Integrity: file not owned by root path=$p uid=$uid"
    fi
    local mode
    mode=$(stat -Lc %a "$p" 2>/dev/null || echo 777)
    mode=${{mode: -3}}
    if (( 10#"$mode" > 600 )); then
        fail "Integrity: permissions too broad path=$p mode=$mode want=600"
    fi
}}

sha256_file() {{
    /usr/bin/sha256sum "$1" | awk '{{print $1}}'
}}

ACTUAL_SHA=$(sha256_file "$SCRIPT")
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
    fail "Integrity: script checksum mismatch file=$SCRIPT have=$ACTUAL_SHA expect=$EXPECTED_SHA"
fi

check_secure_file "$ENVFILE"
if [[ -e "$ENVFILE" && -n "$EXPECTED_ENV_SHA" ]]; then
    ACTUAL_ENV_SHA=$(sha256_file "$ENVFILE")
    if [[ "$ACTUAL_ENV_SHA" != "$EXPECTED_ENV_SHA" ]]; then
        log_warn "Integrity: env checksum changed path=$ENVFILE have=$ACTUAL_ENV_SHA expect=$EXPECTED_ENV_SHA"
    fi
fi

check_secure_file "$KEYFILE"
if [[ -e "$KEYFILE" && -n "$EXPECTED_KEY_SHA" ]]; then
    ACTUAL_KEY_SHA=$(sha256_file "$KEYFILE")
    if [[ "$ACTUAL_KEY_SHA" != "$EXPECTED_KEY_SHA" ]]; then
        log_warn "Integrity: key checksum changed path=$KEYFILE have=$ACTUAL_KEY_SHA expect=$EXPECTED_KEY_SHA"
    fi
fi

# ── Per-service credential file checks ───────────────────────────────────
# A credential file is only expected when its baseline hash is non-empty (the
# service was configured at install time). Services left disabled have an empty
# baseline entry, so we skip them silently instead of crying "missing file".
EXPECTED_GRAPH_SHA=$(read_baseline "graph_env")
EXPECTED_PBS_SHA=$(read_baseline "pbs_env")
EXPECTED_PDM_SHA=$(read_baseline "pdm_env")
EXPECTED_SSH_SHA=$(read_baseline "ssh_env")

check_cred_file() {{
    local p="$1"
    local expected="$2"
    # Not configured at install (no baseline hash) -> nothing to verify.
    if [[ -z "$expected" ]]; then
        return 0
    fi
    check_secure_file "$p"   # warns if missing; fails on symlink/owner/mode
    if [[ -e "$p" ]]; then
        local actual
        actual=$(sha256_file "$p")
        if [[ "$actual" != "$expected" ]]; then
            log_warn "Integrity: env checksum changed path=$p have=$actual expect=$expected"
        fi
    fi
}}

check_cred_file "$GRAPH_ENVFILE" "$EXPECTED_GRAPH_SHA"
check_cred_file "$PBS_ENVFILE"   "$EXPECTED_PBS_SHA"
check_cred_file "$PDM_ENVFILE"   "$EXPECTED_PDM_SHA"
check_cred_file "$SSH_ENVFILE"   "$EXPECTED_SSH_SHA"

exit 0
"""
    CHECKER.write_text(checker_script)
    os.chmod(CHECKER, 0o700)
    fncOk(f"Created/updated checker script at {CHECKER}")

def fncWriteUnits():
    service_unit = f"""[Unit]
Description=Entramox Reconciler - Proxmox OIDC to Linux user sync
After=network-online.target pve-cluster.service
Wants=network-online.target

[Service]
Type=oneshot
# Main config (no secrets)
EnvironmentFile=-{ENVFILE}
# Encryption key (Fernet)
EnvironmentFile=-{KEYFILE}
# Per-service credential files (secrets isolated by service)
EnvironmentFile=-{GRAPH_ENVFILE}
EnvironmentFile=-{PBS_ENVFILE}
EnvironmentFile=-{PDM_ENVFILE}
EnvironmentFile=-{SSH_ENVFILE}
ExecCondition={CHECKER}
ExecStart=/usr/bin/python3 {SCRIPT_DST}
User=root
"""
    SERVICE.write_text(service_unit)
    fncOk(f"Wrote service unit: {SERVICE}")

    timer_unit = f"""[Unit]
Description=Run Entramox Reconciler every 30 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=30min
Unit={SERVICE.name}
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
"""
    TIMER.write_text(timer_unit)
    fncOk(f"Wrote timer unit: {TIMER}")

# ============================
# Actions
# ============================
def fncDoUninstall(purge: bool = False):
    fncRequireRoot()
    fncHeading("[*] Uninstalling Entramox Reconciler...")

    # Stop & disable units (ignore failures)
    for unit in (TIMER.name, SERVICE.name):
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

    # Remove logrotate snippet
    LOGROTATE = Path("/etc/logrotate.d/entramoxreconciler")
    try:
        if LOGROTATE.exists():
            LOGROTATE.unlink()
            fncOk(f"Removed {LOGROTATE}")
    except Exception as e:
        fncWarn(f"Could not remove {LOGROTATE}: {e}")

    # Optional removals
    targets = [
        ("env file",      ENVFILE),
        ("key file",      KEYFILE),
        ("conf dir",      CONF_DIR),
        ("log dir",       LOGDIR),
        ("state dir",     Path("/var/lib/entramoxreconciler")),
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
            + fncColor(f"systemctl daemon-reload && systemctl enable --now {TIMER.name}", "white", "bold"))

def fncDoInstall():
    fncRequireRoot()
    fncHeading("[*] Installing Entramox Reconciler...")

    fncInstallRequirements()
    fncEnsureKeyfile()  # generate key first

    shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
    os.chmod(SCRIPT_DST, 0o700)
    fncOk(f"Installed script to {SCRIPT_DST}")

    expected_sha = fncSha256Sum(SCRIPT_DST)
    fncInfo(f"Calculated SHA256: {fncColor(expected_sha, 'white', 'bold')}")

    LOGDIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    fncOk(f"Ensured log directory {LOGDIR}")

    env_content = fncBuildEnvfileContent()
    fncWriteEnvfile(env_content)

    # Baseline AFTER env files exist, so their hashes are captured and actually
    # verified at runtime (otherwise the baseline records empty env hashes).
    fncWriteChecker(expected_sha)

    fncWriteUnits()

    fncRun(["systemctl", "daemon-reload"])
    fncOk("systemd daemon reloaded")
    fncRun(["systemctl", "enable", "--now", TIMER.name])
    fncOk(f"Enabled and started timer: {TIMER.name}")

    fncOk("Installation complete.")
    fncInfo("Check logs: " + fncColor(f"journalctl -u {SERVICE.name} -n 200 --no-pager", "white", "bold"))
    fncInfo("Edit config: " + fncColor(str(ENVFILE), "white", "bold")
            + " then: " + fncColor(f"systemctl daemon-reload && systemctl restart {SERVICE.name}", "white", "bold"))

def fncDoUpdate(auto_restart: bool = False):
    fncRequireRoot()
    fncHeading("[*] Updating Entramox Reconciler...")

    if not SCRIPT_DST.exists():
        fncErr("Installed script not found (new or adopted). Did you run install first?")
        sys.exit(1)
    if not SCRIPT_SRC.exists():
        fncErr(f"Local source not found: {SCRIPT_SRC}")
        sys.exit(1)
    if not CHECKER.exists():
        fncWarn("Checker not found; it will be regenerated during update.")
        # not fatal

    fncEnsureKeyfile()

    local_sha = fncSha256Sum(SCRIPT_SRC)
    installed_sha = fncSha256Sum(SCRIPT_DST)

    fncInfo(f"Local SHA     : {fncColor(local_sha, 'white', 'bold')}")
    fncInfo(f"Installed SHA : {fncColor(installed_sha, 'white', 'bold')}")

    def ask_yes_no(prompt: str, default_yes: bool = False) -> bool:
        hint = "Y/n" if default_yes else "y/N"
        while True:
            ans = input(f"{fncColor(prompt, 'cyan', 'bold')} {fncColor(f'[{hint}]', 'gray')}: ").strip().lower()
            if not ans:
                return default_yes
            if ans in ("y", "yes"): return True
            if ans in ("n", "no"):  return False
            fncWarn("Please answer y or n.")

    # Env handling (new envfile)
    if ENVFILE.exists():
        if ask_yes_no(f"Re-run config wizard and overwrite {ENVFILE}?", default_yes=False):
            backup = fncEnvBackupPath(ENVFILE)
            try:
                shutil.copy2(ENVFILE, backup)
                fncInfo(f"Backed up existing env to {fncColor(str(backup), 'white', 'bold')}")
            except Exception as e:
                fncWarn(f"Could not backup env file ({e}); proceeding anyway.")
            content = fncBuildEnvfileContent()
            fncWriteEnvfile(content)
        else:
            fncInfo("Keeping existing env file.")
            fncEncryptIfNeededInEnv(ENVFILE)
    else:
        if ask_yes_no(f"{ENVFILE} not found. Create it now?", default_yes=True):
            content = fncBuildEnvfileContent()
            fncWriteEnvfile(content)
        else:
            fncWarn("Skipping env creation; service may not have credentials/config.")

    # Update script if needed
    if local_sha == installed_sha:
        fncWarn("Current installed version already matches local - no update needed.")
    else:
        fncInfo("Updating installed script...")
        shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
        os.chmod(SCRIPT_DST, 0o700)

        new_installed_sha = fncSha256Sum(SCRIPT_DST)
        if new_installed_sha != local_sha:
            fncErr("Post-copy SHA mismatch! Aborting.")
            sys.exit(1)
        fncOk("Script updated.")

    # Always refresh the baseline so it matches the final on-disk state (script
    # AND env files). Doing this unconditionally avoids stale-baseline
    # "checksum changed" warnings when only the config was re-run.
    fncWriteChecker(fncSha256Sum(SCRIPT_DST))

    # Re-write units (ensures timer points at the right service name)
    fncWriteUnits()

    # Reload daemon to pick up any unit changes
    fncRun(["systemctl", "daemon-reload"])
    fncOk("systemd daemon reloaded")

    # Ensure timer is enabled
    try:
        fncRun(["systemctl", "enable", "--now", TIMER.name])
        fncOk(f"Ensured timer enabled: {TIMER.name}")
    except subprocess.CalledProcessError:
        fncWarn(f"Could not enable/start timer {TIMER.name} (check systemd output).")

    if auto_restart:
        fncRun(["systemctl", "restart", SERVICE.name])
        fncOk("Service restarted.")
    else:
        fncInfo("Restart the service with: "
                + fncColor(f"sudo systemctl restart {SERVICE.name}", "white", "bold"))

# ============================
# Entry point
# ============================
def fncMain():
    parser = argparse.ArgumentParser(description="Installer/Updater for Entramox Reconciler")
    parser.add_argument("action", choices=["install", "update", "uninstall"], help="Action to perform")
    parser.add_argument("--restart", action="store_true", help="Auto-restart service after update")
    parser.add_argument("--purge", action="store_true", help="Remove env, logs, and state without prompts (DANGEROUS)")
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
