#!/usr/bin/env python3
import os
import shutil
import hashlib
import subprocess
import argparse
from pathlib import Path
from getpass import getpass

# Paths (all relative to current dir = project root)
ROOT_DIR = Path(__file__).resolve().parent
SCRIPT_SRC = ROOT_DIR / "sudomatic5000.py"
REQS = ROOT_DIR / "requirements.txt"

# System paths
SCRIPT_DST = Path("/usr/local/sbin/sudomatic5000.py")
CHECKER = Path("/usr/local/sbin/sudomatic_check.sh")
SERVICE = Path("/etc/systemd/system/sudomatic.service")
TIMER = Path("/etc/systemd/system/sudomatic.timer")
LOGDIR = Path("/var/log/sudomatic5000")
ENVFILE = Path("/etc/sudomatic5000.env")

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

def sh_quote(val: str) -> str:
    """Safe-ish single-quoted value for env files."""
    if val is None:
        val = ""
    return "'" + val.replace("'", "'\"'\"'") + "'"

def prompt_use_graph() -> bool:
    print("\n== Sudomatic 5000 — Membership Source ==")
    print("[1] Use Microsoft Graph (enforce members from an Entra group)")
    print("[2] Rely on PVE realm accounts only (no Graph enforcement)")
    while True:
        choice = input("Choose 1 or 2 [2]: ").strip() or "2"
        if choice in ("1", "2"):
            return choice == "1"
        print("Please enter 1 or 2.")

def prompt_auth_mode() -> str:
    print("\n== Microsoft Graph authentication mode ==")
    print("[1] Access Token (GRAPH_ACCESS_TOKEN)  — quick testing; short-lived")
    print("[2] Application Tokens (Client Credentials) — ENTR_TENANT_ID / ENTR_CLNT_ID / ENTR_CLNT_SEC")
    while True:
        choice = input("Choose 1 or 2 [2]: ").strip() or "2"
        if choice in ("1", "2"):
            return "access" if choice == "1" else "application"
        print("Please enter 1 or 2.")

def do_uninstall(purge: bool = False):
    require_root()
    print("[*] Uninstalling Sudomatic 5000...")

    # Stop & disable units (ignore failures if not present)
    for unit in ("sudomatic.timer", "sudomatic.service"):
        try:
            run(["systemctl", "stop", unit])
        except subprocess.CalledProcessError:
            pass
        try:
            run(["systemctl", "disable", unit])
        except subprocess.CalledProcessError:
            pass

    # Remove unit files
    for p in (TIMER, SERVICE):
        try:
            if p.exists():
                p.unlink()
                print(f"[+] Removed {p}")
        except Exception as e:
            print(f"[!] Could not remove {p}: {e}")

    # Reload systemd after unit removals
    try:
        run(["systemctl", "daemon-reload"])
    except subprocess.CalledProcessError:
        pass

    # Remove installed script & checker
    for p in (SCRIPT_DST, CHECKER):
        try:
            if p.exists():
                p.unlink()
                print(f"[+] Removed {p}")
        except Exception as e:
            print(f"[!] Could not remove {p}: {e}")

    # Remove logrotate snippet if present
    LOGROTATE = Path("/etc/logrotate.d/sudomatic5000")
    try:
        if LOGROTATE.exists():
            LOGROTATE.unlink()
            print(f"[+] Removed {LOGROTATE}")
    except Exception as e:
        print(f"[!] Could not remove {LOGROTATE}: {e}")

    # Optional removals
    state_root = Path("/var/lib/sudomatic5000")  # parent of pve_oidc_sync
    targets = [
        ("env file", ENVFILE),
        ("log dir", LOGDIR),
        ("state dir", state_root),
    ]

    def ask(q: str) -> bool:
        a = input(q + " [y/N]: ").strip().lower()
        return a in ("y", "yes")

    if purge:
        for label, path in targets:
            try:
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                print(f"[+] Purged {label}: {path}")
            except Exception as e:
                print(f"[!] Failed to purge {label} {path}: {e}")
    else:
        for label, path in targets:
            try:
                if path.exists() and ask(f"Remove {label} {path}?"):
                    if path.is_file():
                        path.unlink()
                    else:
                        shutil.rmtree(path, ignore_errors=True)
                    print(f"[+] Removed {label}: {path}")
            except Exception as e:
                print(f"[!] Failed to remove {label} {path}: {e}")

    print("[+] Uninstall complete.")
    print("[i] If you re-install later, re-run: systemctl daemon-reload && systemctl enable --now sudomatic.timer")


def build_envfile_content() -> str:
    """
    Build /etc/sudomatic5000.env content:
    - Runtime: REALM, DEFAULT_SHELL, GRANT_SUDO, SUDO_NOPASSWD, ALLOWED_UPN_DOMAINS
    - Membership source: Graph vs PVE-only (and Graph auth details)
    """
    import re
    from getpass import getpass

    # ---- tiny inline helpers (keep installer.py tidy) ----
    def ask_bool(q: str, default: bool = True) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            a = input(f"{q} [{hint}]: ").strip().lower()
            if not a:
                return default
            if a in ("y", "yes"):
                return True
            if a in ("n", "no"):
                return False
            print("Please answer y or n.")

    def ask_nonempty(q: str, default: str | None = None) -> str:
        while True:
            prompt = f"{q}{f' [{default}]' if default else ''}: "
            a = input(prompt).strip()
            if a:
                return a
            if default is not None:
                return default
            print("Value cannot be empty.")

    def ask_domains() -> str:
        """
        Ask for allowed UPN domains; returns a single space-separated string.
        Empty input means 'allow all'.
        """
        raw = input("Allowed UPN domains (space/comma-separated, empty = allow all): ").strip()
        if not raw:
            return ""
        parts = [p.strip().lower() for p in re.split(r"[,\s]+", raw) if p.strip()]
        return " ".join(sorted(set(parts)))

    # ---- runtime basics ----
    print("\n== Sudomatic 5000 — Runtime configuration ==")
    realm = ask_nonempty("Proxmox Realm name (must match PVE exactly)")
    shell = ask_nonempty("Default shell for new users", default="/bin/bash")
    grant_sudo = ask_bool("Automatically grant sudo to new users?", default=True)
    sudo_nopasswd = False
    if grant_sudo:
        sudo_nopasswd = ask_bool("Use NOPASSWD for sudo?", default=False)
    domains = ask_domains()  # "" => no filtering

    lines = [
        "# Autogenerated by Sudomatic installer",
        "# Keep this file 0600, owner root",
        "",
        f"REALM={sh_quote(realm)}",
        f"DEFAULT_SHELL={sh_quote(shell)}",
        f"GRANT_SUDO={'true' if grant_sudo else 'false'}",
        f"SUDO_NOPASSWD={'true' if sudo_nopasswd else 'false'}",
        f"ALLOWED_UPN_DOMAINS={sh_quote(domains)}",  # space-separated list or empty
        "",
    ]

    # ---- membership source ----
    use_graph = prompt_use_graph()
    if not use_graph:
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

    # ---- Graph enforcement path ----
    lines.append("GRAPH_ENFORCE='true'")

    group_id = ask_nonempty("\nGraph Group ID (ENTR_SUPERUSR_ID)")
    lines.append(f"ENTR_SUPERUSR_ID={sh_quote(group_id)}")

    fail_open = ask_bool("Fail OPEN if Graph is unavailable?", default=True)
    lines.append(f"GRAPH_FAIL_OPEN={sh_quote('true' if fail_open else 'false')}")

    mode = prompt_auth_mode()
    if mode == "access":
        print("\nYou chose Access Token mode.")
        print("Note: Delegated tokens are short-lived (~1 hour). Good for testing; less ideal for timers.")
        token = getpass("Paste GRAPH_ACCESS_TOKEN (input hidden, can be empty): ").strip()
        lines.append(f"GRAPH_ACCESS_TOKEN={sh_quote(token)}")
        lines.append("AUTH_MODE='access'")
    else:
        print("\nYou chose Application Tokens (client credentials).")
        tenant = ask_nonempty("ENTR_TENANT_ID (Tenant ID GUID)")
        client = ask_nonempty("ENTR_CLNT_ID (App / Client ID GUID)")
        secret = getpass("ENTR_CLNT_SEC (Client Secret) [input hidden]: ").strip()
        lines += [
            f"ENTR_TENANT_ID={sh_quote(tenant)}",
            f"ENTR_CLNT_ID={sh_quote(client)}",
            f"ENTR_CLNT_SEC={sh_quote(secret)}",
            "AUTH_MODE='application'",
        ]

    return "\n".join(lines) + "\n"

def write_envfile(content: str):
    if ENVFILE.exists():
        print(f"[i] Updating {ENVFILE}")
    else:
        print(f"[+] Creating {ENVFILE}")
    ENVFILE.write_text(content)
    os.chmod(ENVFILE, 0o600)
    print("[+] Wrote secrets/config to /etc/sudomatic5000.env (mode 0600)")

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
    print(f"[+] Created/updated checker script at {CHECKER}")

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

def do_install():
    require_root()
    print("[*] Installing Sudomatic 5000...")

    install_requirements()

    # Install Python script
    shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
    os.chmod(SCRIPT_DST, 0o700)
    print(f"[+] Installed script to {SCRIPT_DST}")

    # Calculate SHA256 and write checker
    expected_sha = sha256sum(SCRIPT_DST)
    print(f"[+] Calculated SHA256: {expected_sha}")
    write_checker(expected_sha)

    # Log directory
    LOGDIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    print(f"[+] Ensured log directory {LOGDIR}")

    # Build env file (Graph vs PVE-only)
    env_content = build_envfile_content()
    write_envfile(env_content)

    # Units
    write_units()

    # Enable timer
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "sudomatic.timer"])

    print("[+] Installation complete.")
    print("[i] Check logs: journalctl -u sudomatic.service -n 200 --no-pager")
    print("[i] Edit config: /etc/sudomatic5000.env  (then: sudo systemctl daemon-reload && sudo systemctl restart sudomatic.service)")

def do_update(auto_restart=False):
    require_root()

    if not SCRIPT_DST.exists():
        print("[-] Installed script not found, did you run install first?")
        exit(1)
    if not SCRIPT_SRC.exists():
        print(f"[-] Local source not found: {SCRIPT_SRC}")
        exit(1)
    if not CHECKER.exists():
        print("[-] Checker not found, did you run install first?")
        exit(1)

    local_sha = sha256sum(SCRIPT_SRC)
    installed_sha = sha256sum(SCRIPT_DST)

    print(f"[*] Local SHA      : {local_sha}")
    print(f"[*] Installed SHA  : {installed_sha}")

    if local_sha == installed_sha:
        print("[i] Current version is the latest — no update needed.")
        return

    print("[*] Updating installed script...")
    shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
    os.chmod(SCRIPT_DST, 0o700)

    new_installed_sha = sha256sum(SCRIPT_DST)
    if new_installed_sha != local_sha:
        print("[-] Post-copy SHA mismatch! Aborting.")
        exit(1)

    write_checker(new_installed_sha)

    print("[+] Update complete.")
    if auto_restart:
        run(["systemctl", "restart", "sudomatic.service"])
        print("[+] Service restarted.")
    else:
        print("[i] Restart the service with: sudo systemctl restart sudomatic.service")

def main():
    parser = argparse.ArgumentParser(description="Installer/Updater for Sudomatic 5000")
    parser.add_argument("action", choices=["install", "update", "uninstall"], help="Action to perform")
    parser.add_argument("--restart", action="store_true", help="Auto-restart service after update")
    parser.add_argument("--purge", action="store_true", help="Remove env, logs, and state without prompts (DANGEROUS)")
    args = parser.parse_args()

    if args.action == "install":
        do_install()
    elif args.action == "update":
        do_update(auto_restart=args.restart)
    elif args.action == "uninstall":
        do_uninstall(purge=args.purge)

if __name__ == "__main__":
    main()
