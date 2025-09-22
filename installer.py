#!/usr/bin/env python3
import os
import shutil
import hashlib
import subprocess
import argparse
from pathlib import Path

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
            run(["pip3", "install", "-r", str(REQS)])
            print("[+] Requirements installed successfully")
        except subprocess.CalledProcessError:
            print("[-] Failed to install requirements.txt")
            exit(1)
    else:
        print("[i] No requirements.txt found, skipping dependency installation.")

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

def do_install():
    require_root()
    print("[*] Installing Sudomatic 5000...")

    install_requirements()

    # Install Python script
    shutil.copy2(SCRIPT_SRC, SCRIPT_DST)
    os.chmod(SCRIPT_DST, 0o700)
    print(f"[+] Installed script to {SCRIPT_DST}")

    # Calculate SHA256
    expected_sha = sha256sum(SCRIPT_DST)
    print(f"[+] Calculated SHA256: {expected_sha}")

    # Create checker
    write_checker(expected_sha)

    # Create log directory
    LOGDIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    print(f"[+] Created log directory {LOGDIR}")

    # Create systemd service
    service_unit = f"""[Unit]
Description=Sudomatic 5000 — Proxmox OIDC to Linux user sync
After=network-online.target pve-cluster.service
Wants=network-online.target

[Service]
Type=oneshot
ExecCondition={CHECKER}
ExecStart=/usr/bin/python3 {SCRIPT_DST}
User=root
"""
    SERVICE.write_text(service_unit)

    # Create systemd timer
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

    # Enable
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "sudomatic.timer"])

    print("[+] Installation complete.")
    print("[i] To check logs: journalctl -u sudomatic.service")

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
    parser.add_argument("action", choices=["install", "update"], help="Action to perform")
    parser.add_argument("--restart", action="store_true", help="Auto-restart service after update")
    args = parser.parse_args()

    if args.action == "install":
        do_install()
    elif args.action == "update":
        do_update(auto_restart=args.restart)

if __name__ == "__main__":
    main()
