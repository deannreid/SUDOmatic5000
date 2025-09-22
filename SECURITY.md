# Security Policy — **Sudomatic 5000**

**Turning realms into real users, one sudo at a time.**

This document explains how to report vulnerabilities, what is in scope, our triage timelines, and which versions receive security fixes.

---

## Supported Versions

| Version     | Supported?             |
| ----------- | ---------------------- |
| **1.3.x**   | ✅ Security fixes       |
| **1.3.x**   | ⚠️ Critical fixes   |
| ≤ **1.2.x** | ❌ End of support       |

> I use semantic versioning. Minor releases (e.g., 1.4.x) receive security updates; older lines are deprecated as new minors are cut.

---

## Scope

**In scope**

* The Sudomatic 5000 Python script(s)
* Example systemd service/timer units
* Installation & hardening guidance documented in this repo

**Out of scope**

* Proxmox VE itself and official tooling (`pve*`, `pvesh`, `pveum`)
* Your OS/distro packages and kernel
* Microsoft Graph / Entra ID and any external IdP
* Third-party libraries and tools

If you’re unsure whether something is in scope, report it anyway I'll help route it.

---

## Reporting a Vulnerability

Please **do not open a public issue** for security reports.

* **Preferred:** Create a **private security advisory** in GitHub (Security → Advisories → “Report a vulnerability”)

Include (as applicable):

* A clear description of the issue and potential impact
* Steps to reproduce / PoC (minimal & deterministic)
* Affected version(s) and environment (OS, Python version, Proxmox version)
* Logs or stack traces (scrub secrets, tokens, usernames)
* Any temporary mitigations/workarounds you’ve identified

I offer **safe-harbor** for good-faith research and coordinated disclosure. Please avoid testing against production systems you don’t own or have permission to test.

---

## Vulnerability Handling Process

**Acknowledgment:** within **2 business days**
**Triage & initial assessment:** within **5 business days**
**Fix development & advisory:** within **30 days** for High/Critical; otherwise as soon as practical
**Coordinated disclosure:** I'll agree a timeline with you; Critical issues may be fast-tracked

I classify severity using **CVSS v3.1** and GitHub’s severity levels. Where appropriate I will publish a **GitHub Security Advisory (GHSA)** and request a **CVE ID**.

Credit is given to reporters who request it, unless anonymity is preferred.

---

## Security Expectations & Hardening (for Operators)

Sudomatic 5000 manipulates local accounts and sudoers; run it **defensively**:

* **Run as root** only from a trusted path.
* **Lock down file permissions:**

  * Script file: `chmod 700`, owner `root:root`
  * Log dir (default `/var/log/sudomatic5000`): `chmod 750`, owner `root:root`
  * State dir (default `/var/lib/sudomatic5000`): `chmod 750`, owner `root:root`
  * Managed sudoers files: `chmod 440`, owner `root:root`
* **Pinned binaries:** keep `BIN` paths accurate for your distro to avoid PATH hijacking.
* **Privileged config guard:** keep `fncScriptSecurityCheck()` intact; the script will refuse to grant sudo if this gate is missing/failing.
* **Avoid `NOPASSWD`:** leave `SUDO_NOPASSWD = False` unless you absolutely know what you’re doing.
* **Groups:** treat `"sudo"`, `"wheel"`, `"admin"` as privileged—restrict membership.
* **Graph creds:** store in protected environment (systemd `Environment=` or drop-in with root-only perms). Never commit secrets.
* **Systemd:** run via a **timer** (e.g., every 30 minutes), not as a long-running root process.

---

## Responsible Disclosure

* Please keep reports **private** until a fix or mitigation is available.
* I'll coordinate a disclosure date; if I cannot meet timelines I'll communicate status and interim mitigations.
* If I disagree on impact/scope, I'll explain why and continue the conversation in good faith.

I do not currently run a paid bug bounty. Meaningful, actionable reports will be recognized in release notes (with permission).

---

## Dependencies & Supply Chain

If the issue is in a **dependency** (Python stdlib / OS tools / Proxmox / Graph), please report it to the upstream project and notify us so I can ship mitigations or version pins where required.

---

## Non-Vulnerability Security Issues

Operational misconfiguration (e.g., enabling `NOPASSWD`, overly broad `ALLOID_UPN_DOMAINS`, or running from world-writable locations) is not a software vulnerability. I still welcome reports that improve **docs, defaults, or guardrails**.

---

## Policy Updates

This policy may change over time. The **SECURITY.md** in the main branch is the authoritative version. Significant changes will be noted in release notes.
