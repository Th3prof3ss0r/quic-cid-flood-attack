# Security Policy

## ⚠️ Important Notice

`quic-cid-flood-attack` is an **academic research tool** designed exclusively for studying vulnerabilities in the QUIC protocol (RFC 9000) within isolated laboratory environments. It is **not** a general-purpose offensive tool.

---

## Supported Versions

Only the latest commit on the `main` branch is actively maintained. There are no versioned releases with separate security support windows at this time.

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| Older commits | ❌ |

---

## Responsible Disclosure

If you discover a security vulnerability **within this codebase itself** (e.g., memory unsafety, dependency with a known CVE, or a logic flaw that could enable unintended harm), please follow responsible disclosure practices:

1. **Do not open a public GitHub issue** for security vulnerabilities.
2. Send a private report to the maintainer via email:
   - **Email:** `rafael@renovaci.com`
      - **Subject:** `[SECURITY] quic-cid-flood-attack — <short description>`
      3. Include:
         - A description of the vulnerability and its potential impact.
            - Steps to reproduce.
               - Affected files or components.
                  - Any suggested mitigations.
                  4. You will receive an acknowledgement within **72 hours** and a resolution timeline within **7 days**.

                  We follow a **90-day disclosure timeline**: if a fix is not available within 90 days of the report, the reporter is free to publish their findings.

                  ---

                  ## Scope

                  ### In Scope

                  - Memory safety issues (use-after-free, buffer overflows, data races) in Rust code.
                  - Dependency vulnerabilities (`cargo audit` findings) that could affect tool integrity.
                  - Logic errors that could cause the tool to behave in ways unintended by the codebase.

                  ### Out of Scope

                  - Vulnerabilities in **target servers** (Caddy, nginx, QUIC implementations) — report those to their respective maintainers.
                  - Issues that require an attacker to have already compromised the lab machine running this tool.
                  - Feature requests or usability concerns — use GitHub Issues for those.

                  ---

                  ## Ethical Use Reminder

                  This tool **must not** be used against systems without explicit written authorisation from their owners. Unauthorised use may violate computer fraud laws in your jurisdiction (e.g., CFAA in the USA, Computer Misuse Act in the UK, Lei 12.737/2012 in Brazil).

                  The maintainers accept **zero responsibility** for misuse. By using, forking, or distributing this software, you agree to the terms stated in the [Ethical Use Statement](README.md#️-ethical-use-statement).

                  ---

                  ## Acknowledgements

                  Responsible disclosures will be credited in this file (with the reporter's consent) after a fix is published.
