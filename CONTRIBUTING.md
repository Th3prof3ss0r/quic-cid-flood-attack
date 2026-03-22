# Contributing to quic-cid-flood-attack

Thank you for your interest in contributing to this academic security research project. Please read the following guidelines carefully before opening issues or submitting pull requests.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Scope of Contributions](#scope-of-contributions)
- [How to Report Bugs](#how-to-report-bugs)
- [Proposing New Features](#proposing-new-features)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Ethical Responsibilities](#ethical-responsibilities)

---

## Code of Conduct

This project adheres to basic principles of respectful academic collaboration. All contributors are expected to:

- Be respectful and constructive in all communications.
- Keep discussions focused on the technical and scientific merits of contributions.
- Refrain from any language or behavior that is discriminatory or harassing.

---

## Scope of Contributions

This tool exists **exclusively for academic and defensive security research**. Contributions are welcome in the following areas:

- Bug fixes and correctness improvements to the existing attack vectors.
- New metrics collection strategies or output formats.
- Additional CID generation modes for reproducibility purposes.
- Improvements to documentation, test coverage, and CI pipeline.
- Defense simulation modules that help study mitigation effectiveness.

Contributions that lower the barrier for **offensive use against production systems** will not be accepted. Examples of out-of-scope changes:

- Bypass mechanisms for rate limiting or CAPTCHAs.
- Automatic target discovery or scanning features.
- Obfuscation of traffic patterns to evade IDS/IPS detection.

---

## How to Report Bugs

1. Search [existing issues](https://github.com/Th3prof3ss0r/quic-cid-flood-attack/issues) to avoid duplicates.
2. Open a new issue using the **Bug Report** template.
3. Provide:
   - Rust version (`rustc --version`)
      - OS and kernel version
         - Exact CLI command used
            - Expected vs. actual behaviour
               - Relevant log output (with `RUST_LOG=debug`)

               ---

               ## Proposing New Features

               1. Open a **Feature Request** issue before writing code.
               2. Describe the research motivation: which QUIC RFC section does it relate to?
               3. Discuss the ethical implications of the proposed feature.
               4. Wait for maintainer feedback before investing significant development effort.

               ---

               ## Development Setup

               ```bash
               # Clone the repository
               git clone https://github.com/Th3prof3ss0r/quic-cid-flood-attack.git
               cd quic-cid-flood-attack

               # Install the Rust toolchain (stable)
               rustup install stable
               rustup override set stable

               # Build in debug mode
               cargo build

               # Run unit and integration tests
               cargo test

               # Build optimised release binary
               cargo build --release

               # Check formatting and lints before committing
               cargo fmt --check
               cargo clippy -- -D warnings
               ```

               ---

               ## Coding Standards

               | Rule | Tool |
               |------|------|
               | Formatting | `cargo fmt` (rustfmt defaults) |
               | Linting | `cargo clippy -- -D warnings` |
               | Documentation | All public items must have `///` doc comments |
               | Error handling | Use `anyhow::Result` — avoid `unwrap()` in library code |
               | Unsafe code | Forbidden unless a compelling justification is provided and reviewed |

               ### Commit messages

               Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

               ```
               feat(metrics): add throughput percentile columns to CSV export
               fix(raw_flood): prevent integer overflow on 32-bit targets
               docs(readme): update installation URL to canonical repository
               test(integration): add frame flood smoke test against mock server
               ```

               ---

               ## Pull Request Process

               1. Fork the repository and create a branch from `main`:
                  ```bash
                     git checkout -b feat/my-improvement
                        ```
                        2. Make your changes, ensuring all tests pass:
                           ```bash
                              cargo test && cargo fmt --check && cargo clippy -- -D warnings
                                 ```
                                 3. Update `CHANGELOG.md` under the `[Unreleased]` section.
                                 4. Open a pull request against `main` with a clear description of:
                                    - What was changed and why.
                                       - Which RFC sections are referenced (if applicable).
                                          - Any performance or memory implications.
                                          5. At least one maintainer review is required before merging.

                                          ---

                                          ## Ethical Responsibilities

                                          By contributing to this project, you confirm that:

                                          - You will not use or encourage the use of this tool against systems you do not own or have explicit written permission to test.
                                          - Your contributions will not intentionally facilitate harm to third-party infrastructure.
                                          - You have read and agree to the [Ethical Use Statement](README.md#️-ethical-use-statement) in the README.

                                          Any contribution found to be intentionally harmful will be reverted and the contributor may be permanently blocked from the project.
