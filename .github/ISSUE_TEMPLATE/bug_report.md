---
name: Bug Report
about: Report incorrect behaviour, panics, or unexpected results
title: "[BUG] "
labels: ["bug"]
assignees: []
---

## Description

<!-- A clear and concise description of the bug. -->

## Environment

| Item | Value |
|------|-------|
| OS / Kernel | <!-- e.g. Ubuntu 22.04 / 5.15.0 --> |
| Rust version (`rustc --version`) | |
| Cargo version (`cargo --version`) | |
| Binary built from commit | |

## Command used

```bash
# Paste the exact command here
./target/release/quic-cid-flood-attack \
  --target 127.0.0.1:443 \
    --vector raw \
      ...
      ```

      ## Expected behaviour

      <!-- What did you expect to happen? -->

      ## Actual behaviour

      <!-- What actually happened? Include error messages, panic output, or unexpected CSV results. -->

      ## Log output

      ```
      # Run with RUST_LOG=debug and paste the output here
      RUST_LOG=debug ./target/release/quic-cid-flood-attack ...
      ```

      ## Additional context

      <!-- Anything else that might help diagnose the issue (e.g., server type, network topology, hardware specs). -->
