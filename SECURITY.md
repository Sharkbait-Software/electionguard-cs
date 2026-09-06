# Security Policy

ElectionGuard C# is an implementation of an end-to-end verifiable voting protocol. Cryptographic
correctness and ballot secrecy are core to what this library is for, so we treat security reports
seriously and ask that they be reported responsibly.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting for this repository:

1. Go to the [Security tab](../../security) of this repository.
2. Click **"Report a vulnerability"** to open a private advisory.

This lets us discuss and fix the issue before it's publicly disclosed.

If you're unable to use GitHub's private reporting for some reason, open a regular issue asking
for an alternate private contact method — please don't include vulnerability details in that
issue itself.

### What to include

To help us triage quickly, please include:

- A description of the vulnerability and its potential impact (e.g. key material exposure,
  ballot secrecy violation, ability to forge a valid-looking proof, denial of verification).
- The spec section(s) or code path(s) involved, if known (e.g. a specific `Verify` class or
  `Verification` number).
- Steps to reproduce, or a minimal repro if possible.
- Any suggested fix or mitigation, if you have one.

### What to expect

- We'll acknowledge new reports as soon as we're able to.
- We'll work with you to understand and confirm the issue, and to agree on a disclosure timeline.
- Credit will be given in the advisory/release notes unless you prefer to remain anonymous.

## Supported Versions

This project does not yet have a formal release/support matrix. Until one exists, please report
issues against the latest code on the `main` branch.

## Scope

In scope:

- The `ElectionGuard.Core` library itself — cryptographic primitives, key generation, ballot
  encryption, tallying, and verification logic.

Out of scope:

- The example/console/CLI/test projects (`ElectionGuard.InMemory.Console`,
  `ElectionGuard.Testing.Cli`, the unit test project), unless the issue demonstrates a problem in
  `ElectionGuard.Core` that they merely surface.
- General best-practice suggestions with no demonstrated security impact — feel free to raise
  those as a normal issue or discussion instead.
