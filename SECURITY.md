# Security Policy

## Reporting a vulnerability

**Email [security@frostsnap.com](mailto:security@frostsnap.com).** The maintainers handle reports for this repository
through Frostsnap's security address. Please do not open a public issue or pull request: these crates secure real
bitcoin, and a public report reaches attackers before a fix does.

You may encrypt your report to the key at [frostsnap.com/pgp.txt](https://frostsnap.com/pgp.txt), fingerprint:

```
F19C CCCD 876B 6E57 FB71  2206 A9D5 981F 42B0 EA50
```

Include what you have found: the affected crate and version or commit, what an attacker gains, and a proof of concept
if you have one. A rough report is welcome.

We will acknowledge your report, confirm whether we can reproduce it, and agree a disclosure timeline with you. Fixes go
into a new release of the affected crates. Once the fix is released we publish a security advisory, crediting you
unless you prefer otherwise.

The arithmetic backend in `secp256kfun/src/vendor/k256` is derived from RustCrypto's `k256`. If a bug there also
affects `k256`, we will coordinate the disclosure with its maintainers.

## Scope

Every crate in this workspace: `secp256kfun`, `schnorr_fun` (including FROST, MuSig and chilldkg), `ecdsa_fun`,
`sigma_fun`, `vrf_fun` and `arithmetic_macros`. We most want to hear about:

- forging a signature, aggregate signature or proof without the key or the threshold;
- recovering a secret key, FROST share or nonce from signatures, proofs or protocol messages;
- a malicious participant biasing or controlling a jointly generated key, or obtaining a share it should not have;
- wrong arithmetic results on any backend, including the 32-bit one;
- accepting an invalid point or scalar where the type promises a valid one;
- a timing difference that depends on a value marked `Secret`.

Not in scope, and fine to report in a public issue: variable time on values the caller marks `Public` (this is by
design), secrets not being zeroed in memory (the README says so), and panics or denial of service from malformed input,
unless they lead to one of the issues above.

## Bounty

[Frostsnap](https://frostsnap.com) pays **1,000,000 satoshi** for a vulnerability in the scope list above that could
cost users funds or expose their keys in real use. It must be the first private report of an issue that is not already
known to us or public, and you must follow the coordinated disclosure above. Test only against your own keys and
devices. We assess each report case by case and may pay more for a severe, practically exploitable attack. Frostsnap
decides whether to pay and how much.
