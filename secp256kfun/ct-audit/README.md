# Constant-time CI checks

This unpublished crate tests the vendored k256 backend through concrete `Secret`
API wrappers. [The workflow](../../.github/workflows/constant-time.yml) runs
native x86_64 taint checks, bounded RV32 relational checks, and machine-code drift
checks on four configurations. Generated binaries, disassembly, pins and results
go to `target/ct-audit/` and GitHub Actions artifacts; they are not source files.

## Inventory and secrecy contract

[contracts.json](contracts.json) maps 26 `TimeSensitive` methods to 28 wrappers
and identifies three unused `ConstantTime` entry points. The obligation applies
to `impl TimeSensitive for ConstantTime`; `VariableTime` also implements the
trait. The inventory checker validates explicit wrapper signatures, secret/public
arguments, secret-scalar labels, trait coverage, taint calls and relational cases.
New or changed operations require corresponding wrappers and inventory entries.

Seventeen wrappers take secret scalars:

- Point-producing: `audit_mul_base`, `audit_mul_normal`, `audit_mul_nonnormal`,
  `audit_mul_secret_point`, `audit_double_mul`, `audit_dot_product`,
  `audit_mul_normalize`.
- Scalar operations: `audit_scalar_add`, `audit_scalar_sub`, `audit_scalar_mul`,
  `audit_scalar_invert`, `audit_scalar_negate`, `audit_scalar_cond_negate`,
  `audit_scalar_eq`, `audit_scalar_is_high`, `audit_scalar_is_zero`,
  `audit_scalar_dot`.

The other eleven wrappers operate on secret points or predicates. Secret scalar
bytes, Secret point coordinates and conditional-negation predicates must not
affect branches or addresses. Public pointers, lengths, layouts, allocation
outcomes and explicitly Public values may. Inputs obey canonical scalar,
normalized-point and Zero/NonZero invariants. The inventory covers these wrappers
and the backend trait, not every public function or a complete protocol.

## Gates and controls

| Gate | Coverage | Failure condition |
|---|---|---|
| Native Linux x86_64 Valgrind | 28 roots × 12 fixtures, both defined and tainted passes | Any production finding, nonzero status, malformed output or missing completion receipt |
| BINSEC on RV32IMC | Ten scalar-only roots plus fixed-generator multiplication with/without normalization, in release and size/fat-LTO profiles | Insecure, incomplete, unknown, timeout or unsupported execution |
| Reviewed machine-code drift | Linux x86_64/aarch64 and both RV32 profiles | Changed build inputs, reachable instructions or call graph |

Scalar-dot models cover all nine independent public length pairs 0..2. Together
with eleven non-dot cases this gives 20 production cases per RV32 profile. Models
use canonical symbolic scalars, NonZero/bool constraints where needed, and fixed
public disjoint buffers and stack. Arbitrary point inputs, lengths and aliases
are not modeled. Taint requires all 336 completion receipts per production pass;
it samples executed paths rather than exhaustively exploring inputs.

Every semantic run also tests deliberately leaking scalar functions compiled
only with this crate's `negative-controls` feature. Both call scalar addition,
then use a result byte as a branch condition or table index. The secret variants
must fail; public-input variants must pass. Taint requires the intended finding
kind and control stack with exit 99, so a crash or incomplete run cannot count as
successful detection. BINSEC requires insecure secret controls and secure public
controls. No production finding is allowlisted.

To test the whole CI job's failure path, set [ci-control.json](ci-control.json) to
`{"inject": "branch"}` or `{"inject": "address"}` and push. After running all
production checks and self-tests, the job propagates that control's actual exit
99. Restore `{"inject": null}` afterward. This switch is outside drift hashes
and cannot skip production checking. Controls are absent from the library's
features and package and from normal audit images.

Hosted qualification at the linked historical heads:

- [Normal run](https://github.com/LLFourn/secp256kfun/actions/runs/42549239557): all six jobs passed.
- [Secret branch enabled](https://github.com/LLFourn/secp256kfun/actions/runs/42547736578): only native taint failed, with the intended violation and exit 99.
- [Secret address enabled](https://github.com/LLFourn/secp256kfun/actions/runs/42548308993): the corresponding intended failure; other jobs passed.

These links demonstrate the detector and workflow failure path at those heads.
Every changed head must pass its own checks.

## Running and maintaining the checks

Pinned tools: rustc 1.98.1 / LLVM 22.1.8 with `llvm-tools`, Valgrind 3.22.0,
BINSEC 0.11.3 / Z3 5.3.3, and cargo-zigbuild 0.23.0 / Zig 0.16.0 for Linux
cross-linking. The workflow installs them. Target CPUs are generic x86-64,
aarch64 and RV32IMC. Release uses opt=3, one codegen unit, no LTO and panic=abort;
the firmware profile uses opt=s and fat LTO with allocation/serde/bincode enabled.
Native taint builds have their own recorded pins and need not equal cross-linked
drift images. The firmware profile is a test image, not a device deployment.

From the repository root:

```sh
python3 -m unittest discover -s secp256kfun/scripts -p 'test_ct_audit.py'
python3 secp256kfun/scripts/ct_audit.py coverage
python3 secp256kfun/scripts/ct_audit_review.py
python3 secp256kfun/scripts/ct_audit.py x86 --check
python3 secp256kfun/scripts/ct_audit_repro.py x86

# Linux x86_64 with Valgrind installed:
python3 secp256kfun/scripts/ct_audit_taint.py --build-native \
  --control-switch secp256kfun/ct-audit/ci-control.json

# Run once for rv32 and again for rv32-firmware:
python3 secp256kfun/scripts/ct_audit.py rv32 --check
python3 secp256kfun/scripts/ct_audit.py rv32 --controls
opam exec -- python3 secp256kfun/scripts/ct_audit_relational.py --platform rv32
```

`baselines/` holds the four expected build configurations and reachable code
fingerprints. `reviews/` holds matching branch/address classifications and
limitations. Both are inputs to the gate. For a deliberate compiler, harness or
library update, inspect the generated disassembly and semantic results, use
`--record` to prepare candidate baselines, and update the affected review notes.
`ct_audit_review.py --base BASE_SHA` rejects changed baselines without matching
re-audit notes. Peer review is still required; matching fingerprints alone do not
prove constant-time behavior. Never re-record merely to silence a CI failure.

## Limits

The production fixes remove normalized-point equality's identity short circuit
and scalar inversion's secret-derived `CtOption::unwrap` branch. Inversion uses
`unwrap_or(Scalar::ZERO)`, preserving valid NonZero API results. Fixed loops and
public control flow remain allowed. Empty allocating point-dot has a separate
public-length panic outside these secrecy fixes.

The gates check architectural branches and memory addresses in the stated
models. They do not establish operand-independent instruction latency,
speculation/prefetch resistance, arbitrary iterator behavior, parsing,
serialization, randomness, hashing or whole-protocol security. Unknown static
transfers and unexecuted taint paths remain gaps. Hardware timing, including Apple
execution-context requirements and ESP32-C3 multiply latency, needs separate
validation; see the [library's platform requirements](../README.md#timing-and-platform-requirements).
No statistical timing threshold gates CI.

[Memcheck](https://valgrind.org/docs/manual/mc-manual.html) provides executed-path
taint detection; [BINSEC](https://binsec.github.io/binsec-tutorial/docs/tutorial-security-properties/constant-time/)
compares executions with equal public inputs and independent secrets. These
binary checks address compiler lowering that source/IR tools such as
[ct-verif](https://github.com/imdea-software/verifying-constant-time) do not cover.
[dudect](https://github.com/oreparaz/dudect) is useful for separate statistical
experiments, but a non-detection is not proof of hardware timing safety.
