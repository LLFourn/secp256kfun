# Constant-time checks for the vendored k256 backend

The production taint gate now requires **zero findings**. It no longer accepts a
matching list of known leaks or valid-input-invariant findings. The remaining
scalar-inversion unwrap branch is removed; the normalized-point equality fix is
retained. The hosted workflow runs native Linux x86_64 taint, two RV32 relational
configurations, source/inventory guards and reviewed machine-code drift checks.
Timing statistics are report-only.

This is scoped machine-code evidence, not a constant-time certification for every
input, compiler or CPU. Local semantic validation on this Mac uses an emulated
x86 VM; the hosted job builds and executes natively on Ubuntu x86_64 and records
its own binary/compiler pins. The hosted qualification runs below include a
passing normal configuration and deliberate branch/address failures. Each result
is tied to its exact tested head; later changes need their own checks.

## Fixes and remaining limits

- Normalized equality evaluates both identity predicates as Choices and combines
  them without the old short circuit. Its entire reached subgraph is branch-free
  in all five configurations.
- Scalar inversion uses `CtOption::unwrap_or(Scalar::ZERO)`. Safe public callers
  require NonZero, so their result is unchanged. The internal invalid-zero case
  now produces zero instead of a secret-derived panic. Optimized code replaces
  the unwrap test with masking/conditional selection on all five configurations.
  Fixed exponentiation loops remain allowed. The new strict x86 run is clean;
  RV32 inversion completes the relational model.
- No detected production taint finding is exempted. Unknown static transfers,
  unexecuted paths, unmodeled functions/lengths/aliasing and instruction latency
  remain limits rather than findings silently accepted by the gate. Static
  ARM Linux/Darwin inspection alone supplies no universal semantic proof.
- Empty allocating point-dot still panics based on public length. That is a
  separate functional bug, not a secret-dependent decision; taint covers point
  lengths 1 and 2. Scalar-dot includes lengths 0, 1 and 2.
- The native Apple experiments below show representation-dependent normalization
  timing in the tested default context, including two representations of the
  same nonidentity point. No runtime CPU-mode mitigation is installed. Native
  x86 and ESP32-C3 hardware timing, whole-protocol analysis, speculative/prefetch
  behavior and universal hardware guarantees remain outside this work.

## Checked function inventory

[contracts.json](contracts.json) maps **26 TimeSensitive methods to 28 Secret API
roots**, with three explicitly unused ConstantTime entry points. The obligation
is on `impl TimeSensitive for ConstantTime`; VariableTime also implements the
trait. Seventeen roots have **secret-scalar** inputs. Each function records its
argument classifications, preconditions, static/taint scope and exact relational
cases. The table is a readable view of that checked inventory.

| Root | Secret scalar | Secret argument data | Relational scope |
|---|---|---|---|
| `audit_mul_base` | **yes** | k: scalar | RV32, fixed generator |
| `audit_mul_normal` | **yes** | k: scalar | — |
| `audit_mul_nonnormal` | **yes** | k: scalar | — |
| `audit_mul_secret_point` | **yes** | k: scalar, p: point | — |
| `audit_double_mul` | **yes** | x: scalar, a: point, y: scalar, b: point | — |
| `audit_dot_product` | **yes** | scalars: scalar, points: point | — |
| `audit_point_add` | no | a: point, b: point | — |
| `audit_point_add_normal` | no | a: point, b: point | — |
| `audit_point_negate` | no | a: point | — |
| `audit_normal_negate` | no | a: point | — |
| `audit_point_cond_negate` | no | a: point, cond: predicate | — |
| `audit_normal_cond_negate` | no | a: point, cond: predicate | — |
| `audit_normalize` | no | a: point | — |
| `audit_mul_normalize` | **yes** | k: scalar | RV32, fixed generator |
| `audit_point_eq` | no | a: point, b: point | — |
| `audit_point_eq_normal` | no | a: point, b: point | — |
| `audit_normal_eq` | no | a: point, b: point | — |
| `audit_y_even` | no | a: point | — |
| `audit_scalar_add` | **yes** | a: scalar, b: scalar | RV32 |
| `audit_scalar_sub` | **yes** | a: scalar, b: scalar | RV32 |
| `audit_scalar_mul` | **yes** | a: scalar, b: scalar | RV32 |
| `audit_scalar_invert` | **yes** | a: scalar | RV32 |
| `audit_scalar_negate` | **yes** | a: scalar | RV32 |
| `audit_scalar_cond_negate` | **yes** | a: scalar, cond: predicate | RV32 |
| `audit_scalar_eq` | **yes** | a: scalar, b: scalar | RV32 |
| `audit_scalar_is_high` | **yes** | a: scalar | RV32 |
| `audit_scalar_is_zero` | **yes** | a: scalar | RV32 |
| `audit_scalar_dot` | **yes** | a: scalar, b: scalar | RV32, lengths 0..2 |

All 28 production roots have static coverage and 12 deterministic taint fixtures.
The restricted signature checker resolves the audit aliases and requires explicit
Scalar/Point markers; it rejects unsupported/generic declarations, unregistered
roots, changed argument classifications and incorrect secret-scalar labels. It
also checks the trait inventory, taint call inventory, and relational model list.
It is a conservative source check for these wrappers, not general Rust name
resolution. Macro-generated APIs and arbitrary iterator instantiations require
new reviewed wrappers and models.

Secret inputs are scalar bytes, secret point coordinates (including identity when
Zero permits it), and conditional-negation booleans. Public inputs are pointer
values, lengths, allocation outcomes, layouts, type markers, and point coordinates
explicitly marked Public in the inventory. Return values/predicates are outputs;
the harness does not branch on them in the audited region. Valid inputs obey
canonical scalar, normalized-point and Zero/NonZero invariants. Serialization,
parsing, random generation, hashing and complete signing protocols are excluded.

The twelve fixture records in contracts.json describe one, minus-one and seeded
nonzero scalars; zero operands; identities, equal/opposite points and one-sided
identities; both conditional-negation outcomes; and public slice lengths. The
runner requires an exact completion receipt for every `(case, root)` pair: **336
calls**, once with defined inputs and once with secrets marked undefined. This
is path-sampled taint, not exhaustive coverage of all inputs or branch outcomes.

## Deterministic CI and negative controls

[The workflow](../../.github/workflows/constant-time.yml) runs on pull requests and
pushes to master or ct-checks. It has separate native-x86 taint, RV32 relational,
and four-target static drift jobs. Darwin is locally checked with the same pinned
compiler; it is not a hosted timing gate.

The taint checker invokes a strict child checker for every case. Production
findings, nonzero tool status, malformed/incomplete XML, incomplete execution or
an unexpected checker exit all fail. It has no known-finding allowlist. Native
builds use rustc 1.98.1 / LLVM 22.1.8, x86-64 CPU, release opt=3, one codegen unit,
no LTO and panic=abort. Each hosted run retains its own normal/control executable
hashes, complete build commands/flags/compiler/linker metadata, input hashes,
Valgrind XML and completion receipts. Those native binaries are **not claimed to
be identical to the Mac-cross static baseline**.

The audit-only `negative-controls` feature compiles two standalone-crate functions
with `Scalar<Secret, Zero>` inputs. Both call the real scalar-add wrapper, then
intentionally branch on, or index a public table by, a byte of the scalar result.
Neither leak exists in the library crate or its feature set. The audit crate is
an unpublished nested workspace, excluded from the library package and normal
workspace `--all-features` builds. Normal audit images contain neither control
symbol; separate control images have separate pins.

Every normal taint run proves that each secret control makes the **same child
gate exit 99**, and that each public-input counterpart exits 0. Four concrete
scalar controls include zero and nonzero branch outcomes and several indices.
The parent accepts only the intended Memcheck finding kind with a stack through
the corresponding scalar-control function; a crash, setup failure or incomplete
run does not count as successful detection. Both RV32 profiles likewise require
insecure results for the secret controls and secure results when the scalar is
public. Public branches and public-index accesses are permitted by both engines.

To deliberately fail a whole hosted run before merge, change
[ci-control.json](ci-control.json) from `{"inject": null}` to
`{"inject": "branch"}` or `{"inject": "address"}`, commit on ct-checks and push.
The job still runs the production checks and both control self-tests, then
propagates the chosen control's actual strict-checker exit 99 to the job. Restore
null and push the final head for the passing run. The script accepts only these
three values; the switch cannot bypass production checking. Push-triggered
workflows work before the workflow is merged into the default branch, unlike
relying on a new workflow_dispatch trigger alone. See
[GitHub's event documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).
Local and hosted whole-gate results are retained separately.

## Hosted qualification evidence

| Configuration | Exact tested head | Hosted result |
|---|---|---|
| Normal (`inject: null`) | `fdd9a541a0521a704d4cfedb95e67c041b61f3d8` | [42547107811](https://github.com/LLFourn/secp256kfun/actions/runs/42547107811): all six jobs passed |
| Deliberate secret branch | `85209e82c4c194b8fc8a4404c7ba4dd6b22868e5` | [42547736578](https://github.com/LLFourn/secp256kfun/actions/runs/42547736578): only native taint failed, exit 99 |
| Deliberate secret address | `f1c7c3ebe4199e42032f06fdfc8a17623ce0acc7` | [42548308993](https://github.com/LLFourn/secp256kfun/actions/runs/42548308993): only native taint failed, exit 99 |

Both failing jobs identify the selected secret-scalar control in a `CT VIOLATION`
diagnostic and finish with exit 99. Defined/production-taint/public controls exit 0;
secret branch and address controls exit 99. All production calls complete with
zero findings. All four drift jobs and the relational job remain green in both
failing runs. The switch is deliberately outside the code/configuration drift
digest: it selects propagation of an already-checked detector failure.

The native normal/control executables are byte-identical across these three
runs; their hashes and downloaded artifact ZIP digests are recorded in
[evidence/hosted/runs.json](evidence/hosted/runs.json). Small compressed bundles
retain native build pins, results, XML, completion receipts and job logs without
Cargo build trees or executables. The first hosted relational log contains all
48 accepted production/control cases. These runs establish branch/address checks
on the stated inputs and machine-code models, not hardware timing safety.
The normal switch is restored in this tree. Future heads must pass their own CI.

## RV32 relational model

BINSEC 0.11.3 / Z3 5.3.3 now checks **all ten scalar-only roots** on each RV32
profile: add, subtract, multiply, invert, negate, conditional negate, equality,
is-high, is-zero and dot product. It also checks **fixed-generator scalar
multiplication, with and without normalization**. Eleven non-dot models plus all
nine independent public dot-length pairs 0..2 make **20 production cases per
profile**. Four secret/public control cases bring each suite to 24 cases. All complete with the
required status; pending/discontinued paths, failed assertions, unknowns,
timeouts and unsupported instructions fail the gate.

The model uses the compiled RV32 calling convention and the vendored little-endian
8x32 scalar representation. Canonical scalar values are symbolic secrets below
the group order; inversion and fixed-generator multiplication additionally assume
nonzero, and conditional negate
has a secret boolean constrained to 0 or 1. The stack and separate input/output
buffers have fixed public addresses, and readonly sections are loaded from the
exact image. The two multiplication models load the fixed public generator from
that image; they do not quantify over arbitrary point coordinates. Their depth
limit is ten million instructions (about 3.2–3.5 million executed), versus one
million for the scalar-only models. Dot-product lengths are fixed public values in each of the nine
cases, with independently symbolic canonical elements in both slices. No proof
is claimed for larger lengths or aliased input buffers. A public control uses a
shared nondeterministic input; a secret control gets independent paired values.
The installed checker source confirms that only secret assignments introduce
mirrored variables; both public control experiments complete as secure.

The checks observe control-flow decisions and demand memory addresses. They do
not prove arithmetic correctness, multiplication latency, speculation, prefetch
behavior, side-channel resistance of whole protocols or real device timing.
See the [BINSEC primary tutorial](https://binsec.github.io/binsec-tutorial/docs/tutorial-security-properties/constant-time/).
All scripts, logs, tool versions and exact per-case image hashes are retained.

## Configurations, code review and provenance

Arithmetic base: origin/master 74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce.
The earlier finalized audit/equality/Apple work is 8d2c122 / 530f289 / 37f65e1.
The vendored tree is 7143622710638279fa2b618c1e34f208f1196fec; its README describes
roughly k256 0.11.5 arithmetic with older scalar code, without a precise upstream
commit. The new source and harness digests, rather than a future commit ID, bind
the current candidate. The library MSRV/dependencies are unchanged.

| Configuration | Triple / CPU | Features | Opt / LTO |
|---|---|---|---|
| darwin | aarch64-apple-darwin / apple-m1 | std | 3 / off |
| arm-linux | aarch64-unknown-linux-gnu / generic | std | 3 / off |
| x86 | x86_64-unknown-linux-gnu / x86-64 | std | 3 / off |
| rv32 | riscv32imc-unknown-none-elf / generic-rv32 | none | 3 / off |
| rv32-firmware | riscv32imc-unknown-none-elf / generic-rv32 | firmware | s / fat |

All profiles use one codegen unit, panic=abort and debug level 1. The compiler is
rustc 1.98.1 (48a229ceaefd4985c50990b14116b6d856af0985), LLVM 22.1.8. Linux static
baselines use cargo-zigbuild 0.23.0 / Zig 0.16.0; the native taint job uses its
system linker and records that version separately. The RV32IMC firmware-shaped
profile uses size optimization, fat LTO, alloc/serde/bincode and a bounded dummy
arena. It is not the full ESP32-C3 firmware link, and no hardware was flashed.

| Primary analyzed image | SHA-256 |
|---|---|
| darwin | `cf4fbda199c2935defea213033ccca2a9bac34e937883f3c80abaa6160e41be6` |
| arm-linux | `cc02c6d00c64773a076f0687b39aab713362926697094f91255d1bc77e9d68e8` |
| x86 | `7375926b001b0d886341c4b42a9df2a5f8ca8037b78a308382614373046e7c18` |
| rv32 | `b8ec05ca05c0e97e77c506583142a82e92200dec2ba0f15c32a05edfc211a6e5` |
| rv32-firmware | `7415d3eebc299facfda0ec09e80ddbdfebe725ea8764b19f147802b048a36275` |

| Configuration | Reached functions | Conditional branches | Memory accesses | Unresolved transfers |
|---|---:|---:|---:|---:|
| darwin | 76 | 85 | 3585 | 0 |
| arm-linux | 77 | 85 | 3577 | 1 |
| x86 | 76 | 80 | 5426 | 5 |
| rv32 | 71 | 70 | 7949 | 0 |
| rv32-firmware | 61 | 142 | 4124 | 0 |

These are static inventories, not secret-dependence counts. Scalar inversion loses
its unwrap branch everywhere. The masked/conditional-select replacement uses
fixed scalar/stack/constant offsets. Other changes are relocated call/data/GOT/
arena addresses, plus eleven unreachable x86 int3 padding bytes after audit_y_even's
unconditional tail jump. `strict-gate-changes.json` and compressed diffs record
the complete comparison with 37f65e1. Each affected root/function has a refreshed
review record; records are candidate inspection classifications for peer review, not
script-generated approval. RV32 scalar claims are scoped to the models above.

The drift gate fingerprints all reached instructions and call edges, conditional
branches, loads/stores, exclusions and unresolved transfers. Its linear register
provenance is an inspection aid, not a dataflow proof. Configuration changes
invalidate evidence; candidate re-records require fresh review notes for affected
roots. HOME/Cargo/checkout/Zig-cache paths are remapped, and linker-only debug
metadata is removed with section-preservation checks. Alternate-Cargo-home builds
must match the reviewed snapshots. The four ELF pairs are byte-identical; Darwin
claims snapshot reproducibility only. The hosted Linux jobs reproduced the
existing Mac-cross snapshots on all four hosted configurations, without baseline
changes; hosted x86 also passed its relocated-Cargo-home check. This closes the
previous cross-host snapshot gap for the pinned configuration, not for arbitrary
compiler or linker versions.

`evidence/before-ct-pr/` retains the previous static/semantic pins, snapshots,
classifications and results. They are historical: the prior inversion invariant
is no longer an active allowance. The Apple timing files below retain their
original independent executable/source pins and are not reruns of the current
scalar-inversion change.

## Run and maintain the checks

From the repository root with rustc 1.98.1 selected:

```sh
python3 secp256kfun/scripts/ct_audit.py coverage
python3 -m unittest discover -s secp256kfun/scripts -p test_ct_audit.py
python3 secp256kfun/scripts/ct_audit_review.py --base REVIEW_BASE
python3 secp256kfun/scripts/ct_audit.py x86 --check
python3 secp256kfun/scripts/ct_audit_repro.py x86

# Native Ubuntu x86_64, with Valgrind 3.22.0 installed
python3 secp256kfun/scripts/ct_audit_taint.py --build-native \
  --control-switch secp256kfun/ct-audit/ci-control.json

# Local Mac audit VM: emulated semantic evidence, never native x86 timing
python3 secp256kfun/scripts/ct_audit.py x86 --controls
python3 secp256kfun/scripts/ct_audit_taint.py --runner 'limactl shell ct-x86 --'

# BINSEC 0.11.3 and Z3 5.3.3 on PATH (or pass --binsec)
for platform in rv32 rv32-firmware; do
  python3 secp256kfun/scripts/ct_audit.py "$platform" --check
  python3 secp256kfun/scripts/ct_audit.py "$platform" --controls
  python3 secp256kfun/scripts/ct_audit_relational.py --platform "$platform"
done
```

`--inject-control branch` / `address` also exercise whole-gate failure locally.
`--check-run` invokes the strict child on one supplied mode/image; it has no
exception for a deliberately bad function. Relational `--only` is a diagnostic
subset and writes a separate result; CI always runs the full suite. Use `--record`
only to prepare reviewed static candidates, never to approve code changes.
The semantic checker no longer supports recording an accepted finding list.

Local validation and exact artifacts are summarized in `evidence/validation.json`.
The main library's all-feature and no-default-feature tests/doctests pass, as do
strict audit Clippy and formatting, 14 detector tests, coverage and review guards.
The new workflow passes actionlint 1.7.12. No new timing run is required for this
branch/address change; earlier native experiments remain scoped history below.
Tool caches remain local and within the 20-GB budget; only the owned ct-x86 VM is
used, and it is stopped after semantic checks. The hosted evidence above is
separate from those local runs. The evidence tree is roughly 12 MB, including
compressed disassembly/logs and historical pins; it is retained so consolidating
the audit history does not discard the original scope or results.

## Historical native timing and verification research

The following native measurements were taken on 2026-11-06, before this scalar
inversion change, using their separately pinned timing executables. The hardware
limits and public Apple contract still apply. The present branch has not been
retimed, and these observations do not prove the current library constant-time.

## Native Mac timing and calibration before the equality fix

Host: **Apple M5 Max, macOS 27.0.1 (26A434)**. The separate `ct_timing` executable
uses the same wrappers and locked dependencies, release opt=3/one codegen unit/no
LTO, with rustc's default host CPU. It is separately hashed; it is not the static
`ct_audit` image. Three seeds run 100,000 samples per row, with randomized class
order and fixture generation outside timing. The Welch estimator and pooled
90/75/50-percent crops carry forward the earlier arith-backend harness.

The original audit's final experiment used the **same executable** for default
mode and Apple's
`timingsafe_enable_if_supported()` mode, alternating modes for each seed. DIT was
read as 0 before every run, stayed 0 in default mode, and read `0x1000000` during
timing-safe mode; the previous state is restored on exit. The ordinary library
does not enable this mode as part of this change.

Below is the maximum absolute t statistic across the raw and three pooled crops;
4.5 is an investigation threshold, not a corrected multi-test p-value.

| Comparison | Default seeds 1 / 2 / 3 | Timing-safe seeds 1 / 2 / 3 |
|---|---|---|
| kG one/random | 3.40 / 17.67 / 21.89 | 1.74 / 1.74 / 1.02 |
| kG then normalize one/random | 10.39 / 20.17 / 10.28 | 1.65 / 1.21 / 1.40 |
| normalize identity/nonidentity | 43.19 / 53.95 / 48.54 | 1.68 / 1.83 / 1.51 |
| normalized equality identity/nonidentity | 7.60 / 23.13 / 8.98 | 1.64 / 5.73 / 1.30 |

All identical-input controls stayed below 2.97. kP fixed/random and scalar
inversion one/random stayed below 2.80. A known real branch was not consistently
detected with DIT enabled, illustrating why a statistical pass is insufficient.
The equality test also changes its returned boolean; the harness black-boxes the
result without conditional processing. Static and taint evidence establish the
internal branch independently of this timing comparison.

Positive calibration injects dependent integer-add sequences after fixed-input
kG. Each delay is measured separately against the zero-add call in 101 randomized
pairs of 1,024-call batches, reporting median/p10/p90 nanoseconds. These are
measured incremental costs, not assumed cycles per instruction. Four adds
measured indistinguishably from zero. Across the six final runs:

| Adds / measured incremental cost | Any class-difference flag | Expected direction | Opposite direction |
|---|---:|---:|---:|
| 16 / 0.6–0.8 ns | 0/6 | 0/6 | 0/6 |
| 64 / 7–9 ns | 0/6 | 0/6 | 0/6 |
| 256 / 50–64 ns | 5/6 | 4/6 | 4/6 |
| 1024 / 239–324 ns | 6/6 | 6/6 | 4/6 |

A run flags when any raw or cropped statistic has `abs(t) > 4.5`. Class 1
receives the delay, so the expected direction is `t < -4.5`; opposite-direction
flags have `t > 4.5`. The direction columns overlap when crops disagree. For
example, default seed 2 with 1024 adds has a 375-ns slower class-1 median, but
`t90 = +13.62`, `t75 = -6.46`, `t50 = -8.38` and `t-all = -0.20`.
Pooled cropping of these multimodal, timer-quantized distributions can reverse
the direction. Operation flags can also be confined to particular crops.

This setup repeatedly detected a class difference in the roughly 0.3-microsecond
injection experiment at this workload/sample count, including an expected-direction
flag in all six runs. The conflicting cropped signs prevent treating the absolute
flag counts as a calibrated delay-detection threshold. They do **not** bound all
undetected leakage below that number or guarantee 50-ns detection.
Delay calibration occurs outside the measured cryptographic
operation; instruction overlap, timer granularity and scheduling affect it.
The machine was not isolated or core-pinned; other work/VMs and frequency changes
are possible confounders. TSV summaries and exact pins are retained; individual
sample streams were not saved. Timing is audit evidence, not a flaky PR gate.

The disappearance of repeated kG/normalization flags when enabling timing-safe
mode is evidence of a platform-context dependency, not identification of one
specific leaking instruction or a complete mitigation proof. The focused Apple
follow-up and public platform contract are described below.
No blanket guarantee is available for the default Mac execution context.

## Native timing after the equality fix

The unchanged timing harness was rebuilt with the fixed arithmetic and rerun for
the same three seeds, 100,000 samples per row, alternating default/timing-safe
modes. One executable was used throughout; its hash is above. Our `ct-x86` VM
was stopped before timing, but the Mac remained unisolated and not core-pinned.
DIT again read 0 in default mode and `0x1000000` in timing-safe mode.
The retained files are `evidence/darwin/timing-after-normal-eq/`, including source,
harness and executable pins, all six TSVs, and a parsed summary.

| Comparison, maximum absolute finite t | Default seeds 1 / 2 / 3 | Timing-safe seeds 1 / 2 / 3 |
|---|---|---|
| normalized equality IDENTICAL | 1.27 / 1.45 / 1.97 | 0.25 / 2.37 / 0.56 |
| normalized equality identity/nonidentity | 0.48 / 0.92 / 1.63 | 1.82 / 1.19 / 1.64 |
| normalize identity/nonidentity | 152.70 / 161.05 / 159.79 | 2.19 / 1.28 / 1.07 |

No equality statistic crosses 4.5. All identical-input controls remain below
2.58. The 1024-add positive control measured approximately 216–220 ns; all four
statistics in each of the six runs flagged in the expected direction. This validates
class-difference detection for that experiment, not a general leakage threshold.
However, equality medians are 0 ns at the timer's granularity, and its
50-percent crops have zero variance (`n/a`); non-detection cannot supply a small
leakage bound. Static branch removal and sampled taint are the substantive
regression evidence. The original and new timing binaries are distinct, so
these timings alone do not isolate the source edit from layout/platform changes.

The repeated normalization flags with DIT off motivated the focused experiment
below; the equality branch is already removed. The earlier kG and
kG-then-normalize flags did not recur above 4.5 in these three seeds (maxima 4.24
and 3.00 respectively). Neither result identifies a leaking instruction or
establishes a platform-wide guarantee.

## Apple platform contract and focused normalization experiment

The public [timing/platform requirements](../README.md#timing-and-platform-requirements)
are linked from Secret, Secrecy, Point and Scalar rustdoc. Secret expresses an
implementation obligation; it does not configure the CPU or certify compiled
code and whole protocols. Apple callers must establish a supported synchronous
context before handling sensitive data, handle OS availability separately from
hardware support, and restore the prior state with the opaque token on the same
thread, including early exits. Such a scope must not span await/thread migration.
The library provides neither automatic enablement nor an older-OS fallback.

[Apple's maintained ARM64 guidance](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)
and the local SDK `timingsafe.h` were checked on 2026-11-06. API availability begins
at macOS 15.2, iOS/iPadOS/tvOS 18.2, watchOS 11.2 and visionOS 2.2. An available API
can have no effect on unsupported hardware. Apple's mode uses device-appropriate
safeguards, including speculation barriers, in addition to DIT. Therefore the
API-mode contrast cannot be attributed to the DIT bit alone. Our host reports
`hw.optional.arm.FEAT_DIT=1`; this is CPU support, not a guarantee for every
instruction. We have not established full instruction-latency, speculative or
prefetch safety, even with the mode enabled.

### Actual timing executable comparison

The **separately linked timing executables**, before and after the equality fix,
were disassembled with the pinned LLVM tools. Each normalization subgraph reaches
six functions, with three conditional branches, 443 memory-access instructions,
109 multiply candidates and no unresolved transfers. All six normalized instruction
fingerprints match. Five function locations, including the root, match; only
`subtle_ng::black_box` moves from `0x10003de0c` to `0x10003de00` (12 bytes).
The six raw instruction-operand differences are calls to that helper: two in
field inversion and four in point normalization. Their opcodes are unchanged.

The three branches are fixed exponentiation loops in field inversion, with
counters initialized to 44, 88 and 44. This
comparison does not establish that the helper's alignment caused the changed
statistics, and it does not measure a change in leakage magnitude. Scheduling,
frequency, code/data layout and other process context remain possible confounders.
The original timing sources, hashes and results are preserved, rather than being
relabeled as measurements of the current input tree. Disassembly, symbol layouts,
normalization analyses and exact operand deltas are in
`evidence/darwin/apple-normalization/`.

### Focused experiment

The audit-only `normalize` option uses 16 black-boxed calls to `audit_normalize`
per sample, with 100,000 randomly ordered samples per row and seeds 1, 2 and 3.
The reported medians are **nanoseconds per entire batch**, not per operation.
Fixtures are made outside the timer: identity, a nonidentity point obtained by
adding two normalized points, and that same point normalized then converted back
to the non-normal type (z=1). Equality of the two nonidentity points is asserted.
This holds their affine value constant but changes their coordinate representation;
it does not isolate z, inversion, an individual instruction or a prefetch mechanism.
Both nonidentity representations also have identical-input controls. The positive
control adds 4,096 dependent integer adds after a fixed-input batch in class 1.

One separately pinned native executable is used in both modes, default then
API-enabled for each seed, on the same M5 Max/macOS host and release profile as
before. Our VM is stopped and audit builds are finished before timing. The machine
is still unisolated and not core-pinned. The harness records DIT before, during
and after restoration; nested scopes and unwind restoration are separately tested.
All TSV summaries, seed fixtures, commands, source/harness/compiler/profile pins
and a parsed summary are retained in `evidence/darwin/apple-normalization/`.
The underlying sample streams are not retained; this remains an investigation,
not a CI timing threshold or a hardware proof. This optional experiment binary
and its restoration test require a DIT-supported ARM Mac and macOS 15.2 or later:
they directly link the API and read DIT. Applications need their own availability
and support handling as described in the public contract.

The focused executable's normalization subgraph has the same six function
fingerprints and control/address structure as the post-equality timing executable.
All six function locations change. Its 110 raw operand deltas are 107 calls to
the same named functions and three fixed-loop branches to the same relative
offsets; only absolute addresses change. The batch body contains 16 unrolled
direct calls to the wrapper, so the repeated workload was not optimized away.
These comparisons concern the actual timing images, independently of the static
five-target images. See `focused-differences.json` and `batch-disassembly.json`.

| Comparison, maximum absolute finite t | Default seeds 1 / 2 / 3 | API-enabled seeds 1 / 2 / 3 |
|---|---|---|
| IDENTICAL projective | 1.47 / 1.34 / 1.15 | 1.85 / 2.13 / 1.23 |
| IDENTICAL z=1 | 1.02 / 0.93 / 0.73 | 2.73 / 0.88 / 1.43 |
| identity/projective | 34.33 / 330.04 / 172.22 | 1.22 / 1.61 / 1.34 |
| identity/z=1 | 1.30 / 5.30 / 1.77 | 1.26 / 2.03 / 2.08 |
| nonidentity z=1/projective | 50.43 / 309.75 / 279.44 | 1.52 / 2.35 / 0.91 |
| positive: fixed batch +4096 adds | 23.72 / 198.86 / 181.83 | 422.95 / 631.11 / 177.08 |

DIT reads 0 before all six runs, remains 0 in default mode, reads `0x1000000`
in API-enabled mode, and returns to 0 after every run. The identity/projective
contrast reproduces in all default-mode seeds; so does the comparison between
two representations of the **same nonidentity point**. Neither flags in the
API-enabled runs. This weakens an identity-only explanation but does not identify
the mechanism. Identity/z=1 has one isolated default-mode flag (seed 2's 50-percent
crop); that comparison is not consistently null. The identical controls all stay
below 2.74.

The positive control has an expected-direction flag in every run. Its class-1
median is 918–1,083 ns slower per batch; default seed 1 also has an opposite-sign
50-percent crop (`t50=+11.20`, while `t90=-23.72`). These are noisy, cropped,
multiple-comparison statistics, not a calibrated leakage bound. The large change
in t across seeds does not establish a corresponding change in leak size.
The strongest supported conclusion is repeated input-class timing dependence
in the tested default execution context, with no detection for those contrasts
in these API-enabled runs. This supports a documented caller obligation and
further hardware/instruction investigation, **not** a claim that this change
mitigates the issue at runtime or that timing-safe mode proves the library safe.

## Verification research and hardware limits

The choice is a layered method informed by current primary material:

- [BINSEC's maintained binary checker](https://binsec.github.io/binsec-tutorial/docs/tutorial-security-properties/constant-time/)
  checks paired executions with equal public inputs and independent secrets.
  It closes a useful machine-code gap for small tractable roots; completeness,
  initialization and ISA support still matter. [Release notes](https://github.com/binsec/binsec/blob/master/CHANGES.md)
  distinguish optional multiplication/division observations from default CT checks.
  We used the current checker, not the retired binsec/rel tool.
- [CT-Prover (FSE 2024)](https://arxiv.org/abs/2402.13506) and
  [its artifact](https://github.com/S3L-official/CT_Prover) strengthen scalable
  LLVM-level verification. Its documented Clang-12 pipeline is not a drop-in
  verifier for this Rust/LLVM-22 binary. [ct-verif](https://github.com/imdea-software/verifying-constant-time)
  is another relational IR approach. Neither was claimed to have run here.
  The [BINSEC/Rel compiler study](https://arxiv.org/abs/2209.01129) is direct
  evidence that later lowering can violate an earlier IR-level CT property.
- [ctgrind](https://github.com/agl/ctgrind) motivates secret-as-undefined testing.
  We used modern [Memcheck client requests](https://valgrind.org/docs/manual/mc-manual.html),
  rather than depending on its old patch. This catches executed branch/address
  dependencies but lacks path completeness and semantic invariants.
  [Microwalk](https://github.com/microwalk-project/Microwalk) is an alternative
  dynamic trace/CI approach; it would add another trace implementation, not
  universal input coverage. It was not installed for this audit.
- [dudect](https://github.com/oreparaz/dudect) supplies the statistical testing
  model. Controls, repeated seeds and measured sensitivity are necessary to
  interpret a non-detection, which remains weaker than proof.
- [Jasmin's current CT tooling](https://jasmin-lang.readthedocs.io/en/v2026.03.2/tools/ct.html)
  illustrates the stronger long-term option of explicit security contracts and
  compilation preservation, including separate speculative/DIT concerns. It
  does not verify arbitrary Rust, and a language/backend rewrite is outside scope.

There is no single “state-of-the-art check” that proves hardware timing safety for
this Rust library on arbitrary CPUs. These tools establish different properties;
contract inventory and exact-code regression checking preserve scoped evidence
between audits without upgrading it into a proof.

[Apple's arm64 guidance](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)
explains timing-safe mode/DIT and supported-instruction constraints. Architectural
branch/address independence alone does not imply operand-independent timing.
[GoFetch](https://gofetch.fail/) demonstrates data-dependent prefetch leakage on
studied Apple M-series machines; this audit does not establish whether that
attack applies to this M5. Speculation, prefetch/cache-content effects and power
or frequency channels are outside our binary observation model.

[Intel's DOIT guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html)
scopes operand-independent timing to supported processors/instructions and mode
settings. A generic x86-64 build and emulated taint run do not establish those
hardware assumptions, even without division. Native x86 timing remains a gap.

[Espressif's ESP32-C3 technical reference manual v1.4](https://documentation.espressif.com/esp32-c3_technical_reference_manual_en.pdf)
describes the RV32IMC core, but the reviewed CPU material does not supply a
sufficient operand-independent latency guarantee for its `mul`/`mulhu` here.
**C3 multiply timing is unknown in this audit**; no one-cycle assumption or
emulated cycle measurement substitutes for that missing evidence.
