# Performance harness

Two tiers, answering two different questions.

- **`ElectionGuard.Perf.Cli` (`egperf`)** — runs a whole election end to end and records the result.
  Answers "is the system faster than it was last month." Owns the historical record.
- **`ElectionGuard.Benchmarks`** — BenchmarkDotNet, function level. Answers "is this function faster
  than the one it replaced." Its output is not committed.

## Running a scenario

```bash
dotnet run -c Release --project perf/ElectionGuard.Perf.Cli -- run --scenario smoke
```

Release only. The harness refuses to record a Debug result without `--allow-debug`, because a Debug
number cannot be compared with anything.

Most scenario fields are overridable (ballot count, seed, parallelism, chunk size, warmup, guardian
threshold, and each optional phase); `budgets` and `manifest` are not — edit the scenario file for
those.

Every command also accepts `--repo-root <dir>`, which overrides the repository root the tool
otherwise finds by walking up from the binary looking for `.git` or `electionguard-cs.sln`. Scenario
paths, manifest paths, `perf/results` and `perf/thresholds.json` are all resolved beneath it.

Command-line parsing is [Spectre.Console.Cli](https://spectreconsole.net/cli/), configured in
`Program.cs`; each command declares its options on a nested `Settings` class. Parsing is strict: a
flag a command does not accept is an error, not a no-op. `--balots 1000` used to be stored, ignored,
and leave the scenario's own ballot count running, so a typo produced an authoritative record of a
workload nobody asked for. The same applies to scenario files, which reject any field this tool does
not understand rather than silently dropping it. Usage errors (unknown commands or options, missing
required options, values that do not parse) exit 2.

`egperf --help` (or `egperf help`) lists the commands; `egperf run --help` (or `egperf help run`)
prints that command's options. Both exit 0.

```bash
... -- run --scenario medium --ballots 5000 --parallelism 1 --no-decrypt
```

`--parallelism 1` is the single-threaded baseline: it isolates an algorithmic improvement from a
scheduling one. `--repeat 5` performs the run N times and tags each record with a shared repeat-group
id.

`--window-bits N` sets the width of the Note 3.5 precomputed power tables, which the harness always
builds before the timed work and reports as `powRadixBuildMs` / `powRadixBytes`. `--window-bits 0`
skips the tables entirely, which is not a return to the old behaviour: every exponentiation still
runs on Montgomery limbs, so this isolates what the *table* contributes from what the *representation*
contributes. Measured on `smoke`, against the pre-Montgomery baseline of 30.5 ms/ballot to encrypt
and 30.2 ms/ballot to verify:

| `--window-bits` | table build | table size | encrypt | verify | peak working set |
| --- | --- | --- | --- | --- | --- |
| 0 (no tables)   | –        | –       | 16.93 ms | 15.39 ms | 102 MB |
| 8               | 40 ms    | 12 MB   | 1.68 ms  | 9.97 ms  | 94 MB |
| 12 *(default)*  | 233 ms   | 132 MB  | 1.18 ms  | 9.73 ms  | 241 MB |
| 16              | 2,910 ms | 1,536 MB| 0.89 ms  | 9.58 ms  | 1,619 MB |

These numbers predate the AVX-512 tables and **need re-measuring**. On hardware with AVX-512F,
`PowRadix` now stores each entry as the AVX-512 engine's 144 29-bit digits packed one per `uint`
(576 bytes, against 512 for scalar 64-bit limbs), so the table sizes above become 13.5 MB, 148.5 MB
and 1,728 MB for the three bases (computed, not measured); without AVX-512F they are unchanged. The
build, encrypt, verify and working-set columns will all have moved.

Encryption keeps scaling with window width because every one of its exponentiations is on g, K or
K-hat. Verification flattens out around 3x because roughly half of its exponentiations are on
per-ballot bases -- the ciphertext's own alpha and beta, and the guardians' commitments -- which are
different for every ballot and so can never be tabled; those get only the ~2x from Montgomery form.
16 costs 12x the memory of 12 to buy a further 25% on encryption alone, which is why the default is
12. When `compare` selects a run that belongs to a repeat group -- whether by default or via
`--baseline`/`--candidate` -- it automatically expands to the whole group and judges the per-metric
medians instead of the single selected run, excluding any member whose correctness check failed.

## Comparing runs

`egperf` has four commands: `run`, `compare`, `report`, and `corpus`.

```bash
dotnet run -c Release --project perf/ElectionGuard.Perf.Cli -- compare --scenario medium
dotnet run -c Release --project perf/ElectionGuard.Perf.Cli -- report --output perf/results/report.html
```

`compare` exits non-zero on a threshold breach. Tolerances live in `perf/thresholds.json`: 2% on
allocation, 10% on peak heap and 15% on wall time. **Allocation is the only one that gates the exit
code.** Identical inputs allocate identically to within a fraction of a percent, with no sensitivity
to thermals, scheduling or noisy neighbours — that is what makes it the usable signal on hardware
you do not control. Wall time and peak heap both move too much on identical inputs to fail a build
on: peak heap was measured moving 8.63% between two back-to-back runs of the same scenario against
its 10% tolerance, because `GC.GetTotalMemory(false)` counts uncollected gen-0 garbage and the
sampler starts before DKG and warmup. Allocation moved ~0% in that same comparison.

All three still appear in the table and are still flagged when they exceed their tolerance.
`compare` prints `OVER TOLERANCE` for a breaching informational metric (wall time, peak heap) and
`REGRESSION` for a breaching gating one (allocation) — only the latter changes the exit code.

`compare` refuses to judge runs from different machines, GC modes, build configurations, scenario
configurations, or manifest contents, and refuses either run outright if its correctness status is
`error` or `failed` — a run that did not produce a trustworthy tally is not a measurement to compare
against, and its phases (especially a `0`-ballot, `0`-byte phase an early throw can leave behind) must
never be read as a legitimate baseline or candidate. The manifest check is separate from the scenario
one because a scenario names its manifest by path: editing the manifest file changes the election
completely while leaving the scenario's config hash byte-identical. It reports the deltas anyway,
marked informational.

## Scenarios

`perf/scenarios/*.json`. Adding a scenario is adding a file — there is no list of known ids in code.

Two knobs matter most:

- **`phases`** — which optional phases run.
- **`budgets`** — per-phase wall-clock allowance in minutes, keyed by phase name: `EncryptBallots`,
  `VerifyBallots`, `Tally`, `VerifyTally`, `DecryptTally`. A phase that exhausts its budget stops
  at the next chunk boundary and is recorded as `aborted:budgetExceeded`; the run still produces a
  record.

An exception is treated the same way. If encryption, verification, aggregation or decryption throws,
the run still produces a record: the phases that completed keep their timings, `notes.error` carries
the exception type and message, and correctness is recorded as `error`. A failed run is data — the
DKG figure and the ballots that did encrypt are not invalidated by a later throw. `run` still exits
non-zero. Any phase whose measurement the throw interrupted is also recorded `aborted`, exactly like
a budget-exceeded phase, so it can never be read as a legitimate (and possibly zero-baseline) result
by a later `compare` — which in any case refuses to judge an `error`/`failed` record at all, per
above.

Budgets exist because the code under measurement is expected to get faster. `large` currently
budgets `DecryptTally` at 30 minutes, which it will exhaust: `TallyAdmin` performs `BallotsCast + 1`
modular exponentiations per choice and does not stop on a match, so a million-ballot decryption is
not currently practical. That is a recorded fact about a real limitation rather than a hung machine,
and when the algorithm improves, raising the budget is a one-line edit to `large.json`.

## Why the harness streams

An encrypted ballot is roughly 50 KB for a four-contest manifest, so a million of them would be
about 50 GB. The runner generates a chunk, encrypts it, folds it into the tally and drops it: peak
memory is a function of `chunkSize`, not `ballotCount`. Phase timers accumulate across chunks.

One consequence: `BallotAggregationVerification` (Verification 9) needs every encrypted ballot at
once. Setting `tallyVerification: true` therefore retains them, which is affordable at `smoke` and
`small` and not at `medium` or above. Making that verification incremental is a change to
`ElectionGuard.Core` that the planned Verifier project will want anyway.

Verification 9 gets its own phase in the record, `VerifyTally` (`PhaseNames.VerifyTally`), like every
other optional phase -- its wall time and allocations used to be attributed to nowhere while still
inflating `memory.totalAllocatedBytes`, which made it invisible to a reader of the record even though
it is the most expensive optional step after encryption. Like `DecryptTally`, it can carry a budget: a
timed-out verification is recorded `aborted:budgetExceeded` on its own `VerifyTally` phase (the
`notes.tallyVerification` key still separately records `ran`/`skipped:runAborted`/
`aborted:budgetExceeded`). The `VerifyTally` phase key appears only when Verification 9 actually
started running, not merely whenever `tallyVerification: true` is set -- if the run aborted before
reaching it, it is correctly absent rather than reporting a misleading zero-cost phase.

## Results

`perf/results/<machine-id>.jsonl`, one JSON object per line. One file per machine so results from
different hardware are never averaged. `perf/results/latest/` holds the most recent run per scenario,
pretty-printed. The whole `perf/results/` directory is gitignored.

`report --output <path>` always writes a self-contained HTML file — no scripts, no external
resources, no other output format is selectable — so the same command that produces a local file
today can publish to GitHub Pages from CI later.

## Cross-language corpora

```bash
... -- corpus --scenario small --output /tmp/corpus
```

**`corpus` writes the canonical cross-language fixture.** Its `expected-tally.json` is:

```json
{
  "contests": {
    "<contestId>": {
      "overvotes": 0,
      "nullvotes": 0,
      "undervotes": 0,
      "writeIns": 0,
      "choices": { "<choiceId>": 0 }
    }
  }
}
```

`test/ElectionGuard.Testing.Cli` is a thin CLI over the same `ElectionGuard.Testing.Common` library
this harness uses for ballot generation and expected-tally accounting -- its only unique job is
Bogus-based random manifest generation of arbitrary shape. Both tools write `expected-tally.json` in
exactly this shape, so a consumer sees one schema regardless of which tool produced the file.

Writes the manifest, the plaintext ballots and the expected tally. Encryptors in other languages
consume these files; because the corpus and an in-memory run share a generator and a seed, they are
provably the same workload. `corpus` clears stale ballot files left over from a previous, larger run
at the same output directory before writing, so a non-.NET consumer globbing the ballots directory
never picks up orphaned files from an earlier ballot count. Do not commit a corpus — regenerate it
from the seed.

## Benchmarks

```bash
dotnet run -c Release --project perf/ElectionGuard.Benchmarks -- --filter '*Verification*'
```

Omit `--filter` to be prompted. `--job short` trades precision for speed while iterating.
