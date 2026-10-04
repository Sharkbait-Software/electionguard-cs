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
`PowRadix` now stores each entry as the AVX-512 engine's 80 52-bit digits, one per `ulong` (640
bytes, against 512 for scalar 64-bit limbs), so the table sizes above become 15 MB, 165 MB and
1,920 MB for the three bases (computed, not measured); without AVX-512F they are unchanged. The
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

Budgets exist because the code under measurement is expected to get faster, and a phase that is
impractical today should produce a record rather than a hung machine. `DecryptTally` was the
example: `TallyAdmin` used to perform `BallotsCast + 1` modular exponentiations per choice, which
made a million-ballot decryption impossible inside `large`'s 30-minute budget. It now recovers each
count with a baby-step giant-step search sharing one table across choices, about
2·sqrt(choices x BallotsCast) multiplies in all, and `xsmall`'s decryption fell from 28.5 s to about
50 ms; the budget stays as a backstop.

## Why the harness streams

An encrypted ballot is roughly 50 KB for a four-contest manifest, so a million of them would be
about 50 GB. The runner generates a chunk, encrypts it, folds it into the tally and drops it: peak
memory is a function of `chunkSize`, not `ballotCount`. Phase timers accumulate across chunks.

Verification 9 streams too. It recomputes the aggregate from the ballots and compares it with the
claimed tally, and the aggregate is a product that does not depend on order or grouping, so
`BallotAggregationVerifier` (in `ElectionGuard.Core`) folds each chunk into its own independent
recomputation as the chunk goes by, and compares once after the last one. No ballot is retained, so
`tallyVerification: true` is affordable at every scale and `medium` and `large` run it. (It used to
take every encrypted ballot at once, which made the harness retain them all -- measured at roughly
290 KB per retained ballot, so tens of GB at `medium` and hundreds at `large` -- and those scenarios
had to switch it off. Both now peak at about 4.7 GB of managed heap, the same at a million ballots as
at a hundred thousand.) The harness feeds it the same chunk it
has just aggregated, so it measures what the verification costs, not whether the harness's tally is
right: the expected-tally comparison after decryption is the correctness check.

Verification 9 gets its own phase in the record, `VerifyTally` (`PhaseNames.VerifyTally`), like every
other optional phase -- its wall time and allocations used to be attributed to nowhere while still
inflating `memory.totalAllocatedBytes`, which made it invisible to a reader of the record. Each
chunk's accumulation, and the final comparison, are billed to it. Like `EncryptBallots`, `VerifyBallots`
and `Tally`, its budget is checked at chunk boundaries, and exhausting it stops the run there with
`notes.VerifyTally` set to `aborted:budgetExceeded`. That is a change: when Verification 9 ran once
after the loop, its budget bounded only itself, and encryption and decryption still completed. It now
follows `VerifyBallots`, the other optional verification, whose budget has always stopped the run, so
a tripped `VerifyTally` budget also truncates `EncryptBallots`, skips `DecryptTally` and leaves
correctness `incomplete`. No shipped scenario budgets `VerifyTally`.

Two consequences for `compare` against records made before Verification 9 streamed:

- Turning `tallyVerification` on in `medium.json` and `large.json` changed their config hash, which
  covers the resolved `phases`, so `compare` reports earlier `medium` and `large` records as
  incomparable. For a like-for-like comparison against that history, run the candidate with
  `--no-tally-verification`, which restores the old hash.
- `VerifyTally`'s allocation per ballot now grows with the number of chunks. Each chunk's
  accumulation builds per-worker partial tallies, which the one-shot verification paid once per run
  and the streamed one pays once per chunk, as `Tally` always has. The cost per call scales with the
  manifest's choice count and the worker count: about 2 MB on `xsmall`'s manifest, about 8 MB on
  `famous-names-large` at 32 workers, where `small`'s `VerifyTally` went from 884 to 4,066
  bytes/ballot and now matches `Tally` to within 0.5%. Expect
  `compare` to flag a `VerifyTally` allocation regression against older `smoke`, `xsmall` and `small`
  records (their config hashes are unchanged); rebaseline those rather than read it as a regression.

`notes.tallyVerification` records whether a verdict was reached:

- `ran` -- every chunk was accumulated and the final comparison executed.
- `aborted:budgetExceeded` -- Verification 9's own budget tripped.
- `skipped:runAborted` -- another phase's budget stopped the run first.

A run that throws leaves it unset; `notes.error` says why. The `VerifyTally` phase key appears once
Verification 9 has started, with the first chunk, and is absent if the run stopped before then or
`tallyVerification` is off. Whenever the comparison did not run, the phase is marked `aborted`, even
when another phase's budget stopped the run: its time is a partial accumulation with no verdict, and
must not be compared as the cost of Verification 9. (`Tally`, by contrast, is not marked when another
phase aborts the run -- it measured exactly the chunks it was given.)

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
