export const meta = {
  name: 'spec-fix-stage',
  description: 'Run one spec-compliance fix stage: optional KAT oracle extension, implement under gate, 3-lens review, fix loop',
  phases: [
    { title: 'Oracle', detail: 'extend the spec-only KAT oracle (only when the stage adds/changes hash formulas)' },
    { title: 'Implement', detail: 'single implementer in the worktree, gate before re-pin' },
    { title: 'Review', detail: 'spec / code / tests lenses' },
    { title: 'Fix', detail: 'apply confirmed findings, re-run gate; repeat while blockers/majors remain' },
  ],
}

const S = args
const WT = 'C:\\code\\other\\electionguard-cs\\.claude\\worktrees\\spec-audit-2026-10-04'
const TMP = 'C:\\Users\\Sethc\\.claude\\jobs\\848c7bdd\\tmp'
const SPEC_TXT = TMP + '\\EG_Spec_2_1.txt'
const PAGES = TMP + '\\pages'
const AUDIT = WT + '\\docs\\spec-compliance\\2026-10-04-spec-audit.md'
const TRACKER = WT + '\\docs\\spec-compliance\\2026-10-04-fix-progress.md'

const SPEC_HELP = `Spec v2.1.0 text: ${SPEC_TXT} (pages delimited by "===== PAGE N =====", N = printed page). The text drops overbars/subscripts/hats and renders "_" as spaces in typewriter strings; for any symbol-level detail Read the page image ${PAGES}\\pNNN.png (3-digit page). §5.5 domain-separation tables are on pp.73-78; consolidated verification steps §6.2 pp.80-99.`

const GATE = `GATE (run from ${WT}, Release):
 1. dotnet build electionguard-cs.sln -c Release   -> 0 errors (report warnings)
 2. dotnet run -c Release --project perf/ElectionGuard.Perf.Cli -- run --scenario smoke   -> must print "correctness passed"
 3. dotnet run -c Release --project src/ElectionGuard.InMemory.Console   -> must run all verifications and print/write the decrypted tally (C:\\temp\\eg\\data\\1\\tally.json; 3 ballots all selecting 0-0 => 0-0:3, 0-1:0). A trailing Console.ReadKey InvalidOperationException under redirected stdin is expected.
 4. dotnet test electionguard-cs.sln -c Release --no-build   -> all pass`

const RULES = `RULES:
- Work ONLY in the git worktree ${WT}; absolute paths always (shell cwd may reset). Do NOT commit or push (the orchestrator does). Do not edit files outside the worktree except C:\\temp\\eg\\data (console gate input) when a model change forces it -- keep a .bak and report it.
- Read the tracker ${TRACKER} first: the "Decisions" section holds binding user decisions (Q1-Q9) -- follow them exactly. Read the full detail sections of your G-items in ${AUDIT}.
- The spec is the source of truth (CLAUDE.md). ${SPEC_HELP}
- USER REQUIREMENT on pinned values: make code changes first; then run the GATE and confirm the end-to-end pipeline still encrypts, verifies, tallies and decrypts to the expected tally BEFORE updating any pinned test expectation that broke. Record the verbatim gate lines (and the list of failing tests at that moment) in gate_before_repin. Prefer pinning to spec-derived KAT values (${WT}\\test\\kat\\vectors.json via KnownAnswerTests) over re-capturing new output. Never weaken, skip or delete a test without stating why.
- If you hit a NEW spec contradiction or a genuine design question that the Decisions section does not answer and the spec does not settle, do NOT guess on anything that changes interoperable bytes or security semantics: implement everything else, and list the question in questions_for_user with the options and your recommendation. For low-stakes API-shape choices, decide, and record the choice in the tracker.
- When adding a field to an encrypted-ballot type, add it to BOTH the domain type and the protobuf DTO (and JSON) (CLAUDE.md).
- Respect CLAUDE.md performance rules (MontgomeryModP.PowModP for full-width Z_q exponents, variable-time helpers verifier-only on public values, maxDegreeOfParallelism plumbing). If a hot path changes, compare smoke ms/ballot and alloc MB against the previous stage's numbers in the tracker and report.
- Update CLAUDE.md where a statement becomes false; keep code style consistent with surrounding code.
- Update the tracker: add a log entry "### <date> — ${S.stage} (...)" ABOVE older entries (newest first, below the "## Log" heading) with what changed per G-ID, gate before/after lines, re-pinned tests and why, decisions taken, carry-overs, and set the stage row status to "done (gate green; awaiting commit)" when the gate is green. Also update the "Pinned-value inventory" if pinned values moved.`

const IMPL_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string' },
    per_gid: { type: 'array', items: { type: 'string' }, description: 'one line per G-ID: what was done, or why not' },
    files_changed: { type: 'array', items: { type: 'string' } },
    gate_before_repin: { type: 'string' },
    repinned: { type: 'array', items: { type: 'string' } },
    gate_after: { type: 'string' },
    perf: { type: 'string', description: 'smoke phase lines vs previous stage' },
    questions_for_user: { type: 'array', items: { type: 'string' } },
    open_issues: { type: 'array', items: { type: 'string' } },
  },
  required: ['summary', 'per_gid', 'files_changed', 'gate_before_repin', 'repinned', 'gate_after', 'perf', 'questions_for_user', 'open_issues'],
}
const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['blocker', 'major', 'minor', 'nit'] },
          location: { type: 'string' },
          problem: { type: 'string' },
          evidence: { type: 'string' },
          suggested_fix: { type: 'string' },
        },
        required: ['severity', 'location', 'problem', 'evidence', 'suggested_fix'],
      },
    },
    verdict: { type: 'string' },
  },
  required: ['findings', 'verdict'],
}

let kat = null
if (S.kat) {
  phase('Oracle')
  kat = await agent(`You maintain an INDEPENDENT spec-only Python known-answer-test oracle for the ElectionGuard v2.1.0 C# library at ${WT}\\test\\kat\\eg_kat.py (outputs ${WT}\\test\\kat\\vectors.json, documented in ${WT}\\test\\kat\\README.md).
CRITICAL ISOLATION RULE: derive everything from the SPEC ONLY. Do NOT open, grep or read any file under ${WT}\\src or any *.cs file anywhere -- the C# code may have bugs you must not reproduce. You may read eg_kat.py/vectors.json/README.md, the spec, and the tracker's Decisions section in ${TRACKER} (binding user decisions on spec contradictions).
${SPEC_HELP}
TASK: extend the oracle with these vector families (keep every existing family and its values unchanged unless you find it is spec-incorrect -- then say so loudly): ${S.kat}
Use deterministic labelled inputs, include all inputs and outputs in vectors.json, record the equation and the B1 length (assert against the §5.5 table length where printed). Run the script, confirm existing vectors are byte-identical to before (diff), and report.`, {
    label: `kat:${S.stage}`, phase: 'Oracle', schema: {
      type: 'object',
      properties: { families_added: { type: 'array', items: { type: 'string' } }, existing_unchanged: { type: 'boolean' }, spec_ambiguities: { type: 'array', items: { type: 'string' } } },
      required: ['families_added', 'existing_unchanged', 'spec_ambiguities'],
    },
  })
}

phase('Implement')
const impl = await agent(`You are the single implementer for stage ${S.stage} (${S.title}) of a spec-compliance fix effort on the C# ElectionGuard repo.
G-ITEMS: ${S.gids.join(', ')}
SCOPE AND GUIDANCE:
${S.scope}
${kat ? `KAT ORACLE was just extended (spec-only): ${JSON.stringify(kat)} -- add/extend KnownAnswerTests to check the new families against the library.` : ''}
${RULES}
${GATE}`, { label: `implement:${S.stage}`, phase: 'Implement', schema: IMPL_SCHEMA })

let lastReport = impl
const allReviews = []
let fixes = []
for (let round = 1; round <= 3; round++) {
  phase('Review')
  const reviewCommon = `Review the UNCOMMITTED stage ${S.stage} (${S.title}; G-items ${S.gids.join(', ')}) changes in the worktree ${WT} (git -C "${WT}" diff; git -C "${WT}" status for new files). READ-ONLY: do not edit anything. ${SPEC_HELP}
Binding user decisions: the "Decisions" section of ${TRACKER}. Audit detail for each G-item: ${AUDIT}.
Stage scope: ${S.scope}
Implementer report (latest): ${JSON.stringify(lastReport)}
Report only real problems with evidence; an empty findings list is a fine answer. Severity: blocker = wrong vs spec/decision, security hole, or broken gate; major = missing part of the scope or a test that cannot catch the bug it claims to; minor/nit otherwise.`
  const reviews = await parallel([
    () => agent(`${reviewCommon}
LENS: SPEC CONFORMANCE. For each G-item check the new code against the spec formulas and lettered verification sub-checks (exact separators, keys, argument order, widths, ranges, failure SubSection labels) and against the Decisions. Recompute anything hash-shaped independently (Python) where feasible.`, { label: `review:spec:${S.stage}:r${round}`, phase: 'Review', schema: REVIEW_SCHEMA }),
    () => agent(`${reviewCommon}
LENS: CODE CORRECTNESS, SECURITY & REGRESSIONS. Look for bugs, unhandled edge cases, secret material reaching variable-time paths, missed call sites (grep for every consumer of changed APIs, including perf/, test/ElectionGuard.Testing.*, src/ElectionGuard.InMemory.Console), serialization gaps (JSON and protobuf), thread-safety, perf regressions in hot paths (CLAUDE.md rules).`, { label: `review:code:${S.stage}:r${round}`, phase: 'Review', schema: REVIEW_SCHEMA }),
    () => agent(`${reviewCommon}
LENS: TEST ADEQUACY & PIN HONESTY. Would each new/changed test fail if its bug were reintroduced? Were pinned expectations replaced with spec-derived values rather than re-captured output? Any test weakened/skipped/deleted? Negative tests for every new verification failure path with the right SubSection? Run: dotnet test "${WT}\\electionguard-cs.sln" -c Release and report the summary.`, { label: `review:tests:${S.stage}:r${round}`, phase: 'Review', schema: REVIEW_SCHEMA }),
  ])
  const findings = reviews.filter(Boolean).flatMap((r, i) => r.findings.map(f => ({ lens: ['spec', 'code', 'tests'][i], round, ...f })))
  allReviews.push(...findings)
  const serious = findings.filter(f => f.severity === 'blocker' || f.severity === 'major')
  const actionable = findings.filter(f => f.severity !== 'nit')
  log(`${S.stage} review round ${round}: ${findings.length} findings (${serious.length} blocker/major)`)
  if (!actionable.length) break
  phase('Fix')
  const fix = await agent(`You are the ${S.stage} implementer again (round ${round}), applying review findings. Judge each finding: fix it, or explain precisely why it is wrong -- do not blindly apply.
FINDINGS: ${JSON.stringify(actionable)}
Previous report: ${JSON.stringify(lastReport)}
${RULES}
${GATE}`, { label: `fix:${S.stage}:r${round}`, phase: 'Fix', schema: IMPL_SCHEMA })
  if (fix) { fixes.push(fix); lastReport = fix }
  if (!serious.length) break
}
return { stage: S.stage, kat, impl, reviews: allReviews, fixes, final: lastReport }
