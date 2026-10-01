using Xunit;

// EGParameters is process-wide static state. Most test classes re-initialize it with the same
// default parameters, which is harmless however it interleaves, so this assembly ran in parallel
// safely for a long time. The Montgomery tests are the first here to use EGParameters.OverrideScope
// with a genuinely different p and q - deliberately tiny values, to exercise the limb arithmetic at
// a hand-checkable size and to prove that precomputed tables are not reused across parameter sets.
//
// Those scopes are visible to every other class running at the same time. Left parallel,
// IntegerModQTests computing 6 * 7 would intermittently see q = 13 from a neighbouring scope and
// assert 3 instead of 42. CLAUDE.md describes swapping in a different parameter set as an intended
// testing technique (ParameterVerification depends on it), so this will keep coming up.
//
// ElectionGuard.Perf.UnitTests already disables parallelization for the same reason. The two
// assemblies still run concurrently with each other, so the cost to the full suite is modest.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
