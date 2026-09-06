using Xunit;

// EGParameters (src/ElectionGuard.Core/Models/EGParameters.cs) is a process-wide static holder
// that many tests re-initialize via EGParameters.Init(...) in their constructors (see CLAUDE.md).
// xUnit's default behavior runs test classes in different collections in parallel on separate
// threads, which races against this shared mutable static state -- e.g. one test class calling
// EGParameters.Init(...) can replace the singleton ParameterBaseHash instance out from under
// another test that is mid-assertion against the previous instance. Disabling test
// parallelization keeps the whole suite deterministic without touching any individual test's
// logic.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
