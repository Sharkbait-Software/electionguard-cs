using Xunit;

// The tests redirect Console.Out and Console.Error, which are process-wide.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
