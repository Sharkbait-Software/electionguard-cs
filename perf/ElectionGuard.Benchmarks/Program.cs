using BenchmarkDotNet.Running;

// dotnet run -c Release --project perf/ElectionGuard.Benchmarks -- --filter '*Verification*'
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);

public partial class Program;
