using System.Runtime;
using System.Runtime.InteropServices;

namespace ElectionGuard.Perf.Cli.Results;

public static class EnvironmentProbe
{
    public static EnvironmentInfo Capture(string? machineIdOverride = null) => new()
    {
        MachineId = RunRecordStore.Slug(machineIdOverride ?? Environment.MachineName),
        Cpu = DescribeCpu(),
        LogicalCores = Environment.ProcessorCount,
        RamGb = (int)Math.Round(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (double)(1024L * 1024 * 1024)),
        Os = RuntimeInformation.OSDescription,
        DotNet = RuntimeInformation.FrameworkDescription,
        GcMode = GCSettings.IsServerGC ? "server" : "workstation",
        BuildConfig = IsDebug ? "Debug" : "Release",
    };

    public static bool IsDebug =>
#if DEBUG
        true;
#else
        false;
#endif

    private static string DescribeCpu()
    {
        var identifier = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER");
        if (!string.IsNullOrWhiteSpace(identifier))
        {
            return identifier.Trim();
        }

        try
        {
            const string cpuInfo = "/proc/cpuinfo";
            if (File.Exists(cpuInfo))
            {
                var modelLine = File.ReadLines(cpuInfo)
                    .FirstOrDefault(x => x.StartsWith("model name", StringComparison.OrdinalIgnoreCase));
                if (modelLine is not null)
                {
                    return modelLine[(modelLine.IndexOf(':') + 1)..].Trim();
                }
            }
        }
        catch (IOException)
        {
            // Best effort only -- an unreadable /proc is not a reason to abandon a run.
        }

        return $"unknown ({RuntimeInformation.ProcessArchitecture})";
    }
}
