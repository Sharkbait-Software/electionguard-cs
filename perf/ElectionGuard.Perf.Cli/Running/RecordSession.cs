using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;

namespace ElectionGuard.Perf.Cli.Running;

/// <summary>
/// The election record a scenario writes as it runs (the <c>WriteRecord</c> phase, design §8.5):
/// a phase-gated <see cref="ElectionRecordWriter"/> in a temporary directory, one
/// <see cref="DeviceSectionWriter"/> per simulated device. The runner is synchronous, and nothing
/// here has a synchronization context to deadlock on, so the asynchronous writer is driven to
/// completion call by call. The directory is deleted on dispose.
/// </summary>
internal sealed class RecordSession : IDisposable
{
    private readonly ElectionRecordWriter _writer;
    private readonly DeviceSectionWriter[] _devices;
    private bool _writerDisposed;

    private RecordSession(string directory, ElectionRecordWriter writer, DeviceSectionWriter[] devices)
    {
        Directory = directory;
        _writer = writer;
        _devices = devices;
    }

    public string Directory { get; }

    public RecordEncoding Encoding => _writer.Encoding;

    /// <summary>The phase roots the writer returned, in phase order.</summary>
    public Dictionary<RecordPhase, Sha256Digest> PhaseRoots { get; } = [];

    /// <summary>Creates the record and writes its setup (§3.1) and every device's header.</summary>
    public static RecordSession Create(EncryptionRecord record, IReadOnlyList<string> deviceIds, RecordEncoding encoding)
    {
        string directory = Path.Combine(Path.GetTempPath(), "egperf-records", $"{DateTime.UtcNow:yyyyMMddTHHmmss}-{Guid.NewGuid():N}");
        var writer = ElectionRecord.Create(directory, encoding);
        try
        {
            var setup = Wait(writer.WriteSetupAsync(record));
            var devices = deviceIds.Select(id => Wait(writer.OpenDeviceAsync(id, DeviceChainBallotKind.Encrypted))).ToArray();
            var session = new RecordSession(directory, writer, devices);
            session.PhaseRoots[RecordPhase.Setup] = setup.Root;
            return session;
        }
        catch
        {
            Wait(writer.DisposeAsync());
            DeleteDirectory(directory);
            throw;
        }
    }

    /// <summary>Appends a ballot (its status recorded) to device <paramref name="device"/>'s section.</summary>
    public void Append(EncryptedBallot ballot, int device) => Wait(_devices[device].AppendAsync(ballot));

    /// <summary>Closes every device's chain, seals voting and seals the aggregate with <paramref name="tally"/> (no contest-data requests).</summary>
    public void SealAggregated(EncryptedTally tally, DateTimeOffset closedAt)
    {
        foreach (var device in _devices)
        {
            Wait(device.CloseAsync(closedAt));
            Wait(device.DisposeAsync());
        }

        PhaseRoots[RecordPhase.Sealed] = Wait(_writer.SealVotingAsync()).Root;
        PhaseRoots[RecordPhase.Aggregated] = Wait(_writer.SealAggregatedAsync(tally, [])).Root;
    }

    /// <summary>Completes the record with the decrypted tally (the final phase).</summary>
    public void Complete(DecryptedTally tally) => PhaseRoots[RecordPhase.Final] = Wait(_writer.CompleteAsync(tally)).Root;

    /// <summary>Releases the writer's files, so that the record can be read.</summary>
    public void CloseWriter()
    {
        if (!_writerDisposed)
        {
            _writerDisposed = true;
            Wait(_writer.DisposeAsync());
        }
    }

    /// <summary>The record's size on disk, in bytes.</summary>
    public long Bytes => new DirectoryInfo(Directory).EnumerateFiles("*", SearchOption.AllDirectories).Sum(x => x.Length);

    /// <summary>
    /// Verifies the record from disk: <see cref="ElectionRecordVerifier.VerifyAllAsync"/> with the full
    /// profile over a final record, or, for a record that ends at its aggregated phase (no decryption),
    /// the guardians' preliminary profile (<see cref="ElectionRecordVerifier.VerifyAggregatedAsync"/>,
    /// §3.6.1), which the full profile refuses to run on.
    /// </summary>
    public VerificationReport Verify(int maxDegreeOfParallelism)
    {
        CloseWriter();
        return Wait(VerifyAsync(maxDegreeOfParallelism));
    }

    private async Task<VerificationReport> VerifyAsync(int maxDegreeOfParallelism)
    {
        await using var reader = await ElectionRecord.OpenAsync(Directory);
        var options = new VerifyAllOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
        if (reader.Phase >= RecordPhase.Final)
        {
            return await ElectionRecordVerifier.VerifyAllAsync(reader, options);
        }

        var (report, aggregate) = await ElectionRecordVerifier.VerifyAggregatedAsync(reader, options);
        return aggregate is null && report.Passed ? report with { Passed = false } : report;
    }

    public void Dispose()
    {
        try
        {
            CloseWriter();
        }
        finally
        {
            DeleteDirectory(Directory);
        }
    }

    private static void DeleteDirectory(string directory)
    {
        try
        {
            if (System.IO.Directory.Exists(directory))
            {
                System.IO.Directory.Delete(directory, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static T Wait<T>(ValueTask<T> task) => task.IsCompletedSuccessfully ? task.Result : task.AsTask().GetAwaiter().GetResult();

    private static T Wait<T>(Task<T> task) => task.GetAwaiter().GetResult();

    private static void Wait(ValueTask task)
    {
        if (!task.IsCompletedSuccessfully)
        {
            task.AsTask().GetAwaiter().GetResult();
        }
    }
}
