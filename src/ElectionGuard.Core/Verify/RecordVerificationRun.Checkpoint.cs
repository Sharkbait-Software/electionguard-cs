using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.Tally;
using System.Text.Json;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// The verifier checkpoint (design §6.8): local, trusted state written atomically (a temporary file,
/// then a rename) between batches of the device pass, every <see cref="VerifyAllOptions.CheckpointInterval"/>.
/// It holds the record's identity (the claimed TOC root) and the options', the device pass's position
/// (the device and the next ordinal), that device's section frontier and chain-walker state, the join
/// cursors' positions and frontiers, the TOC entries of the devices done, the Verification 9 partial in
/// standard form (never a raw <c>ModPProduct</c>, whose Montgomery drift is engine-specific), 5.A's key
/// and runs (the buffer spilled as a run), the 11.D contests, the counters, the outcomes and the
/// findings so far. Steps A to C are cheap and deterministic, so a resumed run does them again and
/// then continues the device pass from the checkpoint; the final section roots must equal the claimed
/// TOC's, which shows that what was finished extends what was verified. The encoding is this
/// library's (JSON), not part of the format. A checkpoint for another record or other options, or whose
/// 5.A runs are gone, is deleted and the run starts over. A record without a claimed TOC is never
/// checkpointed: the resumed run does not re-read its verified prefix, and only the TOC root binds it.
/// </summary>
internal sealed partial class RecordVerificationRun
{
    private const int CheckpointVersion = 1;

    private static readonly JsonSerializerOptions CheckpointJson = new() { IncludeFields = false, WriteIndented = false };

    internal sealed class CheckpointState
    {
        public int Version { get; set; }

        public string RecordIdentity { get; set; } = "";

        public string OptionsIdentity { get; set; } = "";

        public int DeviceIndex { get; set; }

        public long NextOrdinal { get; set; }

        public DeviceChainWalker.State? Walker { get; set; }

        public byte[]? Frontier { get; set; }

        public bool HeaderOk { get; set; }

        public Dictionary<long, byte[]> PrefixRoots { get; set; } = [];

        public List<EntryDto> Computed { get; set; } = [];

        public Dictionary<string, JoinCursor.State> Cursors { get; set; } = [];

        public BallotAggregationPartial? Aggregate { get; set; }

        public SpillingIdentifierSet.State? Identifiers { get; set; }

        public List<string> Contests { get; set; } = [];

        public long[] Counters { get; set; } = [];

        public int[] Outcomes { get; set; } = [];

        public List<FindingDto> Findings { get; set; } = [];

        public long FindingsTotal { get; set; }

        public bool Truncated { get; set; }

        public bool Complete { get; set; }

        public List<string> Skipped { get; set; } = [];

        public List<AttestationDto> Attestations { get; set; } = [];

        public List<LocatorDto> BallotsToOpen { get; set; } = [];

        public List<LocatorDto> UncastToRelease { get; set; } = [];

        public int UndecodableCast { get; set; }

        public long ElapsedTicks { get; set; }
    }

    internal sealed record EntryDto(ushort Type, byte[] Key, bool Critical, long ItemCount, byte[] Root);

    internal sealed record LocatorDto(byte[] Device, long Position)
    {
        public static LocatorDto Of(BallotLocator locator) => new(locator.Device.ToBytes(), locator.Position);

        public BallotLocator ToLocator() => new(ElectionRecordReader.DeviceKeyOf(Device), Position);
    }

    internal sealed record FindingDto(int Step, string SubSection, int Verification, ushort? SectionType, byte[]? SectionKey, long? Ordinal, LocatorDto? Locator, string? Identifier, string Message);

    internal sealed record SignatureDto(SignatureStatus Status, string Algorithm, string KeyIdHex, string Message);

    internal sealed record AttestationDto(byte[] Device, AttestationKind? Kind, bool Present, bool ContentsMatch, SignatureDto? Signature, string Message);

    private async ValueTask<CheckpointState?> LoadCheckpointAsync()
    {
        if (_options.CheckpointPath is not { } path || IsBallotCorrectness || !File.Exists(path))
        {
            return null;
        }

        if (!Checkpointing)
        {
            // No claimed TOC: nothing ties a checkpoint's verified prefix to the bytes on disk now.
            DeleteCheckpoint();
            return null;
        }

        CheckpointState? state;
        try
        {
            await using var stream = File.OpenRead(path);
            state = await JsonSerializer.DeserializeAsync<CheckpointState>(stream, CheckpointJson, _ct).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            state = null;
        }

        // A checkpoint for another record or other options, or whose 5.A runs are gone or damaged, is
        // deleted and the run starts over.
        if (state is null || state.Version != CheckpointVersion || state.RecordIdentity != RecordIdentity() || state.OptionsIdentity != OptionsIdentity()
            || (state.Identifiers?.Runs ?? []).Any(run => !File.Exists(run) || new FileInfo(run).Length % sizeof(ulong) != 0))
        {
            DeleteCheckpoint();
            return null;
        }

        // Runs a stopped run spilled after its last checkpoint belong to no checkpoint.
        string directory = path + ".5a";
        if (Directory.Exists(directory))
        {
            var kept = (state.Identifiers?.Runs ?? []).Select(Path.GetFullPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var file in Directory.EnumerateFiles(directory))
            {
                if (!kept.Contains(Path.GetFullPath(file)))
                {
                    File.Delete(file);
                }
            }
        }

        return state;
    }

    /// <summary>Restores what step D and the report need from <paramref name="state"/>; returns the device in progress, if any.</summary>
    private DeviceContext? ApplyCheckpoint(CheckpointState state)
    {
        _findings.Restore(state.Findings.Select(x => (x.Step, new VerificationFinding(
            x.SubSection, x.Verification,
            x.SectionType is { } type ? new SectionKey((RecordSectionType)type, x.SectionKey ?? []) : null,
            x.Ordinal, x.Locator?.ToLocator(), x.Identifier, x.Message))), state.FindingsTotal, state.Truncated);
        _outcomes.Import(state.Outcomes);
        _counters.Import(state.Counters);
        _complete &= state.Complete;
        foreach (var skipped in state.Skipped)
        {
            Skipped(skipped);
        }

        foreach (var contest in state.Contests)
        {
            _contestsOnSubmittedBallots.TryAdd(contest, true);
        }

        lock (_computed)
        {
            foreach (var entry in state.Computed)
            {
                if (!_computed.Any(x => x.Type == (RecordSectionType)entry.Type && x.Key.Span.SequenceEqual(entry.Key)))
                {
                    _computed.Add(new TocEntry((RecordSectionType)entry.Type, entry.Key, entry.Critical, entry.ItemCount, Sha256Digest.FromBytes(entry.Root)));
                }
            }
        }

        if (state.Aggregate is { } aggregate)
        {
            _aggregators.Add(BallotAggregationVerifier.ImportStandardForm(_record!.Manifest, aggregate));
        }

        _attestationResults.AddRange(state.Attestations.Select(x => new AttestationResult(
            ElectionRecordReader.DeviceKeyOf(x.Device), x.Kind, x.Present, x.ContentsMatch,
            x.Signature is { } s ? new SignatureCheck(s.Status, s.Algorithm, s.KeyIdHex, s.Message) : null, x.Message)));
        _ballotsToOpen.AddRange(state.BallotsToOpen.Select(x => x.ToLocator()));
        _uncastToRelease.AddRange(state.UncastToRelease.Select(x => x.ToLocator()));
        _undecodableCast = state.UndecodableCast;
        _elapsedBefore = TimeSpan.FromTicks(state.ElapsedTicks);

        if (state.Walker is null || state.DeviceIndex >= _reader.Devices.Count)
        {
            return null;
        }

        var device = NewDevice(state.DeviceIndex, _reader.Devices[state.DeviceIndex]);
        device.Walker.Import(state.Walker);
        device.Frontier = MerkleFrontier.Deserialize(state.Frontier ?? []);
        device.HeaderOk = state.HeaderOk;
        foreach (var (count, root) in state.PrefixRoots)
        {
            device.PrefixRoots[count] = Sha256Digest.FromBytes(root);
        }

        return device;
    }

    /// <summary>Writes the checkpoint at a batch boundary: the device pass continues at <paramref name="deviceIndex"/>, ordinal <paramref name="nextOrdinal"/>, of <paramref name="inProgress"/> when it is mid-section.</summary>
    private async ValueTask WriteCheckpointAsync(DeviceContext? inProgress, int deviceIndex, long nextOrdinal)
    {
        string path = _options.CheckpointPath!;
        var aggregate = Runs(9) && _record is not null ? MergedAggregator().ExportStandardForm() : null;
        var state = new CheckpointState
        {
            Version = CheckpointVersion,
            RecordIdentity = RecordIdentity(),
            OptionsIdentity = OptionsIdentity(),
            DeviceIndex = deviceIndex,
            NextOrdinal = nextOrdinal,
            Walker = inProgress?.Walker.Export(),
            Frontier = inProgress?.Frontier.Serialize(),
            HeaderOk = inProgress?.HeaderOk ?? false,
            PrefixRoots = inProgress?.PrefixRoots.ToDictionary(x => x.Key, x => x.Value.ToArray()) ?? [],
            Computed = _computed.Where(x => x.Type == RecordSectionType.Device).Select(x => new EntryDto((ushort)x.Type, x.Key.ToArray(), x.Critical, x.ItemCount, x.Root.ToArray())).ToList(),
            Cursors = new[] { _requestCursor, _challengedCursor, _contestDataCursor, _releaseCursor }
                .OfType<JoinCursor>()
                .ToDictionary(x => ((ushort)x.Section.Type).ToString(System.Globalization.CultureInfo.InvariantCulture), x => x.Export()),
            Aggregate = aggregate,
            Identifiers = _identifiers?.Checkpoint(),
            Contests = [.. _contestsOnSubmittedBallots.Keys.Order(StringComparer.Ordinal)],
            Counters = _counters.Export(),
            Outcomes = _outcomes.Export(),
            Findings = _findings.All().Select(x => new FindingDto(
                x.Step, x.Finding.SubSection, x.Finding.Verification,
                x.Finding.Section is { } s ? (ushort)s.Type : null, x.Finding.Section?.Key.ToArray(),
                x.Finding.Ordinal, x.Finding.Locator is { } l ? LocatorDto.Of(l) : null, x.Finding.SelectionEncryptionIdentifierHex, x.Finding.Message)).ToList(),
            FindingsTotal = _findings.Total,
            Truncated = _findings.Truncated,
            Complete = _complete,
            Skipped = [.. _skipped.Keys],
            Attestations = _attestationResults.Select(x => new AttestationDto(x.Device.ToBytes(), x.Kind, x.Present, x.ContentsMatch,
                x.Signature is { } s ? new SignatureDto(s.Status, s.Algorithm, s.KeyIdHex, s.Message) : null, x.Message)).ToList(),
            BallotsToOpen = _ballotsToOpen.Select(LocatorDto.Of).ToList(),
            UncastToRelease = _uncastToRelease.Select(LocatorDto.Of).ToList(),
            UndecodableCast = _undecodableCast,
            ElapsedTicks = (_elapsedBefore + _clock.Elapsed).Ticks,
        };

        string temporary = path + ".tmp";
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await JsonSerializer.SerializeAsync(stream, state, CheckpointJson, _ct).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>Deletes the checkpoint and its 5.A runs (a run that completed, or a checkpoint that does not apply).</summary>
    private void DeleteCheckpoint()
    {
        if (_options.CheckpointPath is not { } path)
        {
            return;
        }

        File.Delete(path);
        File.Delete(path + ".tmp");
        if (Directory.Exists(path + ".5a"))
        {
            _identifiers?.Dispose();
            _identifiers = null;
            Directory.Delete(path + ".5a", recursive: true);
        }
    }

    /// <summary>
    /// Whether this run writes and resumes checkpoints: a checkpoint path is set, the profile is not
    /// ballot correctness, and the record has a claimed TOC. The TOC root is the record's identity:
    /// a resumed run does not re-read the prefix it verified, so for a record without one (a live
    /// record) nothing would tie that prefix to the bytes on disk, and such a run always starts over
    /// (as the writer has nothing to resume without a TOC).
    /// </summary>
    private bool Checkpointing => _options.CheckpointPath is not null && !IsBallotCorrectness && _reader.ClaimedToc is not null;

    private string RecordIdentity() => $"toc:{_reader.ClaimedToc!.Root}:{_reader.Phase}";

    private string OptionsIdentity() =>
        $"{_options.Profile}|{string.Join(",", _profile.Order())}|{_options.MaxFindings}|{_options.SignaturePolicy}|{string.Join(";", _options.SignatureVerifiers.Select(x => $"{x.Algorithm}={x.TrustAnchorsIdentity}"))}|{_options.ExpectedSetupRoot}|{_options.ExpectedSealedRoot}|{_options.ExpectedAggregatedRoot}|{_options.ExpectedFinalRoot}";
}
