using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.KeyGeneration;
using ElectionGuard.Core.Verify.Tally;
using System.Collections.Concurrent;
using System.Diagnostics;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// One run of <see cref="ElectionRecordVerifier.VerifyAllAsync"/> (design §6.1): the steps in order,
/// the findings, the outcomes and the state a checkpoint saves. The device pass is in
/// <c>RecordVerificationRun.Devices.cs</c>, the checkpoint in <c>RecordVerificationRun.Checkpoint.cs</c>.
/// </summary>
internal sealed partial class RecordVerificationRun
{
    // Steps (design §6.1): the first key of the findings' order.
    private const int StepRecord = 1, StepSetup = 2, StepJoinPrep = 3, StepBallots = 4, StepTally = 5, StepCompletion = 6;

    private readonly IElectionRecordReader _reader;
    private readonly VerifyAllOptions _options;
    private readonly IProgress<VerificationProgress>? _progress;
    private readonly CancellationToken _ct;
    private readonly FindingSet _findings;
    private readonly Outcomes _outcomes;
    private readonly HashSet<int> _profile;
    private readonly RecordPhase _phaseCap;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly ConcurrentDictionary<string, string> _skipped = new(StringComparer.Ordinal);
    private readonly List<TocEntry> _computed = [];
    private readonly List<AttestationResult> _attestationResults = [];
    private readonly List<RecordSignatureResult> _signatureResults = [];
    private readonly ConcurrentDictionary<string, bool> _contestsOnSubmittedBallots = new(StringComparer.Ordinal);
    private readonly ConcurrentBag<BallotAggregationVerifier> _aggregators = [];
    private readonly Counters _counters = new();
    private readonly List<BallotLocator> _ballotsToOpen = [];
    private readonly List<BallotLocator> _uncastToRelease = [];
    private readonly List<BallotInclusion> _inclusions = [];
    private readonly HashSet<BallotLocator>? _selected;

    private EncryptionRecord? _record;
    private bool _cryptography;
    private bool _complete = true;
    private bool _stopped;
    private TimeSpan _elapsedBefore;
    private SpillingIdentifierSet? _identifiers;
    private Dictionary<DeviceKey, List<Attestation>> _attestations = [];
    private RecordDecoded<EncryptedTally>? _encryptedTally;
    private int _undecodableCast;

    public RecordVerificationRun(IElectionRecordReader reader, VerifyAllOptions options, IProgress<VerificationProgress>? progress, CancellationToken ct)
    {
        _reader = reader;
        _options = options;
        _progress = progress;
        _ct = ct;
        if (options.MaxFindings < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxFindings is at least 1.");
        }

        _findings = new FindingSet(options.MaxFindings);
        _profile = options.Profile switch
        {
            VerificationProfile.Full => [.. Enumerable.Range(1, 19)],
            // §3.6.1 names Verifications 4-9; on pre-encrypted ballots p.64 replaces Verification 8 by
            // 16 and requires 15 with 7 (a selection vector may be accumulated). Both are
            // NotApplicable on a record without a pre-encrypting device.
            VerificationProfile.GuardianPreliminary => [.. Enumerable.Range(1, 9), 15, 16],
            VerificationProfile.BallotCorrectness => [5, 6, 7, 8, 13, 14, 15, 16, 17, 18, 19],
            VerificationProfile.Custom => options.Verifications is { } set && set.All(x => x is >= 1 and <= 19)
                ? [.. set]
                : throw new ArgumentException("A custom profile names a subset of Verifications 1..19.", nameof(options)),
            _ => throw new ArgumentOutOfRangeException(nameof(options), options.Profile, null),
        };

        if (options.Profile == VerificationProfile.BallotCorrectness)
        {
            _selected = options.Ballots is { Count: > 0 } ballots
                ? [.. ballots]
                : throw new ArgumentException("The ballot correctness profile names the ballots to verify.", nameof(options));
        }

        _outcomes = new Outcomes(_profile);
        _phaseCap = options.Profile == VerificationProfile.GuardianPreliminary ? RecordPhase.Aggregated : RecordPhase.Final;
    }

    private bool IsBallotCorrectness => _selected is not null;

    private bool Runs(int verification) => _profile.Contains(verification);

    /// <summary>The record's phase as far as this profile reads it.</summary>
    private RecordPhase Phase => _reader.Phase < _phaseCap ? _reader.Phase : _phaseCap;

    private int Parallelism => _options.MaxDegreeOfParallelism > 0 ? _options.MaxDegreeOfParallelism : Environment.ProcessorCount;

    /// <summary>
    /// Runs the steps and returns the report, the encrypted tally and the election it verified (when
    /// it read them), and the TOC entries it recomputed from the bytes it verified.
    /// </summary>
    public async Task<(VerificationReport Report, EncryptedTally? Tally, EncryptionRecord? Record, IReadOnlyList<TocEntry> Computed)> RunAsync()
    {
        bool completed = false;
        try
        {
            var resumed = await LoadCheckpointAsync().ConfigureAwait(false);
            await StepRecordAsync().ConfigureAwait(false);
            await StepSetupAsync().ConfigureAwait(false);
            if (!Stop())
            {
                await StepDevicesAsync(resumed).ConfigureAwait(false);
            }

            if (!Stop())
            {
                await StepTallyAsync().ConfigureAwait(false);
            }

            if (!Stop())
            {
                await StepCompletionAsync().ConfigureAwait(false);
            }

            var report = BuildReport();
            DeleteCheckpoint();
            completed = true;
            List<TocEntry> computed;
            lock (_computed)
            {
                computed = [.. _computed];
            }

            return (report, _encryptedTally?.Value, _record, computed);
        }
        finally
        {
            // A run that stopped with a checkpoint leaves its 5.A runs for the run that resumes it.
            if (completed || !Checkpointing)
            {
                _identifiers?.Dispose();
            }

            foreach (var cursor in new[] { _requestCursor, _challengedCursor, _contestDataCursor, _releaseCursor })
            {
                if (cursor is not null)
                {
                    await cursor.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private bool Stop() => _stopped || (_stopped = _options.StopOnFirstFailure && _findings.Total > 0);

    // ---- findings and outcomes ------------------------------------------------------------------

    private void Report(int step, string subSection, string message, SectionKey? section = null, long? ordinal = null, BallotLocator? locator = null, string? identifier = null)
    {
        int verification = VerificationOf(subSection);
        _outcomes.Fail(verification);
        _findings.Add(step, new VerificationFinding(subSection, verification, section, ordinal, locator, identifier, message));
    }

    private static int VerificationOf(string subSection)
    {
        int dot = subSection.IndexOf('.');
        return dot > 0 && int.TryParse(subSection.AsSpan(0, dot), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int v) ? v : 0;
    }

    /// <summary>
    /// Runs verification <paramref name="verification"/> by <paramref name="check"/>: a failure is a
    /// finding (unless it is a finding of <paramref name="decoded"/>, which was reported when the item
    /// was decoded), a <see cref="RecordItemNotEvaluableException"/> leaves it not evaluable, and any
    /// other exception of a verification on a malformed item is its <c>N.structure</c>.
    /// </summary>
    private void Check(int verification, int step, Action check, Where where, params IRecordDecoded[] decoded)
    {
        if (!Runs(verification))
        {
            return;
        }

        if (!_cryptography)
        {
            _outcomes.NotEvaluable(verification);
            return;
        }

        _outcomes.Ran(verification);
        try
        {
            check();
        }
        catch (VerificationFailedException ex)
        {
            if (decoded.Any(x => x.Findings.Any(f => f.SubSection == ex.SubSection && f.Message == ex.Message)))
            {
                _outcomes.Fail(VerificationOf(ex.SubSection));
            }
            else
            {
                Report(step, ex.SubSection, ex.Message, where.Section, where.Ordinal, where.Locator, where.Identifier);
            }
        }
        catch (RecordItemNotEvaluableException)
        {
            _outcomes.NotEvaluable(verification);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or KeyNotFoundException or IndexOutOfRangeException or FormatException or OverflowException)
        {
            Report(step, $"{verification}.{BallotStructure.SubSectionSuffix}", $"Verification {verification} could not be evaluated on a malformed item: {ex.Message}", where.Section, where.Ordinal, where.Locator, where.Identifier);
        }
    }

    /// <summary>
    /// Reports every decode finding of an item once, under its code, whether or not its owner runs on
    /// the item (design §4.8), and marks each of <paramref name="readers"/> (the verifications that
    /// would read the item) failed when the finding is its own and not evaluable otherwise. Returns
    /// whether the item decoded without a finding.
    /// </summary>
    private bool Decoded(IRecordDecoded decoded, int step, Where where, params int[] readers) => Decoded(decoded, step, _ => where, readers);

    /// <summary><see cref="Decoded(IRecordDecoded, int, Where, int[])"/>, each finding placed by <paramref name="where"/> (a joined object spans two items).</summary>
    private bool Decoded(IRecordDecoded decoded, int step, Func<RecordFinding, Where> where, params int[] readers)
    {
        if (decoded.IsEvaluable)
        {
            return true;
        }

        foreach (var finding in decoded.Findings)
        {
            var at = where(finding);
            Report(step, finding.SubSection, finding.Message, at.Section, at.Ordinal, at.Locator, at.Identifier);
        }

        foreach (var verification in readers)
        {
            if (Runs(verification) && !decoded.Findings.Any(x => x.Verification == verification))
            {
                _outcomes.NotEvaluable(verification);
            }
        }

        return false;
    }

    /// <summary>Where a finding is: the section, the item's ordinal, the ballot's locator and id_B.</summary>
    private readonly record struct Where(SectionKey? Section, long? Ordinal, BallotLocator? Locator, string? Identifier)
    {
        public static Where Of(SectionKey section, long ordinal) => new(section, ordinal, null, null);
    }

    private void Skipped(string what) => _skipped.TryAdd(what, what);

    // ---- step A: the record ---------------------------------------------------------------------

    private async ValueTask StepRecordAsync()
    {
        // Layout, framing of the setup and the header, the format major and the presence rules were
        // checked when the record was opened (R.container, R.version, R.structure); a failure there
        // stops before any verification, as design §6.1 step A says.
        if (_reader.Format.Minor > RecordFormatVersion.Library.Minor)
        {
            _complete = false;
            Skipped($"The record is EGRF {_reader.Format.Major}.{_reader.Format.Minor}; this verifier reads {RecordFormatVersion.Library.Major}.{RecordFormatVersion.Library.Minor} and verifies what it understands (NQ-1, R-2).");
        }

        var needed = _options.Profile switch
        {
            VerificationProfile.Full => RecordPhase.Final,
            VerificationProfile.GuardianPreliminary => RecordPhase.Aggregated,
            _ => RecordPhase.Setup,
        };

        if (_reader.Phase < needed)
        {
            Report(StepRecord, RecordCodes.Structure, $"The {_options.Profile} profile verifies a record at phase {needed} or later; this record is at phase {_reader.Phase} (design §6.9).");
        }

        if (_reader is ElectionRecordReader own)
        {
            try
            {
                var manifest = await ReadManifestBytesAsync().ConfigureAwait(false);
                if (manifest is not null)
                {
                    await own.CheckManifestCopyAsync(manifest, _ct).ConfigureAwait(false);
                }
            }
            catch (VerificationFailedException ex)
            {
                Report(StepRecord, ex.SubSection, ex.Message, SectionKey.Of(RecordSectionType.Manifest), 0);
            }
        }
    }

    private async ValueTask<byte[]?> ReadManifestBytesAsync()
    {
        await foreach (var item in _reader.ReadSectionAsync(SectionKey.Of(RecordSectionType.Manifest), 0, _ct).ConfigureAwait(false))
        {
            if (item.Check.IsCanonical && Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span) is { ItemCase: Pb.RecordItem.ItemOneofCase.ManifestFile } parsed)
            {
                return parsed.ManifestFile.Content.ToByteArray();
            }
        }

        return null;
    }

    // ---- step B: the setup ----------------------------------------------------------------------

    private async ValueTask StepSetupAsync()
    {
        Progress("setup", 0);
        (RecordSectionType Type, Pb.RecordItem.ItemOneofCase Member, bool Many)[] sections =
        [
            (RecordSectionType.Header, Pb.RecordItem.ItemOneofCase.RecordHeader, false),
            (RecordSectionType.Parameters, Pb.RecordItem.ItemOneofCase.Parameters, false),
            (RecordSectionType.Manifest, Pb.RecordItem.ItemOneofCase.ManifestFile, false),
            (RecordSectionType.Guardians, Pb.RecordItem.ItemOneofCase.GuardianPublicKey, true),
            (RecordSectionType.ElectionKeys, Pb.RecordItem.ItemOneofCase.ElectionKeys, false),
        ];

        var items = new List<Pb.RecordItem>();
        bool readable = true;
        foreach (var (type, member, many) in sections)
        {
            var section = SectionKey.Of(type);
            int count = 0;
            await DigestAsync(section, item =>
            {
                count++;
                if (!item.Check.IsCanonical)
                {
                    readable = false;
                    Report(StepSetup, RecordCodes.Encoding, $"Item {item.Ordinal} of section {section} is not canonical ({item.Check.Rule}): {item.Check.Message}", section, item.Ordinal);
                    return;
                }

                NoteUnknownContent(item.Check, section);
                var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
                if (parsed.ItemCase != member)
                {
                    readable = false;
                    Report(StepSetup, RecordCodes.Structure, $"Section {section} holds item member {(int)parsed.ItemCase}; it holds {member} items only (§4.5).", section, item.Ordinal);
                    return;
                }

                items.Add(parsed);
            }).ConfigureAwait(false);

            if (many ? count == 0 : count != 1)
            {
                readable = false;
                Report(StepSetup, RecordCodes.Structure, $"Section {section} holds {count} items; it holds {(many ? "one or more" : "exactly one")} (§4.5).", section);
            }
        }

        if (!readable)
        {
            foreach (var verification in _profile.Where(x => x <= 4))
            {
                _outcomes.NotEvaluable(verification);
            }

            NoCryptography();
            return;
        }

        var decoded = SetupMapper.FromItems(items);
        foreach (var finding in decoded.Findings)
        {
            Report(StepSetup, finding.SubSection, finding.Message, SectionKey.Of(SectionOfSetupItem(finding.Item)));
        }

        // Verifications 1-3 through their record entry points (design §4.8): each is not evaluable
        // only when a finding is on an item it reads.
        _cryptography = true;
        Check(1, StepSetup, () => new ParameterVerification().Verify(decoded), Where.Of(SectionKey.Of(RecordSectionType.Parameters), 0), decoded);
        bool parametersPass = !_outcomes.HasFailed(1) && !_outcomes.IsNotEvaluable(1);

        // The manifest, parsed from the stored bytes by its media type (design §4.6).
        var setup = decoded.ValueReading([SetupMapper.ParametersItem, "manifest_file", SetupMapper.ElectionKeysItem]);
        bool manifestParses = false;
        if (setup is not null)
        {
            if (setup.ManifestMediaType != RecordSetup.ManifestMediaTypeFormat1)
            {
                Report(StepSetup, RecordCodes.Version, $"The manifest's media type is \"{setup.ManifestMediaType}\"; this verifier reads \"{RecordSetup.ManifestMediaTypeFormat1}\" (design §4.6).", SectionKey.Of(RecordSectionType.Manifest), 0);
            }
            else
            {
                try
                {
                    _record = setup.ToEncryptionRecord();
                    manifestParses = true;
                }
                catch (InvalidManifestException ex)
                {
                    Report(StepSetup, "1.structure", $"The stored manifest is not a manifest under its media type, so no ballot can be read: {ex.Message}", SectionKey.Of(RecordSectionType.Manifest), 0);
                }
            }
        }

        Check(2, StepSetup, () => new GuardianPublicKeyVerification().Verify(decoded), Where.Of(SectionKey.Of(RecordSectionType.Guardians), 0), decoded);
        Check(3, StepSetup, () => new ElectionPublicKeyVerification().Verify(decoded), Where.Of(SectionKey.Of(RecordSectionType.ElectionKeys), 0), decoded);
        bool extendedBaseHashPasses = false;
        if (setup is not null && Runs(4))
        {
            _outcomes.Ran(4);
            try
            {
                new ExtendedBaseHashVerification().Verify(setup.ExtendedBaseHash, setup.ElectionBaseHash, setup.Keys);
                extendedBaseHashPasses = true;
            }
            catch (VerificationFailedException ex)
            {
                Report(StepSetup, ex.SubSection, ex.Message, SectionKey.Of(RecordSectionType.ElectionKeys), 0);
            }
        }
        else if (setup is not null)
        {
            extendedBaseHashPasses = true;
        }
        else
        {
            _outcomes.NotEvaluable(4);
        }

        // Design §6.1 step B: a V1 failure, an unparseable manifest or a V4 failure stops all
        // cryptography; digests and structure still run to the end.
        if (!(parametersPass || !Runs(1)) || !manifestParses || !extendedBaseHashPasses)
        {
            NoCryptography();
        }
    }

    private void NoCryptography()
    {
        _cryptography = false;
        foreach (var verification in _profile.Where(x => x >= 5))
        {
            _outcomes.NotEvaluable(verification);
        }
    }

    private static RecordSectionType SectionOfSetupItem(string? item) => item switch
    {
        SetupMapper.GuardianItem => RecordSectionType.Guardians,
        SetupMapper.ElectionKeysItem => RecordSectionType.ElectionKeys,
        "manifest_file" => RecordSectionType.Manifest,
        _ => RecordSectionType.Parameters,
    };

    private void NoteUnknownContent(CanonicalCheck check, SectionKey section)
    {
        if (check.HasUnknownContent)
        {
            _complete = false;
            Skipped($"Section {section} holds content of a newer format minor (unknown fields, item types or enum values), digested but not verified (§7).");
        }
    }

    /// <summary>Reads a whole section, digesting every item into its TOC entry, and hands each item to <paramref name="onItem"/>.</summary>
    private async ValueTask DigestAsync(SectionKey section, Action<RecordItemBytes> onItem)
    {
        if (!_reader.Sections.Contains(section))
        {
            return;
        }

        var frontier = new MerkleFrontier();
        try
        {
            await foreach (var item in _reader.ReadSectionAsync(section, 0, _ct).ConfigureAwait(false))
            {
                frontier.Append(item.Bytes.Span);
                _counters.Digest(item.Bytes.Length);
                onItem(item);
            }
        }
        catch (VerificationFailedException ex)
        {
            // A carrier or line failure mid-section (R.container, R.encoding): the section's root is unknown.
            Report(StepRecord, ex.SubSection, ex.Message, section);
            return;
        }

        AddEntry(section, frontier);
    }

    private void AddEntry(SectionKey section, MerkleFrontier frontier)
    {
        lock (_computed)
        {
            _computed.Add(new TocEntry(section.Type, section.Key.Span, ElectionRecord.CriticalBitOf(_reader, section), frontier.Count, frontier.Root()));
        }
    }

    private void Progress(string step, long items) => _progress?.Report(new VerificationProgress(step, items));

    // ---- step E: the tally ----------------------------------------------------------------------

    private async ValueTask StepTallyAsync()
    {
        if (Phase < RecordPhase.Aggregated || IsBallotCorrectness)
        {
            return;
        }

        Progress("tally", _counters.BallotItems);
        var tallySection = SectionKey.Of(RecordSectionType.EncryptedTally);
        Pb.EncryptedTallyHeader? header = null;
        var contests = new List<Pb.EncryptedTallyContest>();
        bool readable = true;
        await DigestAsync(tallySection, item =>
        {
            if (!item.Check.IsCanonical)
            {
                readable = false;
                Report(StepTally, RecordCodes.Encoding, $"Item {item.Ordinal} of section {tallySection} is not canonical ({item.Check.Rule}): {item.Check.Message}", tallySection, item.Ordinal);
                return;
            }

            NoteUnknownContent(item.Check, tallySection);
            var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
            if (item.Ordinal == 0 && parsed.ItemCase == Pb.RecordItem.ItemOneofCase.EncryptedTallyHeader)
            {
                header = parsed.EncryptedTallyHeader;
            }
            else if (item.Ordinal > 0 && parsed.ItemCase == Pb.RecordItem.ItemOneofCase.EncryptedTallyContest)
            {
                contests.Add(parsed.EncryptedTallyContest);
            }
            else
            {
                readable = false;
                Report(StepTally, RecordCodes.Structure, $"Item {item.Ordinal} of section {tallySection} is member {(int)parsed.ItemCase}; the section holds an encrypted_tally_header, then encrypted_tally_contest items (§4.5).", tallySection, item.Ordinal);
            }
        }).ConfigureAwait(false);

        if (header is null && readable)
        {
            readable = false;
            Report(StepTally, RecordCodes.Structure, $"Section {tallySection} has no encrypted_tally_header (§4.5).", tallySection);
        }

        if (_record is null || !_cryptography)
        {
            // No election to read the tallies against (design §6.1 step B's gate): digested only.
            foreach (var verification in new[] { 9, 10, 11 }.Where(Runs))
            {
                _outcomes.NotEvaluable(verification);
            }

            if (Phase >= RecordPhase.Final)
            {
                await DigestAsync(SectionKey.Of(RecordSectionType.DecryptedTally), _ => { }).ConfigureAwait(false);
            }

            return;
        }

        if (readable)
        {
            _encryptedTally = TallyMapper.FromItems(header!, contests, _record.Manifest);
            Decoded(_encryptedTally, StepTally, Where.Of(tallySection, 0), 9, 10);
        }

        // Verification 9: the merged recount against the claimed tally (design §6.1 step E).
        var recount = MergedAggregator();
        if (Runs(9))
        {
            if (!_cryptography || _encryptedTally is null || !readable)
            {
                _outcomes.NotEvaluable(9);
            }
            else if (_undecodableCast > 0 || recount.IsFaulted)
            {
                // A cast ballot with a finding has no factor in the recount, and a ballot that broke the
                // recount's structure faulted it (design §6.2): never reported as passed.
                _outcomes.NotEvaluable(9);
            }
            else
            {
                Check(9, StepTally, () => recount.Verify(RecordItemGate.Require(_encryptedTally, 9)), Where.Of(tallySection, 0), _encryptedTally);
            }
        }

        // The header against the recount: R.summary, beside Verification 9's outcome, never as it.
        if (_cryptography && _encryptedTally?.Value is { } tally && _undecodableCast == 0 && !recount.IsFaulted && Runs(9))
        {
            try
            {
                recount.VerifySummary(tally);
            }
            catch (VerificationFailedException ex)
            {
                Report(StepTally, ex.SubSection, ex.Message, tallySection, 0);
            }
        }

        if (Phase < RecordPhase.Final)
        {
            return;
        }

        var decryptedSection = SectionKey.Of(RecordSectionType.DecryptedTally);
        var decryptedContests = new List<Pb.DecryptedTallyContest>();
        bool decryptedReadable = true;
        await DigestAsync(decryptedSection, item =>
        {
            if (!item.Check.IsCanonical)
            {
                decryptedReadable = false;
                Report(StepTally, RecordCodes.Encoding, $"Item {item.Ordinal} of section {decryptedSection} is not canonical ({item.Check.Rule}): {item.Check.Message}", decryptedSection, item.Ordinal);
                return;
            }

            NoteUnknownContent(item.Check, decryptedSection);
            var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
            if (parsed.ItemCase == Pb.RecordItem.ItemOneofCase.DecryptedTallyContest)
            {
                decryptedContests.Add(parsed.DecryptedTallyContest);
            }
            else
            {
                decryptedReadable = false;
                Report(StepTally, RecordCodes.Structure, $"Item {item.Ordinal} of section {decryptedSection} is member {(int)parsed.ItemCase}; the section holds decrypted_tally_contest items only (§4.5).", decryptedSection, item.Ordinal);
            }
        }).ConfigureAwait(false);

        if (!decryptedReadable || _record is null)
        {
            _outcomes.NotEvaluable(10);
            _outcomes.NotEvaluable(11);
            return;
        }

        var decrypted = TallyMapper.FromItems(decryptedContests);
        Decoded(decrypted, StepTally, Where.Of(decryptedSection, 0), 10, 11);
        if (_encryptedTally is null)
        {
            _outcomes.NotEvaluable(10);
        }
        else
        {
            var encrypted = _encryptedTally;
            Check(10, StepTally, () => new TallyDecryptionVerification().Verify(_record, encrypted, decrypted, _options.MaxDegreeOfParallelism), Where.Of(decryptedSection, 0), encrypted, decrypted);
        }

        var contestIds = _contestsOnSubmittedBallots.Keys.ToList();
        Check(11, StepTally, () => new TallyContentsVerification().Verify(_record.Manifest, decrypted, contestIds), Where.Of(decryptedSection, 0), decrypted);
    }

    private BallotAggregationVerifier MergedAggregator()
    {
        var parts = new List<BallotAggregationVerifier>();
        while (_aggregators.TryTake(out var part))
        {
            parts.Add(part);
        }

        var merged = _record is null ? null : new BallotAggregationVerifier(_record.Manifest);
        foreach (var part in parts)
        {
            merged!.Merge(part);
        }

        if (merged is not null)
        {
            _aggregators.Add(merged);
        }

        return merged ?? throw new InvalidOperationException("No election record.");
    }

    // ---- step F: completion ---------------------------------------------------------------------

    private async ValueTask StepCompletionAsync()
    {
        Progress("completion", _counters.BallotItems);

        // 5.A over every ballot item of every kind and status (design §6.5).
        if (_identifiers is not null && Runs(5) && _cryptography && !IsBallotCorrectness)
        {
            var colliding = _identifiers.CollidingPrefixes();
            if (colliding.Count > 0)
            {
                await ConfirmDuplicatesAsync(colliding).ConfigureAwait(false);
            }
        }

        // Every other section (vendor sections; the final sections a guardian run does not read):
        // digested, and a critical vendor section, which nothing here understands, is R.version.
        if (!IsBallotCorrectness)
        {
            foreach (var section in _reader.Sections.Where(x => x.Phase <= Phase && !_computed.Any(e => e.Type == x.Type && e.Key.Span.SequenceEqual(x.Key.Span))))
            {
                await DigestAsync(section, item => NoteUnknownContent(item.Check, section)).ConfigureAwait(false);
                if (RecordSections.IsVendor(section.Type))
                {
                    _counters.Vendor();
                    if (ElectionRecord.CriticalBitOf(_reader, section))
                    {
                        Report(StepCompletion, RecordCodes.Version, $"Vendor section {section} is marked critical: its writer says it must be understood to verify the record, and this verifier does not understand vendor sections (design §7).", section);
                    }
                }
            }
        }

        // The roots: the recomputed TOC against the claimed one (R.root), and the phase roots against
        // any root obtained out of band.
        var computed = new TableOfContents(_computed.Order(Comparer<TocEntry>.Create(TocEntry.CompareSections)));
        if (_reader.ClaimedToc is { } claimed)
        {
            var differences = ElectionRecord.ClaimedTocDifferences(computed.Entries, claimed, IsBallotCorrectness ? null : Phase).ToList();
            if (IsBallotCorrectness)
            {
                // Only the sections this profile read are compared.
                differences = differences.Where(x => computed.Entries.Any(e => e.Type == x.Section.Type && e.Key.Span.SequenceEqual(x.Section.Key.Span))).ToList();
            }

            foreach (var (section, message) in differences)
            {
                Report(StepCompletion, RecordCodes.Root, message, section);
            }

            _rootsMatch = differences.Count == 0;
        }

        if (!IsBallotCorrectness)
        {
            foreach (var phase in Enum.GetValues<RecordPhase>().Where(x => x <= Phase && computed.Entries.Any(e => e.Phase == x)))
            {
                _phaseRoots[phase] = computed.PhaseRoot(phase);
            }

            ExpectRoot(RecordPhase.Setup, _options.ExpectedSetupRoot);
            ExpectRoot(RecordPhase.Sealed, _options.ExpectedSealedRoot);
            ExpectRoot(RecordPhase.Aggregated, _options.ExpectedAggregatedRoot);
            ExpectRoot(RecordPhase.Final, _options.ExpectedFinalRoot);
            await CheckRecordSignaturesAsync().ConfigureAwait(false);
        }
        else
        {
            BuildInclusions(computed);
        }
    }

    private bool _rootsMatch;
    private readonly Dictionary<RecordPhase, Sha256Digest> _phaseRoots = [];

    private void ExpectRoot(RecordPhase phase, Sha256Digest? expected)
    {
        if (expected is not { } root)
        {
            return;
        }

        if (!_phaseRoots.TryGetValue(phase, out var actual) || actual != root)
        {
            Report(StepCompletion, RecordCodes.Root, $"The record's {phase} root is {(_phaseRoots.ContainsKey(phase) ? actual.ToString() : "absent")}, not the expected {root} obtained out of band.");
        }
    }

    /// <summary>Design §6.5 step 4: a second pass over the ballot items, keeping only those whose keyed prefix collided, and an exact comparison.</summary>
    private async ValueTask ConfirmDuplicatesAsync(IReadOnlyList<ulong> colliding)
    {
        // The pass offers what the device pass added: every 32-byte id_B (a non-canonical item's id_B of
        // another width was never added, and is no identifier to compare), up to where a section broke.
        var confirmation = new SpillingIdentifierSet.Confirmation<BallotLocator>(_identifiers!, colliding);
        foreach (var device in _reader.Devices)
        {
            try
            {
                await foreach (var raw in _reader.ReadSectionAsync(SectionKey.Device(device), 1, _ct).ConfigureAwait(false))
                {
                    if (IdentifierOf(raw) is { Length: 32 } identifier)
                    {
                        confirmation.Offer(identifier, new BallotLocator(device, raw.Ordinal));
                    }
                }
            }
            catch (VerificationFailedException)
            {
                // A frame, line or carrier failure in this section: the device pass reported it and
                // added nothing after it, so the confirmation stops there too.
            }
        }

        foreach (var (identifier, places) in confirmation.Duplicates())
        {
            for (int i = 1; i < places.Count; i++)
            {
                Report(StepCompletion, "5.A", $"Duplicate selection encryption identifier detected. {identifier}: the ballots at {string.Join(" and ", places.Select(Describe))} share it.",
                    SectionKey.Device(places[i].Device), places[i].Position, places[i], identifier);
            }
        }

        static string Describe(BallotLocator locator) => $"position {locator.Position} of device {Convert.ToHexStringLower(locator.Device.ToBytes())}";
    }

    /// <summary>id_B of a ballot item (field 1 of every ballot member, design §6.5), or null when the bytes are not a ballot item.</summary>
    private static byte[]? IdentifierOf(RecordItemBytes raw)
    {
        Pb.RecordItem item;
        try
        {
            item = Pb.RecordItem.Parser.ParseFrom(raw.Bytes.Span);
        }
        catch (Google.Protobuf.InvalidProtocolBufferException)
        {
            return null;
        }

        var identifier = item.ItemCase switch
        {
            Pb.RecordItem.ItemOneofCase.EncryptedBallot => item.EncryptedBallot.IdB,
            Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot => item.PreEncryptedCastBallot.IdB,
            Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot => item.PreEncryptedUncastBallot.IdB,
            Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot => item.PreEncryptedCompactUncastBallot.IdB,
            _ => null,
        };

        return identifier is { Length: > 0 } ? identifier.ToByteArray() : null;
    }

    // ---- the report -----------------------------------------------------------------------------

    private VerificationReport BuildReport()
    {
        var outcomes = Enumerable.Range(1, 19).ToDictionary(x => x, _outcomes.Outcome);
        var findings = _findings.Sorted();
        return new VerificationReport
        {
            Passed = _findings.Total == 0,
            Complete = _complete,
            Profile = _options.Profile,
            Phase = Phase,
            RecordFormat = _reader.Format,
            ReaderFormat = RecordFormatVersion.Library,
            PhaseRoots = _phaseRoots,
            RootsMatchClaimedToc = _reader.ClaimedToc is not null && _rootsMatch,
            Verifications = outcomes,
            Findings = findings,
            Truncated = _findings.Truncated || _stopped,
            Attestations = _attestationResults.OrderBy(x => x.Device).ThenBy(x => x.Kind).ThenBy(x => x.Message, StringComparer.Ordinal).ToList(),
            Signatures = _signatureResults.OrderBy(x => x.Phase).ThenBy(x => x.Message, StringComparer.Ordinal).ToList(),
            SkippedUnknownContent = _skipped.Keys.Order(StringComparer.Ordinal).ToList(),
            Statistics = _counters.Snapshot(),
            BallotsToOpen = [.. _ballotsToOpen.Order()],
            UncastBallotsToRelease = [.. _uncastToRelease.Order()],
            Inclusions = [.. _inclusions.OrderBy(x => x.Locator)],
            Elapsed = _elapsedBefore + _clock.Elapsed,
        };
    }

    // ---- small state classes ----------------------------------------------------------------------

    /// <summary>
    /// The findings, kept in the report's order (step, section, ordinal, sub-section, message), at most
    /// <c>max</c> of them: the first in that order, so the kept set does not depend on parallelism.
    /// </summary>
    private sealed class FindingSet(int max)
    {
        private readonly SortedSet<(int Step, VerificationFinding Finding)> _kept = new(Comparer<(int Step, VerificationFinding Finding)>.Create(Compare));
        private readonly object _lock = new();

        public long Total { get; private set; }

        public bool Truncated { get; private set; }

        public void Add(int step, VerificationFinding finding)
        {
            lock (_lock)
            {
                if (_kept.Add((step, finding)))
                {
                    Total++;
                    if (_kept.Count > max)
                    {
                        _kept.Remove(_kept.Max);
                        Truncated = true;
                    }
                }
            }
        }

        public IReadOnlyList<VerificationFinding> Sorted()
        {
            lock (_lock)
            {
                return _kept.Select(x => x.Finding).ToList();
            }
        }

        public IReadOnlyList<(int Step, VerificationFinding Finding)> All()
        {
            lock (_lock)
            {
                return [.. _kept];
            }
        }

        public void Restore(IEnumerable<(int Step, VerificationFinding Finding)> findings, long total, bool truncated)
        {
            lock (_lock)
            {
                foreach (var finding in findings)
                {
                    _kept.Add(finding);
                }

                Total = Math.Max(Total, total);
                Truncated |= truncated;
            }
        }

        private static int Compare((int Step, VerificationFinding Finding) a, (int Step, VerificationFinding Finding) b)
        {
            int c = a.Step.CompareTo(b.Step);
            if (c != 0)
            {
                return c;
            }

            c = (a.Finding.Section is null).CompareTo(b.Finding.Section is null) * -1;
            if (c != 0)
            {
                return c;
            }

            if (a.Finding.Section is { } sa && b.Finding.Section is { } sb && (c = sa.CompareTo(sb)) != 0)
            {
                return c;
            }

            c = (a.Finding.Ordinal ?? -1).CompareTo(b.Finding.Ordinal ?? -1);
            if (c != 0)
            {
                return c;
            }

            c = a.Finding.Verification.CompareTo(b.Finding.Verification);
            if (c != 0)
            {
                return c;
            }

            c = string.CompareOrdinal(a.Finding.SubSection, b.Finding.SubSection);
            return c != 0 ? c : string.CompareOrdinal(a.Finding.Message, b.Finding.Message);
        }
    }

    /// <summary>Per verification: whether it ran on anything, failed, or was not evaluable somewhere. Thread-safe.</summary>
    private sealed class Outcomes(HashSet<int> profile)
    {
        private readonly int[] _flags = new int[20];
        private const int RanFlag = 1, FailedFlag = 2, NotEvaluableFlag = 4;

        public void Ran(int v) => Set(v, RanFlag);

        /// <summary>Marks verification v failed; a record-level R-code (v = 0) marks none, by design: it is a finding of the record, not of a numbered verification.</summary>
        public void Fail(int v) => Set(v, FailedFlag);

        public void NotEvaluable(int v) => Set(v, NotEvaluableFlag);

        public bool HasFailed(int v) => v is >= 1 and <= 19 && (Volatile.Read(ref _flags[v]) & FailedFlag) != 0;

        public bool IsNotEvaluable(int v) => v is >= 1 and <= 19 && (Volatile.Read(ref _flags[v]) & NotEvaluableFlag) != 0;

        public int[] Export() => [.. _flags];

        public void Import(int[] flags)
        {
            for (int v = 0; v < Math.Min(flags.Length, _flags.Length); v++)
            {
                Set(v, flags[v]);
            }
        }

        public VerificationOutcome Outcome(int v)
        {
            // Outside the profile it is NotRun even when a finding names it: a decode or structure
            // finding is reported under its code whatever the profile (design §4.8), and the finding
            // itself fails the run.
            int flags = Volatile.Read(ref _flags[v]);
            return !profile.Contains(v) ? VerificationOutcome.NotRun
                : (flags & FailedFlag) != 0 ? VerificationOutcome.Failed
                : (flags & NotEvaluableFlag) != 0 ? VerificationOutcome.NotEvaluable
                : (flags & RanFlag) != 0 ? VerificationOutcome.Passed
                : VerificationOutcome.NotApplicable;
        }

        private void Set(int v, int flag)
        {
            if (v is < 1 or > 19)
            {
                return;
            }

            int current;
            do
            {
                current = Volatile.Read(ref _flags[v]);
            }
            while ((current | flag) != current && Interlocked.CompareExchange(ref _flags[v], current | flag, current) != current);
        }
    }

    /// <summary>The statistics' counters. Thread-safe.</summary>
    private sealed class Counters
    {
        private long _ballots, _cast, _challenged, _spoiled, _preCast, _uncastFull, _uncastCompact, _devices, _vendor, _items, _bytes;

        public long BallotItems => Interlocked.Read(ref _ballots);

        public void Ballot() => Interlocked.Increment(ref _ballots);

        public void Status(Pb.BallotStatus status)
        {
            switch (status)
            {
                case Pb.BallotStatus.Cast: Interlocked.Increment(ref _cast); break;
                case Pb.BallotStatus.Challenged: Interlocked.Increment(ref _challenged); break;
                case Pb.BallotStatus.Spoiled: Interlocked.Increment(ref _spoiled); break;
            }
        }

        public void PreEncryptedCast() => Interlocked.Increment(ref _preCast);

        public void Uncast(bool compact) => Interlocked.Increment(ref compact ? ref _uncastCompact : ref _uncastFull);

        public void Device() => Interlocked.Increment(ref _devices);

        public void Vendor() => Interlocked.Increment(ref _vendor);

        public void Digest(long bytes)
        {
            Interlocked.Increment(ref _items);
            Interlocked.Add(ref _bytes, bytes);
        }

        public long[] Export() => [_ballots, _cast, _challenged, _spoiled, _preCast, _uncastFull, _uncastCompact, _devices, _vendor, _items, _bytes];

        public void Import(long[] values)
        {
            (_ballots, _cast, _challenged, _spoiled, _preCast, _uncastFull, _uncastCompact, _devices, _vendor, _items, _bytes) =
                (values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8], values[9], values[10]);
        }

        public RecordStatistics Snapshot() => new()
        {
            BallotItems = _ballots,
            Cast = _cast,
            Challenged = _challenged,
            Spoiled = _spoiled,
            PreEncryptedCast = _preCast,
            UncastFull = _uncastFull,
            UncastCompact = _uncastCompact,
            Devices = _devices,
            VendorSections = _vendor,
            ItemsDigested = _items,
            BytesDigested = _bytes,
        };
    }

    /// <summary>A device attestation as read in step C: its ordinal, the signed statement and its parsed statement.</summary>
    private sealed record Attestation(long Ordinal, SignedStatement Signed, Pb.RecordItem Statement);
}
