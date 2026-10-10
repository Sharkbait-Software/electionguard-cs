using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Tally;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// The verify-everything entry point of the election record (design §6, §8.3; S10b-9): Verifications
/// 1-19 and every record-level rule over a record opened with <see cref="ElectionRecord.OpenAsync(string, CancellationToken)"/>,
/// in the design's step order (A record, B setup, C join preparation, D the device pass, E the tally,
/// F completion), streaming: memory is bounded by the batch of items in flight, Verification 5.A's
/// budget (it spills beyond it, design §6.5) and per-device and per-field state, never by the number
/// of ballots.
///
/// Findings are collected (not stop-on-first) and ordered deterministically: by step, then canonical
/// record order, then sub-section. Each carries the spec's sub-section ("6.D", "13.structure") or a
/// record-level code ("R.root"; <see cref="RecordCodes"/>) and where it is. The verifications are the
/// existing classes, reached through their record-item entry points (design §4.8); a value out of
/// range is reported once, under its code, and leaves the verifications that would have read it not
/// evaluable on that item.
/// </summary>
public static class ElectionRecordVerifier
{
    /// <summary>
    /// Verifies <paramref name="record"/> under <paramref name="options"/> (<see cref="VerifyAllOptions"/>;
    /// the full profile by default). With <see cref="VerifyAllOptions.CheckpointPath"/> set, a run that
    /// was stopped (killed, cancelled) continues from its last checkpoint and gives the same report.
    /// </summary>
    public static async Task<VerificationReport> VerifyAllAsync(IElectionRecordReader record, VerifyAllOptions? options = null,
        IProgress<VerificationProgress>? progress = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        var run = new RecordVerificationRun(record, options ?? new VerifyAllOptions(), progress, ct);
        return (await run.RunAsync().ConfigureAwait(false)).Report;
    }

    /// <summary>
    /// §3.6.1, before guardians decrypt: the <see cref="VerificationProfile.GuardianPreliminary"/>
    /// run over the record's aggregated prefix. When it passes, with Verification 9 passed (not merely
    /// not failed), it returns the <see cref="VerifiedAggregate"/>: the encrypted tally it verified,
    /// with R_aggregated, which <see cref="TallyAdmin.Decrypt(IReadOnlyList{TallyGuardian}, VerifiedAggregate, int)"/>
    /// requires, and the guardians' view of the sealed record's cast and spoiled ballots (Q31, "Refuse
    /// spoiled too"), built by a second read of the device sections that is digested and must give
    /// exactly the section roots the run verified: a record changed in between is <c>R.root</c> and
    /// yields no aggregate. Set <see cref="VerifyAllOptions.ExpectedAggregatedRoot"/> to the root
    /// obtained out of band, so the guardians decrypt exactly what they verified (Q36).
    /// </summary>
    public static async Task<(VerificationReport Report, VerifiedAggregate? Aggregate)> VerifyAggregatedAsync(IElectionRecordReader record, VerifyAllOptions options,
        IProgress<VerificationProgress>? progress = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(options);
        var run = new RecordVerificationRun(record, options with { Profile = VerificationProfile.GuardianPreliminary }, progress, ct);
        var (report, tally, encryptionRecord, computed) = await run.RunAsync().ConfigureAwait(false);
        if (!report.Passed || tally is null || encryptionRecord is null
            || report.Verifications[9] != VerificationOutcome.Passed
            || !report.PhaseRoots.TryGetValue(RecordPhase.Aggregated, out var root))
        {
            return (report, null);
        }

        var changed = new List<SectionKey>();
        var published = await ReadPublishedBallotsAsync(record, encryptionRecord.ExtendedBaseHash, (section, count, sectionRoot) =>
        {
            var verified = computed.FirstOrDefault(x => x.Type == section.Type && x.Key.Span.SequenceEqual(section.Key.Span));
            if (verified is null || verified.ItemCount != count || verified.Root != sectionRoot)
            {
                changed.Add(section);
            }
        }, ct).ConfigureAwait(false);

        if (changed.Count > 0)
        {
            var findings = changed.Select(section => new VerificationFinding(RecordCodes.Root, 0, section, null, null, null,
                $"Device section {section} read for the guardians' view of the cast and spoiled ballots is not the section the run verified: its root changed after verification (Q31, Q36). No aggregate is returned."));
            return (report with { Passed = false, Findings = [.. report.Findings, .. findings] }, null);
        }

        return (report, new VerifiedAggregate(encryptionRecord, tally, root, published));
    }

    /// <summary>
    /// The guardians' view of a sealed record's cast and spoiled ballots (<see cref="IPublishedCastAndSpoiledBallots"/>),
    /// from the parsed items with their raw values (<see cref="PublishedCastAndSpoiledBallots.Add(BallotStatus, ReadOnlySpan{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>),
    /// so a ballot whose values are out of range is held too: regular ballots recorded cast or spoiled,
    /// and cast pre-encrypted ballots. Reads every device section once. Verify the record first.
    /// </summary>
    public static Task<PublishedCastAndSpoiledBallots> ReadPublishedBallotsAsync(IElectionRecordReader record, ExtendedBaseHash extendedBaseHash, CancellationToken ct = default) =>
        ReadPublishedBallotsAsync(record, extendedBaseHash, null, ct);

    /// <summary>
    /// <see cref="ReadPublishedBallotsAsync(IElectionRecordReader, ExtendedBaseHash, CancellationToken)"/>,
    /// digesting each device section whole (header and close included) and handing its item count and
    /// root to <paramref name="onSection"/>; a section that fails to read is handed count -1.
    /// </summary>
    private static async Task<PublishedCastAndSpoiledBallots> ReadPublishedBallotsAsync(IElectionRecordReader record, ExtendedBaseHash extendedBaseHash,
        Action<SectionKey, long, Sha256Digest>? onSection, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(record);
        var view = new PublishedCastAndSpoiledBallots(extendedBaseHash);
        foreach (var device in record.Devices)
        {
            var section = SectionKey.Device(device);
            var frontier = new MerkleFrontier();
            try
            {
                await foreach (var raw in record.ReadSectionAsync(section, 0, ct).ConfigureAwait(false))
                {
                    frontier.Append(raw.Bytes.Span);
                    if (raw.Ordinal > 0)
                    {
                        Hold(view, raw);
                    }
                }
            }
            catch (VerificationFailedException) when (onSection is not null)
            {
                onSection(section, -1, default);
                continue;
            }

            onSection?.Invoke(section, frontier.Count, frontier.Root());
        }

        return view;
    }

    private static void Hold(PublishedCastAndSpoiledBallots view, RecordItemBytes raw)
    {
        Pb.RecordItem item;
        try
        {
            item = Pb.RecordItem.Parser.ParseFrom(raw.Bytes.Span);
        }
        catch (Google.Protobuf.InvalidProtocolBufferException)
        {
            return;
        }

        (BallotStatus Status, Google.Protobuf.ByteString IdB, Google.Protobuf.ByteString HI, Pb.HashedCiphertext? Nonce)? held = item.ItemCase switch
        {
            Pb.RecordItem.ItemOneofCase.EncryptedBallot when item.EncryptedBallot.Status is Pb.BallotStatus.Cast or Pb.BallotStatus.Spoiled =>
                ((BallotStatus)(int)item.EncryptedBallot.Status, item.EncryptedBallot.IdB, item.EncryptedBallot.HI, item.EncryptedBallot.EncryptedBallotNonce),
            Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot =>
                (BallotStatus.Cast, item.PreEncryptedCastBallot.IdB, item.PreEncryptedCastBallot.HI, item.PreEncryptedCastBallot.EncryptedBallotNonce),
            _ => null,
        };

        if (held is { } ballot && ballot.IdB.Length == 32 && ballot.HI.Length == 32)
        {
            var c0 = ballot.Nonce?.C0;
            view.Add(ballot.Status, ballot.IdB.Span, ballot.HI.Span, c0 is { Length: 512 } ? c0.Span : []);
        }
    }
}

/// <summary>
/// An encrypted tally that passed Verification 9 against the cast ballots of a record whose
/// aggregated prefix passed the <see cref="VerificationProfile.GuardianPreliminary"/> profile (design
/// §6.9). It exists only as <see cref="ElectionRecordVerifier.VerifyAggregatedAsync"/>'s result, so
/// the decryption bounds read back with a tally (its published cast weights) have been checked before
/// <see cref="TallyAdmin.Decrypt(IReadOnlyList{TallyGuardian}, VerifiedAggregate, int)"/> uses them
/// (the S10a carry-over: a tally read back must not be decrypted before Verification 9).
/// </summary>
public sealed class VerifiedAggregate
{
    internal VerifiedAggregate(EncryptionRecord encryptionRecord, EncryptedTally encryptedTally, Sha256Digest aggregatedRoot, PublishedCastAndSpoiledBallots publishedBallots)
    {
        EncryptionRecord = encryptionRecord;
        EncryptedTally = encryptedTally;
        AggregatedRoot = aggregatedRoot;
        PublishedBallots = publishedBallots;
    }

    /// <summary>The election the record's setup describes (its claims passed Verifications 1-4).</summary>
    public EncryptionRecord EncryptionRecord { get; }

    /// <summary>The encrypted tally that passed Verification 9. Treat it as read-only.</summary>
    public EncryptedTally EncryptedTally { get; }

    /// <summary>R_aggregated of the verified record.</summary>
    public Sha256Digest AggregatedRoot { get; }

    /// <summary>The sealed record's cast and spoiled ballots, for the guardians' Q31 check before opening a challenged ballot.</summary>
    public PublishedCastAndSpoiledBallots PublishedBallots { get; }
}
