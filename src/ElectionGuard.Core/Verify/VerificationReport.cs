using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.Verify;

/// <summary>What a record verification run checks (design §6.9).</summary>
public enum VerificationProfile
{
    /// <summary>A final record: Verifications 1-19 and every record-level rule.</summary>
    Full,

    /// <summary>
    /// §3.6.1, before guardians decrypt: an aggregated (or later) record's aggregated prefix, with
    /// Verifications 1-9, 15 and 16 (on pre-encrypted ballots spec p.64 checks confirmation codes by
    /// Verification 16 in place of 8, and accumulated selection vectors by 15 with 7; both are
    /// NotApplicable without a pre-encrypting device) and the contest-data request rules. A passed run yields the
    /// <see cref="VerifiedAggregate"/> that tally decryption from a record requires.
    /// </summary>
    GuardianPreliminary,

    /// <summary>Chosen ballots (<see cref="VerifyAllOptions.Ballots"/>): their per-ballot verifications and an inclusion proof each.</summary>
    BallotCorrectness,

    /// <summary>A chosen subset of Verifications 1-19 (<see cref="VerifyAllOptions.Verifications"/>), every record-level rule included.</summary>
    Custom,
}

/// <summary>
/// What a missing or invalid signature does to the verdict (design §4.9, user decision #7: "Report"
/// is the default; "RequireValid" is recommended for official verification).
/// </summary>
public enum SignaturePolicy
{
    /// <summary>Signatures are not checked or reported; statement contents still are (<c>R.attestation</c>).</summary>
    Ignore,

    /// <summary>Signatures are checked against the configured verifiers and reported; a missing or invalid one is not a failure.</summary>
    Report,

    /// <summary>
    /// A device without a valid chain-close attestation, a record without a valid signature over its
    /// phase root, and any signature that is invalid or cannot be checked, are failures
    /// (<c>R.attestation</c>, <c>R.signature</c>).
    /// </summary>
    RequireValid,
}

/// <summary>The outcome of one numbered verification over a record (design §6.9).</summary>
public enum VerificationOutcome
{
    /// <summary>It ran on every item it applies to, and nothing failed.</summary>
    Passed,

    /// <summary>At least one of its checks failed (see the findings).</summary>
    Failed,

    /// <summary>The record holds nothing it applies to (for example Verifications 15-19 without a pre-encrypting device).</summary>
    NotApplicable,

    /// <summary>It could not be evaluated on some item, because of an earlier failure or a finding of another verification on the item.</summary>
    NotEvaluable,

    /// <summary>Outside the profile. A decode or structure finding under its code is still reported (design §4.8), and fails the run, without making the outcome Failed.</summary>
    NotRun,
}

/// <summary>The options of <see cref="ElectionRecordVerifier.VerifyAllAsync"/> (design §8.3).</summary>
public sealed record VerifyAllOptions
{
    public VerificationProfile Profile { get; init; } = VerificationProfile.Full;

    /// <summary><see cref="VerificationProfile.Custom"/>: the verifications to run, a subset of 1..19.</summary>
    public IReadOnlySet<int>? Verifications { get; init; }

    /// <summary><see cref="VerificationProfile.BallotCorrectness"/>: the ballots to verify.</summary>
    public IReadOnlyCollection<BallotLocator>? Ballots { get; init; }

    /// <summary>Passed to every parallel stage (the item workers, Verifications 9 and 10); 1 is a true single-threaded run.</summary>
    public int MaxDegreeOfParallelism { get; init; } = -1;

    /// <summary>Verification 5.A's in-memory budget before it spills sorted runs to disk (design §6.5).</summary>
    public long UniquenessMemoryBudgetBytes { get; init; } = 256L << 20;

    /// <summary>Where 5.A's runs go; the system's temporary directory when null (a checkpoint keeps its own next to it).</summary>
    public string? TempDirectory { get; init; }

    /// <summary>
    /// When set, the run is resumable: its state is written here atomically every
    /// <see cref="CheckpointInterval"/> (between batches of items) and read back by a later run with
    /// the same record and options, which continues where it stopped. A checkpoint holds verdicts and
    /// the 5.A key: it is local, trusted state and must never be accepted from anyone else (design §6.8).
    /// The file and its runs are deleted when the run completes. A record without a claimed TOC is
    /// never checkpointed (its identity would not bind the verified prefix), so its run starts over.
    /// </summary>
    public string? CheckpointPath { get; init; }

    public TimeSpan CheckpointInterval { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Stop at the first failure (findings are collected by default).</summary>
    public bool StopOnFirstFailure { get; init; }

    /// <summary>The most findings reported; the first ones in the report's order are kept.</summary>
    public int MaxFindings { get; init; } = 10_000;

    /// <summary>The bound, in bytes, of the items read ahead and held while their batch is verified (at least one item).</summary>
    public long BatchBytes { get; init; } = 64L << 20;

    public SignaturePolicy SignaturePolicy { get; init; } = SignaturePolicy.Report;

    /// <summary>The trust anchors: one verifier per algorithm, each holding the public keys it accepts.</summary>
    public IReadOnlyList<ISignatureVerifier> SignatureVerifiers { get; init; } = [];

    /// <summary>R_setup obtained out of band (a device pins it); a record whose setup root differs fails <c>R.root</c>.</summary>
    public Sha256Digest? ExpectedSetupRoot { get; init; }

    public Sha256Digest? ExpectedSealedRoot { get; init; }

    /// <summary>R_aggregated obtained out of band, so guardians decrypt exactly what they verified (Q36).</summary>
    public Sha256Digest? ExpectedAggregatedRoot { get; init; }

    public Sha256Digest? ExpectedFinalRoot { get; init; }
}

/// <summary>
/// One failure (design §6.9): its sub-section ("6.D", "13.structure", "R.order"), the verification
/// number (0 for a record-level R-code), where it is (the section, the item's ordinal in it, the
/// ballot's locator and id_B when it concerns a ballot) and a message.
/// </summary>
public sealed record VerificationFinding(
    string SubSection,
    int Verification,
    SectionKey? Section,
    long? Ordinal,
    BallotLocator? Locator,
    string? SelectionEncryptionIdentifierHex,
    string Message);

/// <summary>Whether a statement's signature was checked, and how it came out.</summary>
public enum SignatureStatus
{
    /// <summary>A configured verifier for its algorithm holds the key, and the signature verifies.</summary>
    Valid,

    /// <summary>A configured verifier holds the key, and the signature does not verify.</summary>
    Invalid,

    /// <summary>No configured verifier for its algorithm, or none holds its key: "present, not checked" (design §4.9).</summary>
    NotChecked,

    /// <summary>The policy is <see cref="SignaturePolicy.Ignore"/>.</summary>
    Ignored,
}

/// <summary>The result of checking one signed statement's signature.</summary>
public sealed record SignatureCheck(SignatureStatus Status, string Algorithm, string KeyIdHex, string Message);

/// <summary>What a device attestation statement is (the <c>RecordItem</c> member it holds).</summary>
public enum AttestationKind
{
    ChainClose,
    SectionSeal,
    PrefixCheckpoint,
}

/// <summary>
/// One device attestation, or the absence of the recommended chain-close attestation (design §4.9):
/// whether its contents agree with the record (they are always checked, whatever the policy), and its
/// signature check.
/// </summary>
public sealed record AttestationResult(DeviceKey Device, AttestationKind? Kind, bool Present, bool ContentsMatch, SignatureCheck? Signature, string Message);

/// <summary>One detached record signature (§3.7, "together with the date"): its phase, whether its statement matches the record, and its signature check.</summary>
public sealed record RecordSignatureResult(RecordPhase? Phase, string SignerRole, DateTimeOffset? SignedAt, bool ContentsMatch, SignatureCheck Signature, string Message);

/// <summary>Counts over the record (design §6.9, "Also reported").</summary>
public sealed record RecordStatistics
{
    public long BallotItems { get; init; }

    public long Cast { get; init; }

    public long Challenged { get; init; }

    public long Spoiled { get; init; }

    public long PreEncryptedCast { get; init; }

    public long UncastFull { get; init; }

    /// <summary>Compact uncast items: the items whose 17.A and 19.A-D held by construction (§3.2: the record holds no printed codes or labels for them).</summary>
    public long UncastCompact { get; init; }

    public long Devices { get; init; }

    public long VendorSections { get; init; }

    public long ItemsDigested { get; init; }

    public long BytesDigested { get; init; }
}

/// <summary>Where one chosen ballot sits under the record root (<see cref="VerificationProfile.BallotCorrectness"/>): RFC 9162 inclusion proofs from its leaf to its section root and from its section's TOC entry to the root.</summary>
public sealed record BallotInclusion(BallotLocator Locator, Sha256Digest LeafHash, long SectionSize, IReadOnlyList<Sha256Digest> SectionPath, Sha256Digest SectionRoot, long TocIndex, long TocSize, IReadOnlyList<Sha256Digest> TocPath, Sha256Digest Root);

/// <summary>
/// The result of a record verification (design §6.9). <see cref="Passed"/> means no failures
/// (user decision R-2, "Pass, flagged incomplete"); <see cref="Complete"/> is reported beside it and
/// is false when the reader skipped content of a newer format minor (<see cref="SkippedUnknownContent"/>).
/// A command line exits 0 when passed and complete, 2 when passed but incomplete, 1 on any failure.
/// Two runs over the same record with the same options give equal reports whatever the parallelism,
/// representation or resumption, apart from <see cref="Elapsed"/>.
/// </summary>
public sealed record VerificationReport
{
    public required bool Passed { get; init; }

    public required bool Complete { get; init; }

    public required VerificationProfile Profile { get; init; }

    /// <summary>The phase verified: the record's, or a guardian run's aggregated prefix of a later record.</summary>
    public required RecordPhase Phase { get; init; }

    public required RecordFormatVersion RecordFormat { get; init; }

    public required RecordFormatVersion ReaderFormat { get; init; }

    /// <summary>The phase roots recomputed from the record, for the phases it holds.</summary>
    public required IReadOnlyDictionary<RecordPhase, Sha256Digest> PhaseRoots { get; init; }

    /// <summary>Whether the recomputed TOC equals the claimed one (false without a claimed TOC).</summary>
    public required bool RootsMatchClaimedToc { get; init; }

    /// <summary>Verifications 1..19.</summary>
    public required IReadOnlyDictionary<int, VerificationOutcome> Verifications { get; init; }

    public required IReadOnlyList<VerificationFinding> Findings { get; init; }

    /// <summary>More findings existed than <see cref="VerifyAllOptions.MaxFindings"/>, or the run stopped at the first failure.</summary>
    public required bool Truncated { get; init; }

    public required IReadOnlyList<AttestationResult> Attestations { get; init; }

    public required IReadOnlyList<RecordSignatureResult> Signatures { get; init; }

    public required IReadOnlyList<string> SkippedUnknownContent { get; init; }

    public required RecordStatistics Statistics { get; init; }

    /// <summary><see cref="VerificationProfile.GuardianPreliminary"/>: the challenged regular ballots the guardians will open (§3.6.7), in record order.</summary>
    public IReadOnlyList<BallotLocator> BallotsToOpen { get; init; } = [];

    /// <summary><see cref="VerificationProfile.GuardianPreliminary"/>: the uncast pre-encrypted ballots that need a nonce release, in record order.</summary>
    public IReadOnlyList<BallotLocator> UncastBallotsToRelease { get; init; } = [];

    /// <summary><see cref="VerificationProfile.BallotCorrectness"/>: each chosen ballot's inclusion proofs.</summary>
    public IReadOnlyList<BallotInclusion> Inclusions { get; init; } = [];

    /// <summary>Wall-clock time of the run (of all its resumed parts); the one value two equal runs do not share.</summary>
    public TimeSpan Elapsed { get; init; }
}

/// <summary>Progress of a run: the step and the ballot items verified so far.</summary>
public sealed record VerificationProgress(string Step, long ItemsVerified);
