using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Tally;
using System.Text.Json;

namespace ElectionGuard.Testing.Common;

/// <summary>
/// Shared bootstrap helper mirroring the guardians -> keys -> shares -> manifest -> ballot ->
/// encrypt -> tally pipeline in src/ElectionGuard.InMemory.Console/Program.cs, so later test
/// classes don't have to re-derive the ~40-line construction sequence.
///
/// EGParameters defaults to the spec's v2.1.0 parameters, so callers need not call
/// EGParameters.Init(...) before using any method here unless a test deliberately needs a
/// non-default parameter set.
///
/// This is a pure fixture helper shared by the unit tests and the performance harness; it has no [Fact]/[Theory] methods of its own.
/// </summary>
public static class ElectionFixtureBuilder
{
    /// <summary>
    /// Result of bootstrapping a full N/K guardian set: generated keys, exchanged/decrypted secret
    /// shares, the resulting election public keys, and a verified GuardianRecord.
    /// </summary>
    public sealed class GuardianSetResult
    {
        public required List<Guardian> Guardians { get; init; }
        public required List<GuardianKeys> GuardianKeys { get; init; }
        public required List<GuardianPublicView> GuardianPublicViews { get; init; }
        public required Dictionary<GuardianIndex, GuardianSecretShares> SecretShares { get; init; }
        public required ElectionPublicKeys ElectionPublicKeys { get; init; }
        public required GuardianRecord GuardianRecord { get; init; }
    }

    /// <summary>
    /// Result of building the ElectionBaseHash/ExtendedBaseHash/EncryptionRecord layer on top of a
    /// GuardianSetResult and a manifest.
    /// </summary>
    public sealed class EncryptionRecordResult
    {
        public required ElectionBaseHash ElectionBaseHash { get; init; }
        public required ExtendedBaseHash ExtendedBaseHash { get; init; }
        public required EncryptionRecord EncryptionRecord { get; init; }
    }

    /// <summary>
    /// Bootstraps a full N-of-K guardian set: generates keys for each guardian, exchanges and
    /// decrypts secret shares across the full set, builds the resulting ElectionPublicKeys, and
    /// verifies the resulting GuardianRecord from every guardian's perspective (mirrors
    /// Program.cs). n and k must match EGParameters.GuardianParameters, which the guardians and
    /// Verification 1 read (the defaults match the default 3-of-2 parameters).
    ///
    /// The guardian record carries the manifest file and H_B, because each guardian checks H_B
    /// (Verification 1.F) and keys its comparison hash H_G with it (§3.2.2 step 1). Pass the
    /// election's manifest file; without one, CreateMinimalManifest()'s is used. A test that then
    /// builds an encryption record over a different manifest gets a guardian record and an
    /// encryption record that disagree about H_B; nothing in the library compares the two.
    /// </summary>
    public static GuardianSetResult CreateGuardianSet(int n = 3, int k = 2, ManifestFile? manifestFile = null)
    {
        manifestFile ??= CreateMinimalManifest().ManifestFile;

        var guardians = new List<Guardian>();
        for (int i = 1; i <= n; i++)
        {
            guardians.Add(new Guardian(new GuardianIndex(i)));
        }

        var guardianKeysList = new List<GuardianKeys>();
        var guardianPublicViews = new List<GuardianPublicView>();
        foreach (var guardian in guardians)
        {
            var keys = guardian.GenerateKeys();
            guardianKeysList.Add(keys);
            guardianPublicViews.Add(keys.ToPublicView());
        }

        var guardianEncryptedShares = new List<GuardianEncryptedShare>();
        foreach (var guardian in guardians)
        {
            var encryptedShares = guardian.EncryptShares(
                guardianPublicViews.Where(x => x.Index != guardian.Index).ToList());
            guardianEncryptedShares.AddRange(encryptedShares);
        }

        var secretShares = new Dictionary<GuardianIndex, GuardianSecretShares>();
        foreach (var guardian in guardians)
        {
            var shares = guardian.DecryptShares(
                guardianEncryptedShares.Where(x => x.DestinationIndex == guardian.Index).ToList());
            secretShares[guardian.Index] = shares;
        }

        var electionPublicKeys = new ElectionPublicKeys(
            guardianPublicViews.Select(x => x.VoteEncryptionCommitments[0]),
            guardianPublicViews.Select(x => x.OtherBallotDataEncryptionCommitments[0]));

        var guardianRecord = new GuardianRecord
        {
            CryptographicParameters = EGParameters.CryptographicParameters,
            GuardianParameters = EGParameters.GuardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile),
            Guardians = guardianPublicViews,
            ElectionPublicKeys = electionPublicKeys,
        };

        foreach (var guardian in guardians)
        {
            guardian.Verify(guardianRecord, manifestFile);
        }

        return new GuardianSetResult
        {
            Guardians = guardians,
            GuardianKeys = guardianKeysList,
            GuardianPublicViews = guardianPublicViews,
            SecretShares = secretShares,
            ElectionPublicKeys = electionPublicKeys,
            GuardianRecord = guardianRecord,
        };
    }

    /// <summary>
    /// The supplemental fields <see cref="CreateMinimalManifest"/> declares by default: the overvote,
    /// null-vote and undervote indicators and the undervote difference count (§3.3.9).
    /// </summary>
    public static readonly IReadOnlyList<SupplementalFieldKind> DefaultSupplementalFields =
    [
        SupplementalFieldKind.OvervoteIndicator,
        SupplementalFieldKind.NullVoteIndicator,
        SupplementalFieldKind.UndervoteIndicator,
        SupplementalFieldKind.UndervoteDifferenceCount,
    ];

    /// <summary>Every supplemental field kind of §3.3.9, in declaration order.</summary>
    public static readonly IReadOnlyList<SupplementalFieldKind> AllSupplementalFields =
    [
        SupplementalFieldKind.OvervoteIndicator,
        SupplementalFieldKind.NullVoteIndicator,
        SupplementalFieldKind.UndervoteIndicator,
        SupplementalFieldKind.UndervoteDifferenceCount,
        SupplementalFieldKind.WriteInCount,
    ];

    /// <summary>
    /// Supplemental field declarations for a contest with <paramref name="optionCount"/> options, in
    /// the order given, with option indices continuing after the options (§3.1.3 p.19).
    /// </summary>
    public static List<SupplementalField> SupplementalFields(int optionCount, IEnumerable<SupplementalFieldKind> kinds)
    {
        return kinds.Select((kind, position) => new SupplementalField
        {
            Id = SupplementalFieldId(kind),
            Name = kind.ToString(),
            Index = optionCount + position + 1,
            Kind = kind,
        }).ToList();
    }

    /// <summary>The label the fixtures give a supplemental field of <paramref name="kind"/>.</summary>
    public static string SupplementalFieldId(SupplementalFieldKind kind) => kind switch
    {
        SupplementalFieldKind.OvervoteIndicator => "overvotes",
        SupplementalFieldKind.NullVoteIndicator => "null-votes",
        SupplementalFieldKind.UndervoteIndicator => "undervotes",
        SupplementalFieldKind.UndervoteDifferenceCount => "undervote-difference",
        SupplementalFieldKind.WriteInCount => "write-ins",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };

    /// <summary>
    /// Builds a small deterministic (non-Bogus) 1-contest, 2-choice manifest plus its serialized
    /// ManifestFile bytes. The contest declares <paramref name="supplementalFields"/>, by default
    /// <see cref="DefaultSupplementalFields"/>, plus the write-in count when
    /// <paramref name="includeWriteIns"/>. Pass includeWriteIns: true and a non-null ContestData
    /// string on the ballot (see CreateBallot) to exercise the write-in / contest-data path; the
    /// contest then offers <paramref name="writeInFieldCount"/> write-in fields (1 by default).
    /// </summary>
    public static (Manifest Manifest, ManifestFile ManifestFile) CreateMinimalManifest(
        bool includeWriteIns = false,
        ChainingMode chainingMode = ChainingMode.None,
        int optionSelectionLimit = 1,
        int selectionLimit = 1,
        HashTrimmingFunction? hashTrimmingFunction = null,
        IReadOnlyList<SupplementalFieldKind>? supplementalFields = null,
        int? writeInFieldCount = null)
    {
        var kinds = (supplementalFields ?? DefaultSupplementalFields).ToList();
        if (includeWriteIns && !kinds.Contains(SupplementalFieldKind.WriteInCount))
        {
            kinds.Add(SupplementalFieldKind.WriteInCount);
        }

        int writeInFields = writeInFieldCount ?? (kinds.Contains(SupplementalFieldKind.WriteInCount) || includeWriteIns ? 1 : 0);

        var manifest = new Manifest
        {
            ElectionId = "test-election-1",
            Contests = new List<Contest>
            {
                new Contest
                {
                    Id = "contest-1",
                    Name = "Test Contest",
                    SelectionLimit = selectionLimit,
                    OptionSelectionLimit = optionSelectionLimit,
                    // §3.1.3: indices are 1-based list positions.
                    Index = 1,
                    Choices = new List<Choice>
                    {
                        new Choice { Id = "choice-1", Name = "Choice 1", Index = 1 },
                        new Choice { Id = "choice-2", Name = "Choice 2", Index = 2 },
                    },
                    SupplementalFields = SupplementalFields(2, kinds),
                    WriteInFieldCount = writeInFields,
                },
            },
            BallotStyles = new List<BallotStyle>
            {
                new BallotStyle
                {
                    Id = "ballot-style-1",
                    Name = "Ballot Style 1",
                    ContestIds = new List<string> { "contest-1" },
                },
            },
            OptionalContestDataMaxLength = 256,
            ChainingMode = chainingMode,
            HashTrimmingFunction = hashTrimmingFunction,
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest);
        var manifestFile = new ManifestFile { Bytes = bytes };

        return (manifest, manifestFile);
    }

    /// <summary>
    /// Builds the ElectionBaseHash/ExtendedBaseHash/EncryptionRecord layer for a given guardian set
    /// and manifest (mirrors Program.cs lines 80-100).
    /// </summary>
    public static EncryptionRecordResult CreateEncryptionRecord(
        GuardianSetResult guardianSet,
        Manifest manifest,
        ManifestFile manifestFile)
    {
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, guardianSet.ElectionPublicKeys);

        var encryptionRecord = new EncryptionRecord
        {
            CryptographicParameters = EGParameters.CryptographicParameters,
            GuardianParameters = EGParameters.GuardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = guardianSet.GuardianPublicViews,
            ElectionPublicKeys = guardianSet.ElectionPublicKeys,
            ExtendedBaseHash = extendedBaseHash,
            Manifest = manifest,
        };

        return new EncryptionRecordResult
        {
            ElectionBaseHash = electionBaseHash,
            ExtendedBaseHash = extendedBaseHash,
            EncryptionRecord = encryptionRecord,
        };
    }

    /// <summary>
    /// Builds a minimal deterministic Ballot/BallotContest/BallotChoice graph matching the manifest
    /// produced by CreateMinimalManifest (single contest). Supply selectionValuesByChoiceId to mark
    /// specific choices, or leave null/empty for a nullvote. Set numWriteinsSelected/contestData to
    /// exercise the write-in path.
    /// </summary>
    public static Ballot CreateBallot(
        Manifest manifest,
        string ballotId = "ballot-1",
        Dictionary<string, int>? selectionValuesByChoiceId = null,
        int numWriteinsSelected = 0,
        string? contestData = null)
    {
        var contest = manifest.Contests.Single();
        var choices = contest.Choices.Select(choice => new BallotChoice
        {
            Id = choice.Id,
            SelectionValue = selectionValuesByChoiceId != null
                && selectionValuesByChoiceId.TryGetValue(choice.Id, out var value)
                ? value
                : 0,
        }).ToList();

        return new Ballot
        {
            Id = ballotId,
            BallotStyleId = manifest.BallotStyles.Single().Id,
            Contests = new List<BallotContest>
            {
                new BallotContest
                {
                    Id = contest.Id,
                    Choices = choices,
                    NumWriteinsSelected = numWriteinsSelected,
                    ContestData = contestData,
                },
            },
        };
    }

    /// <summary>
    /// Encrypts a ballot and records it as submitted with <paramref name="status"/> (cast, by
    /// default), as Program.cs does. Pass previousConfirmationCode to chain from a prior ballot on
    /// the same device (ChainingMode.Simple); pass null for the first ballot. Pass
    /// <see cref="BallotStatus.NotSubmitted"/> to get the encryptor's output untouched.
    /// </summary>
    public static EncryptedBallot CreateEncryptedBallot(
        EncryptionRecord encryptionRecord,
        string deviceId,
        VotingDeviceInformationHash deviceHash,
        Ballot ballot,
        ConfirmationCode? previousConfirmationCode = null,
        BallotStatus status = BallotStatus.Cast)
    {
        var encryptor = new BallotEncryptor(encryptionRecord, deviceId, deviceHash);
        var encryptedBallot = encryptor.Encrypt(ballot, previousConfirmationCode);
        if (status != BallotStatus.NotSubmitted)
        {
            encryptedBallot.RecordStatus(status);
        }

        return encryptedBallot;
    }

    /// <summary>
    /// Builds an EncryptedTally for the given manifest and accumulates the given encrypted ballots
    /// into it (mirrors Program.cs). Only cast ballots are counted.
    /// </summary>
    public static EncryptedTally CreateEncryptedTally(Manifest manifest, params EncryptedBallot[] ballots)
    {
        var tally = new EncryptedTally(manifest);
        foreach (var ballot in ballots)
        {
            tally.AddBallot(ballot);
        }

        return tally;
    }

    /// <summary>
    /// Decrypts <paramref name="tally"/> with the first <paramref name="guardianCount"/> guardians of
    /// <paramref name="guardianSet"/> (k, by default: the realistic and cheapest quorum), through the
    /// three rounds of the §3.6.5 protocol, as Program.cs and the perf harness do.
    /// </summary>
    public static DecryptedTally DecryptTally(
        GuardianSetResult guardianSet,
        EncryptedTally tally,
        EncryptionRecord encryptionRecord,
        int? guardianCount = null,
        int maxDegreeOfParallelism = -1)
    {
        return new TallyAdmin().Decrypt(TallyGuardians(guardianSet, guardianCount), tally, encryptionRecord, maxDegreeOfParallelism);
    }

    /// <summary>The first <paramref name="guardianCount"/> (default k) guardians of the set, ready to decrypt.</summary>
    public static List<TallyGuardian> TallyGuardians(GuardianSetResult guardianSet, int? guardianCount = null)
    {
        return guardianSet.Guardians
            .Take(guardianCount ?? EGParameters.GuardianParameters.K)
            .Select(guardian => new TallyGuardian(guardian.Index, guardianSet.SecretShares[guardian.Index]))
            .ToList();
    }
}
