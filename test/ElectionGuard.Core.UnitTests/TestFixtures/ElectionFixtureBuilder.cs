using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using System.Text.Json;

namespace ElectionGuard.Core.UnitTests.TestFixtures;

/// <summary>
/// Shared bootstrap helper mirroring the guardians -> keys -> shares -> manifest -> ballot ->
/// encrypt -> tally pipeline in src/ElectionGuard.InMemory.Console/Program.cs, so later test
/// classes don't have to re-derive the ~40-line construction sequence.
///
/// Callers must call EGParameters.Init(...) before using any method here (same requirement as
/// every other type in this library that touches IntegerModP/IntegerModQ/hash types).
///
/// This is a pure test helper -- it has no [Fact]/[Theory] methods of its own.
/// </summary>
internal static class ElectionFixtureBuilder
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
    /// Program.cs lines 30-73). GuardianParameters is hardcoded to N=3/K=2 (see CLAUDE.md), so the
    /// defaults here match that; do not pass values GuardianParameters doesn't support.
    /// </summary>
    public static GuardianSetResult CreateGuardianSet(int n = 3, int k = 2)
    {
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
            Guardians = guardianPublicViews,
            ElectionPublicKeys = electionPublicKeys,
        };

        foreach (var guardian in guardians)
        {
            guardian.Verify(guardianRecord);
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
    /// Builds a small deterministic (non-Bogus) 1-contest, 2-choice manifest plus its serialized
    /// ManifestFile bytes. Pass includeWriteIns: true and a non-null ContestData string on the
    /// ballot (see CreateBallot) to exercise the write-in / contest-data path.
    /// </summary>
    public static (Manifest Manifest, ManifestFile ManifestFile) CreateMinimalManifest(
        bool includeWriteIns = false,
        ChainingMode chainingMode = ChainingMode.None,
        int optionSelectionLimit = 1,
        int selectionLimit = 1)
    {
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
                    Index = 0,
                    Choices = new List<Choice>
                    {
                        new Choice { Id = "choice-1", Name = "Choice 1", Index = 0 },
                        new Choice { Id = "choice-2", Name = "Choice 2", Index = 1 },
                    },
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
            IncludeOvervotes = true,
            IncludeNullvotes = true,
            IncludeUndervotes = true,
            IncludeWriteins = includeWriteIns,
            ChainingMode = chainingMode,
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
    /// Encrypts a ballot (mirrors Program.cs lines 105-133). Pass previousConfirmationCode to chain
    /// from a prior ballot on the same device (ChainingMode.Simple); pass null for the first ballot.
    /// </summary>
    public static EncryptedBallot CreateEncryptedBallot(
        EncryptionRecord encryptionRecord,
        string deviceId,
        VotingDeviceInformationHash deviceHash,
        Ballot ballot,
        ConfirmationCode? previousConfirmationCode = null)
    {
        var encryptor = new BallotEncryptor(encryptionRecord, deviceId, deviceHash);
        return encryptor.Encrypt(ballot, previousConfirmationCode);
    }

    /// <summary>
    /// Builds an EncryptedTally for the given manifest and accumulates the given encrypted ballots
    /// into it (mirrors Program.cs lines 183-187).
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
}
