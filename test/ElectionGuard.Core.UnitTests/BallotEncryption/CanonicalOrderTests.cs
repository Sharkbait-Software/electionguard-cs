using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Testing.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ElectionGuard.Core.UnitTests.BallotEncryption;

/// <summary>
/// §3.4.1 eq. (70) hashes a contest's selections "in order specified by the election manifest", and
/// §3.4.2 eq. (71) hashes the contest hashes "in the order of the contests as specified in the
/// election manifest". The order a plaintext ballot or a stored encrypted ballot happens to list
/// them in must not matter to either the encryptor or Verification 8.
/// </summary>
public class CanonicalOrderTests
{
    private const string DeviceId = "device-1";

    public CanonicalOrderTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    /// <summary>
    /// Two contests with different option counts, so a contest-order mix-up cannot hide behind
    /// identical shapes. The ballot style lists them in the opposite order to the manifest, which
    /// §3.1.3 allows: a ballot style's contest list is unordered.
    /// </summary>
    private static (EncryptionRecord Record, VotingDeviceInformationHash DeviceHash) CreateRecord() =>
        CreateRecord([ContestA(), ContestB()], ["contest-b", "contest-a"]);

    private static Contest ContestA() => new()
    {
        Id = "contest-a",
        Name = "Contest A",
        SelectionLimit = 1,
        OptionSelectionLimit = 1,
        Index = 1,
        Choices =
        [
            new Choice { Id = "a-1", Name = "A 1", Index = 1 },
            new Choice { Id = "a-2", Name = "A 2", Index = 2 },
            new Choice { Id = "a-3", Name = "A 3", Index = 3 },
        ],
    };

    private static Contest ContestB() => new()
    {
        Id = "contest-b",
        Name = "Contest B",
        SelectionLimit = 1,
        OptionSelectionLimit = 1,
        Index = 2,
        Choices =
        [
            new Choice { Id = "b-1", Name = "B 1", Index = 1 },
            new Choice { Id = "b-2", Name = "B 2", Index = 2 },
        ],
    };

    private static Contest ContestC() => new()
    {
        Id = "contest-c",
        Name = "Contest C",
        SelectionLimit = 1,
        OptionSelectionLimit = 1,
        Index = 3,
        Choices =
        [
            new Choice { Id = "c-1", Name = "C 1", Index = 1 },
            new Choice { Id = "c-2", Name = "C 2", Index = 2 },
        ],
    };

    /// <param name="contests">The manifest's contests, in manifest order.</param>
    /// <param name="styleContestIds">The single ballot style's contest list, in any order.</param>
    private static (EncryptionRecord Record, VotingDeviceInformationHash DeviceHash) CreateRecord(List<Contest> contests, List<string> styleContestIds)
    {
        var manifest = new Manifest
        {
            ElectionId = "canonical-order",
            Contests = contests,
            BallotStyles = [new BallotStyle { Id = "style-1", Name = "Style 1", ContestIds = styleContestIds }],
            OptionalContestDataMaxLength = 0,
            IncludeOvervotes = true,
            IncludeNullvotes = true,
            IncludeUndervotes = true,
            IncludeWriteins = true,
            ChainingMode = ChainingMode.None,
        };
        var manifestFile = new ManifestFile { Bytes = JsonSerializer.SerializeToUtf8Bytes(manifest) };

        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        return (records.EncryptionRecord, new VotingDeviceInformationHash(records.ExtendedBaseHash, DeviceId));
    }

    private static Ballot OrderedBallot() => new()
    {
        Id = "ballot-1",
        BallotStyleId = "style-1",
        Contests =
        [
            new BallotContest
            {
                Id = "contest-a",
                NumWriteinsSelected = 0,
                Choices =
                [
                    new BallotChoice { Id = "a-1", SelectionValue = 0 },
                    new BallotChoice { Id = "a-2", SelectionValue = 1 },
                    new BallotChoice { Id = "a-3", SelectionValue = 0 },
                ],
            },
            new BallotContest
            {
                Id = "contest-b",
                NumWriteinsSelected = 0,
                Choices =
                [
                    new BallotChoice { Id = "b-1", SelectionValue = 1 },
                    new BallotChoice { Id = "b-2", SelectionValue = 0 },
                ],
            },
        ],
    };

    /// <summary>The same selections as <see cref="OrderedBallot"/>, with every list reversed.</summary>
    private static Ballot ShuffledBallot()
    {
        var ordered = OrderedBallot();
        return ordered with
        {
            Contests = ordered.Contests
                .Select(contest => contest with { Choices = Enumerable.Reverse(contest.Choices).ToList() })
                .Reverse()
                .ToList(),
        };
    }

    private static (SelectionEncryptionIdentifier Id, BallotNonce Nonce) Seed() => (
        new SelectionEncryptionIdentifier(SHA256.HashData(Encoding.UTF8.GetBytes("canonical-order-id"))),
        new BallotNonce(SHA256.HashData(Encoding.UTF8.GetBytes("canonical-order-nonce"))));

    private static EncryptedBallot Encrypt(EncryptionRecord record, VotingDeviceInformationHash deviceHash, Ballot ballot)
    {
        var (id, nonce) = Seed();
        return new BallotEncryptor(record, DeviceId, deviceHash).Encrypt(ballot, null, id, nonce);
    }

    private static EncryptedBallot WithContests(EncryptedBallot ballot, List<EncryptedContest> contests, ConfirmationCode confirmationCode) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballot.BallotStyleId,
        Contests = contests,
        ConfirmationCode = confirmationCode,
        Weight = ballot.Weight,
        DeviceId = ballot.DeviceId,
    };

    private static ContestHash HashInStoredOrder(EncryptedBallot ballot, EncryptedContest contest, int contestIndex) => new(
        ballot.SelectionEncryptionIdentifierHash,
        contestIndex,
        contest.Choices,
        contest.OvervoteCount,
        contest.NullvoteCount,
        contest.UndervoteCount,
        contest.WriteInVoteCount,
        contest.ContestData);

    [Fact]
    public void Encrypt_ShuffledPlaintextBallot_ProducesTheSameHashesAsTheOrderedOne()
    {
        var (record, deviceHash) = CreateRecord();

        var ordered = Encrypt(record, deviceHash, OrderedBallot());
        var shuffled = Encrypt(record, deviceHash, ShuffledBallot());

        Assert.Equal(ordered.ConfirmationCode, shuffled.ConfirmationCode);
        Assert.Equal(ordered.Contests.Select(x => x.ContestHash), shuffled.Contests.Select(x => x.ContestHash));
        Assert.Equal(
            ordered.Contests.SelectMany(x => x.Choices).Select(x => (x.ChoiceId, x.Alpha, x.Beta)),
            shuffled.Contests.SelectMany(x => x.Choices).Select(x => (x.ChoiceId, x.Alpha, x.Beta)));
    }

    [Fact]
    public void Encrypt_ShuffledPlaintextBallot_ListsContestsAndSelectionsInManifestOrder()
    {
        var (record, deviceHash) = CreateRecord();

        var encrypted = Encrypt(record, deviceHash, ShuffledBallot());

        Assert.Equal(record.Manifest.Contests.Select(x => x.Id), encrypted.Contests.Select(x => x.Id));
        foreach (var (manifestContest, contest) in record.Manifest.Contests.Zip(encrypted.Contests))
        {
            Assert.Equal(manifestContest.Choices.Select(x => x.Id), contest.Choices.Select(x => x.ChoiceId));
        }
    }

    [Fact]
    public void Encrypt_ConfirmationCode_HashesContestHashesInManifestOrder()
    {
        var (record, deviceHash) = CreateRecord();

        var encrypted = Encrypt(record, deviceHash, ShuffledBallot());

        var chainingField = new ChainingField(ChainingMode.None, deviceHash, record.ExtendedBaseHash, null);
        var hashA = encrypted.Contests.Single(x => x.Id == "contest-a").ContestHash;
        var hashB = encrypted.Contests.Single(x => x.Id == "contest-b").ContestHash;

        Assert.Equal(new ConfirmationCode(encrypted.SelectionEncryptionIdentifierHash, [hashA, hashB], chainingField), encrypted.ConfirmationCode);
        Assert.NotEqual(new ConfirmationCode(encrypted.SelectionEncryptionIdentifierHash, [hashB, hashA], chainingField), encrypted.ConfirmationCode);

        // And each contest hash is over its selections in option-index order.
        var contestA = encrypted.Contests.Single(x => x.Id == "contest-a");
        Assert.Equal(HashInStoredOrder(encrypted, contestA, 1), contestA.ContestHash);
    }

    [Fact]
    public void Verify8_StoredListsPermuted_HashesCanonical_Passes()
    {
        var (record, deviceHash) = CreateRecord();
        var encrypted = Encrypt(record, deviceHash, OrderedBallot());

        // The ballot as an implementation that stores its lists in some other order would publish
        // it: the same ciphertexts and the same (canonical) hashes.
        var permuted = WithContests(
            encrypted,
            encrypted.Contests
                .Select(contest => contest with { Choices = Enumerable.Reverse(contest.Choices).ToList() })
                .Reverse()
                .ToList(),
            encrypted.ConfirmationCode);

        var exception = Record.Exception(() => new ConfirmationCodeVerification().Verify(permuted, deviceHash, record, null));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify8_ConfirmationCodeOverNonCanonicalContestOrder_Fails8B()
    {
        var (record, deviceHash) = CreateRecord();
        var encrypted = Encrypt(record, deviceHash, OrderedBallot());

        // A self-consistent ballot that lists its contests in the wrong order and hashes them in
        // that same stored order. Only the manifest order is acceptable (eq. 71).
        var reversed = Enumerable.Reverse(encrypted.Contests).ToList();
        var chainingField = new ChainingField(ChainingMode.None, deviceHash, record.ExtendedBaseHash, null);
        var storedOrderCode = new ConfirmationCode(encrypted.SelectionEncryptionIdentifierHash, reversed.Select(x => x.ContestHash).ToList(), chainingField);
        Assert.NotEqual(encrypted.ConfirmationCode, storedOrderCode);

        var tampered = WithContests(encrypted, reversed, storedOrderCode);

        var exception = Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(tampered, deviceHash, record, null));
        Assert.Equal("8.B", exception.SubSection);
    }

    [Fact]
    public void Verify8_ContestHashOverNonCanonicalOptionOrder_Fails8A()
    {
        var (record, deviceHash) = CreateRecord();
        var encrypted = Encrypt(record, deviceHash, OrderedBallot());

        // Contest A with its selections listed, and hashed, in reverse option order, and the
        // confirmation code recomputed over that contest hash so that only the option order is wrong.
        var contestA = encrypted.Contests.Single(x => x.Id == "contest-a");
        var reversedA = contestA with { Choices = Enumerable.Reverse(contestA.Choices).ToList() };
        reversedA = reversedA with { ContestHash = HashInStoredOrder(encrypted, reversedA, 1) };
        Assert.NotEqual(contestA.ContestHash, reversedA.ContestHash);

        var contests = encrypted.Contests.Select(x => x.Id == "contest-a" ? reversedA : x).ToList();
        var chainingField = new ChainingField(ChainingMode.None, deviceHash, record.ExtendedBaseHash, null);
        var code = new ConfirmationCode(encrypted.SelectionEncryptionIdentifierHash, contests.Select(x => x.ContestHash).ToList(), chainingField);
        var tampered = WithContests(encrypted, contests, code);

        var exception = Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(tampered, deviceHash, record, null));
        Assert.Equal("8.A", exception.SubSection);
    }

    /// <summary>
    /// A ballot style that holds only some of the manifest's contests (§3.1.3): the encryptor walks
    /// the manifest and skips the contests the ballot lacks, emits the rest in manifest order, and
    /// hashes each with its manifest index, not its position on the ballot.
    /// </summary>
    [Fact]
    public void Encrypt_BallotStyleWithSubsetOfContests_EmitsThemInManifestOrderAndVerifies()
    {
        var (record, deviceHash) = CreateRecord([ContestA(), ContestB(), ContestC()], ["contest-c", "contest-a"]);
        var ballot = new Ballot
        {
            Id = "ballot-subset",
            BallotStyleId = "style-1",
            Contests =
            [
                new BallotContest
                {
                    Id = "contest-c",
                    NumWriteinsSelected = 0,
                    Choices =
                    [
                        new BallotChoice { Id = "c-2", SelectionValue = 1 },
                        new BallotChoice { Id = "c-1", SelectionValue = 0 },
                    ],
                },
                new BallotContest
                {
                    Id = "contest-a",
                    NumWriteinsSelected = 0,
                    Choices =
                    [
                        new BallotChoice { Id = "a-1", SelectionValue = 1 },
                        new BallotChoice { Id = "a-2", SelectionValue = 0 },
                        new BallotChoice { Id = "a-3", SelectionValue = 0 },
                    ],
                },
            ],
        };

        var encrypted = Encrypt(record, deviceHash, ballot);

        Assert.Equal(["contest-a", "contest-c"], encrypted.Contests.Select(x => x.Id));

        // Contest C is second on the encrypted ballot but third in the manifest; index 3 is hashed.
        var contestA = encrypted.Contests.Single(x => x.Id == "contest-a");
        var contestC = encrypted.Contests.Single(x => x.Id == "contest-c");
        Assert.Equal(["c-1", "c-2"], contestC.Choices.Select(x => x.ChoiceId));
        Assert.Equal(HashInStoredOrder(encrypted, contestC, 3), contestC.ContestHash);
        Assert.NotEqual(HashInStoredOrder(encrypted, contestC, 2), contestC.ContestHash);

        var chainingField = new ChainingField(ChainingMode.None, deviceHash, record.ExtendedBaseHash, null);
        Assert.Equal(
            new ConfirmationCode(encrypted.SelectionEncryptionIdentifierHash, [contestA.ContestHash, contestC.ContestHash], chainingField),
            encrypted.ConfirmationCode);

        Assert.Null(Record.Exception(() => new SelectionEncryptionsWellFormedVerification().Verify(encrypted, record)));
        Assert.Null(Record.Exception(() => new AdherenceToVoteLimitsVerification().Verify(encrypted, record)));
        Assert.Null(Record.Exception(() => new ConfirmationCodeVerification().Verify(encrypted, deviceHash, record, null)));
    }

    [Fact]
    public void Encrypt_BallotListingAContestTwice_IsRejected()
    {
        var (record, deviceHash) = CreateRecord();
        var ordered = OrderedBallot();
        var duplicated = ordered with { Contests = [ordered.Contests[0], ordered.Contests[0] with { }] };

        var exception = Assert.ThrowsAny<Exception>(() => Encrypt(record, deviceHash, duplicated));

        Assert.Contains("more than once", exception.Message);
    }
}
