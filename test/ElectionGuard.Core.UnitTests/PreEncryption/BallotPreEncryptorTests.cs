using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Testing.Common;
using System.Security.Cryptography;
using System.Text;

namespace ElectionGuard.Core.UnitTests.PreEncryption;

public class BallotPreEncryptorTests
{
    private const string DeviceId = "device-1";
    private const string BallotStyleId = "ballot-style-1";

    public BallotPreEncryptorTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static EncryptionRecord CreateEncryptionRecord(
        int selectionLimit = 1,
        ChainingMode chainingMode = ChainingMode.None,
        HashTrimmingFunction? hashTrimmingFunction = HashTrimmingFunction.TwoHex)
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(
            chainingMode: chainingMode,
            selectionLimit: selectionLimit,
            hashTrimmingFunction: hashTrimmingFunction);
        return ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
    }

    private static EncryptionRecord WithManifest(EncryptionRecord record, Manifest manifest)
    {
        return new EncryptionRecord
        {
            CryptographicParameters = record.CryptographicParameters,
            GuardianParameters = record.GuardianParameters,
            ParameterBaseHash = record.ParameterBaseHash,
            ManifestFile = record.ManifestFile,
            ElectionBaseHash = record.ElectionBaseHash,
            Guardians = record.Guardians,
            ElectionPublicKeys = record.ElectionPublicKeys,
            ExtendedBaseHash = record.ExtendedBaseHash,
            Manifest = manifest,
        };
    }

    private static (SelectionEncryptionIdentifier Id, BallotNonce Nonce) Seed(int seed)
    {
        return (
            new SelectionEncryptionIdentifier(SHA256.HashData(Encoding.UTF8.GetBytes($"id-{seed}"))),
            new BallotNonce(SHA256.HashData(Encoding.UTF8.GetBytes($"nonce-{seed}"))));
    }

    private static PreEncryptedBallot PreEncrypt(BallotPreEncryptor encryptor, int seed, ConfirmationCode? previousConfirmationCode = null)
    {
        var (id, nonce) = Seed(seed);
        return encryptor.PreEncrypt("ballot-1", BallotStyleId, id, nonce, previousConfirmationCode);
    }

    [Fact]
    public void PreEncrypt_SameSeed_ProducesSameHashesAndShortCodes()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(), DeviceId);

        var first = PreEncrypt(encryptor, seed: 1);
        var second = PreEncrypt(encryptor, seed: 1);

        Assert.Equal(first.ConfirmationCode, second.ConfirmationCode);
        Assert.Equal(first.Contests[0].ContestHash, second.Contests[0].ContestHash);
        Assert.Equal(
            first.Contests[0].Selections.Select(s => (s.SelectionHash, s.ShortCode)),
            second.Contests[0].Selections.Select(s => (s.SelectionHash, s.ShortCode)));
    }

    [Fact]
    public void PreEncrypt_DifferentSeed_ProducesDifferentConfirmationCode()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(), DeviceId);

        Assert.NotEqual(PreEncrypt(encryptor, seed: 1).ConfirmationCode, PreEncrypt(encryptor, seed: 2).ConfirmationCode);
    }

    [Fact]
    public void PreEncrypt_HasOneSelectionVectorPerOptionThenSelectionLimitNullVectors()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var encryptor = new BallotPreEncryptor(record, DeviceId);
        var manifestContest = record.Manifest.Contests[0];

        var contest = PreEncrypt(encryptor, seed: 1).Contests.Single();

        // §3.1.3: indices are 1-based list positions, so they are derived here from the positions,
        // not read back from the manifest's own Index fields. The null vectors extend them past m.
        int optionCount = manifestContest.Choices.Count;
        Assert.Equal(1, contest.ContestIndex);
        Assert.Equal(manifestContest.Id, contest.ContestId);
        Assert.Equal(
            manifestContest.Choices.Select((c, position) => ((string?)c.Id, position + 1, false))
                .Concat([(null, optionCount + 1, true), (null, optionCount + 2, true)]),
            contest.Selections.Select(s => (s.ChoiceId, s.SelectionIndex, s.IsNullVote)));
        Assert.All(contest.Selections, s => Assert.Equal(manifestContest.Choices.Count, s.Vector.Count));
    }

    [Fact]
    public void PreEncrypt_VectorsEncryptOneOnlyAtTheirOwnPosition_WithEquation121Nonces()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var encryptor = new BallotPreEncryptor(record, DeviceId);
        var (id, ballotNonce) = Seed(1);
        var manifestContest = record.Manifest.Contests[0];
        var positions = Enumerable.Range(1, manifestContest.Choices.Count).ToList();
        var K = record.ElectionPublicKeys.VoteEncryptionKey;

        var ballot = encryptor.PreEncrypt("ballot-1", BallotStyleId, id, ballotNonce, null);

        foreach (var selection in ballot.Contests[0].Selections)
        {
            for (int k = 0; k < positions.Count; k++)
            {
                IntegerModQ xi = new PreEncryptionNonce(ballot.SelectionEncryptionIdentifierHash, ballotNonce,
                    contestIndex: 1, selection.SelectionIndex, positions[k]);
                int expectedValue = selection.SelectionIndex == positions[k] ? 1 : 0;

                Assert.Equal(IntegerModP.PowModP(EGParameters.G, xi), selection.Vector[k].Alpha);
                Assert.Equal(IntegerModP.PowModP(K, xi + expectedValue), selection.Vector[k].Beta);
                Assert.Equal(xi, selection.Vector[k].EncryptionNonce);
            }
        }
    }

    [Fact]
    public void PreEncrypt_SelectionHashesAndShortCodesFollowTheSpec()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(hashTrimmingFunction: HashTrimmingFunction.LetterDigit), DeviceId);

        var ballot = PreEncrypt(encryptor, seed: 1);

        Assert.All(ballot.Contests[0].Selections, s =>
        {
            Assert.Equal(new SelectionHash(ballot.SelectionEncryptionIdentifierHash, s.Vector), s.SelectionHash);
            Assert.Equal(HashTrimming.Trim(HashTrimmingFunction.LetterDigit, s.SelectionHash), s.ShortCode);
        });
    }

    [Fact]
    public void PreEncrypt_ContestHashAndConfirmationCodeFollowTheSpec()
    {
        var record = CreateEncryptionRecord();
        var encryptor = new BallotPreEncryptor(record, DeviceId);

        var ballot = PreEncrypt(encryptor, seed: 1);

        var contest = ballot.Contests[0];
        var hi = ballot.SelectionEncryptionIdentifierHash;
        Assert.Equal((byte[])new SelectionEncryptionIdentifierHash(record.ExtendedBaseHash, ballot.SelectionEncryptionIdentifier), (byte[])hi);
        Assert.Equal(
            ContestHash.ForPreEncryptedContest(hi, contest.ContestIndex, contest.Selections.Select(s => s.SelectionHash)),
            contest.ContestHash);

        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, DeviceId);
        var chainingField = ChainingField.ForPreEncryptedBallots(ChainingMode.None, deviceHash, record.ExtendedBaseHash, null);
        Assert.Equal(chainingField, ballot.ChainingField);
        Assert.Equal(ConfirmationCode.ForPreEncryptedBallot(hi, [contest.ContestHash], chainingField), ballot.ConfirmationCode);
        Assert.Equal(DeviceId, ballot.DeviceId);
        Assert.Equal(BallotStyleId, ballot.BallotStyleId);
        Assert.Equal("ballot-1", ballot.Id);
    }

    [Fact]
    public void PreEncrypt_SortedSelectionHashesAreInIncreasingOrder()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(selectionLimit: 2), DeviceId);

        var contest = PreEncrypt(encryptor, seed: 1).Contests[0];

        Assert.Equal(contest.Selections.Select(s => s.SelectionHash).Order(), contest.SortedSelectionHashes);
    }

    [Fact]
    public void PreEncrypt_SimpleChaining_ChainsFromThePreviousConfirmationCode()
    {
        var record = CreateEncryptionRecord(chainingMode: ChainingMode.Simple);
        var encryptor = new BallotPreEncryptor(record, DeviceId);

        var first = PreEncrypt(encryptor, seed: 1);
        var second = PreEncrypt(encryptor, seed: 2, previousConfirmationCode: first.ConfirmationCode);

        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, DeviceId);
        Assert.Equal(ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, deviceHash, record.ExtendedBaseHash, null), first.ChainingField);
        Assert.Equal(ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, deviceHash, record.ExtendedBaseHash, first.ConfirmationCode), second.ChainingField);
    }

    [Fact]
    public void PreEncrypt_EncryptedBallotNonceCarriesAValidProof()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(), DeviceId);

        var ballot = PreEncrypt(encryptor, seed: 1);

        // §3.3.4: c = Hq(HI; 0x23, a, C0, C1) with a = g^v * C0^c.
        var data = ballot.EncryptedBallotNonce;
        var c0 = new IntegerModP(data.C0);
        var commitment = IntegerModP.PowModP(EGParameters.G, data.Response) * IntegerModP.PowModP(c0, data.Challenge);
        var expectedChallenge = EGHash.HashModQ(ballot.SelectionEncryptionIdentifierHash, [0x23], commitment, data.C0, data.C1);
        Assert.Equal(expectedChallenge, data.Challenge);
        Assert.Equal(32, data.C1.Length);
    }

    [Fact]
    public void PreEncrypt_OrdersContestsByContestIndex()
    {
        // §3.1.3 makes a contest index the contest's 1-based position in the manifest, so the
        // manifest lists the contests in index order; the ballot style lists them the other way
        // round, which is allowed since its contest list is unordered. The output must follow the
        // indices, not the ballot style.
        var record = CreateEncryptionRecord();
        var template = record.Manifest.Contests[0];
        var earlier = template with { Id = "contest-earlier", Index = 1 };
        var later = template with { Id = "contest-later", Index = 2 };
        var manifest = record.Manifest with
        {
            Contests = [earlier, later],
            BallotStyles = [new BallotStyle { Id = BallotStyleId, Name = "style", ContestIds = ["contest-later", "contest-earlier"] }],
        };
        var encryptor = new BallotPreEncryptor(WithManifest(record, manifest), DeviceId);

        var ballot = PreEncrypt(encryptor, seed: 1);

        Assert.Equal(["contest-earlier", "contest-later"], ballot.Contests.Select(c => c.ContestId));
    }

    [Fact]
    public void PreEncrypt_LabelOrderDiffersFromIndexOrder_OrdersContestsAndOptionsByIndex()
    {
        // In the test above, label order and index order coincide. Here the labels sort the other way
        // round, in both the contests and the options, so ordering by label would be caught. The
        // ballot then passes Verification 16, which recomputes the confirmation code in index order.
        var record = CreateEncryptionRecord();
        var template = record.Manifest.Contests[0];
        Choice[] options =
        [
            new Choice { Id = "option-z", Name = "Z", Index = 1 },
            new Choice { Id = "option-a", Name = "A", Index = 2 },
        ];
        var zulu = template with { Id = "contest-zulu", Index = 1, Choices = [.. options] };
        var alpha = template with { Id = "contest-alpha", Index = 2, Choices = [.. options] };
        var manifest = record.Manifest with
        {
            Contests = [zulu, alpha],
            BallotStyles = [new BallotStyle { Id = BallotStyleId, Name = "style", ContestIds = ["contest-alpha", "contest-zulu"] }],
        };
        var reordered = WithManifest(record, manifest);
        var encryptor = new BallotPreEncryptor(reordered, DeviceId);

        var ballot = PreEncrypt(encryptor, seed: 1);

        Assert.Equal(["contest-zulu", "contest-alpha"], ballot.Contests.Select(c => c.ContestId));
        Assert.Equal([1, 2], ballot.Contests.Select(c => c.ContestIndex));
        foreach (var contest in ballot.Contests)
        {
            Assert.Equal(["option-z", "option-a"], contest.Selections.Where(s => !s.IsNullVote).Select(s => s.ChoiceId));
        }

        var expected = ConfirmationCode.ForPreEncryptedBallot(
            ballot.SelectionEncryptionIdentifierHash, ballot.Contests.Select(c => c.ContestHash), ballot.ChainingField);
        var byLabel = ConfirmationCode.ForPreEncryptedBallot(
            ballot.SelectionEncryptionIdentifierHash, ballot.Contests.OrderBy(c => c.ContestId, StringComparer.Ordinal).Select(c => c.ContestHash), ballot.ChainingField);
        Assert.Equal(expected, ballot.ConfirmationCode);
        Assert.NotEqual(byLabel, ballot.ConfirmationCode);

        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(reordered.ExtendedBaseHash, DeviceId);
        Assert.Null(Record.Exception(() => new PreEncryptedConfirmationCodeVerification().Verify(ballot, deviceHash, reordered, null)));
    }

    [Fact]
    public void PreEncrypt_UnknownBallotStyle_Throws()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(), DeviceId);
        var (id, nonce) = Seed(1);

        Assert.Throws<ArgumentException>(() => encryptor.PreEncrypt("ballot-1", "no-such-style", id, nonce, null));
    }

    [Fact]
    public void Constructor_ManifestWithoutHashTrimmingFunction_Throws()
    {
        var record = CreateEncryptionRecord(hashTrimmingFunction: null);

        Assert.Throws<ArgumentException>(() => new BallotPreEncryptor(record, DeviceId));
    }

    [Fact]
    public void Constructor_ContestNeedingMoreShortCodesThanTheCodeSpace_Throws()
    {
        var record = CreateEncryptionRecord();
        var template = record.Manifest.Contests[0];
        // 256 options plus one null vector need 257 distinct codes; Ω1 has 256.
        var oversized = template with
        {
            Choices = Enumerable.Range(0, 256).Select(i => new Choice { Id = $"choice-{i}", Name = $"Choice {i}", Index = i + 1 }).ToList(),
        };
        var manifest = record.Manifest with { Contests = [oversized] };

        Assert.Throws<ArgumentException>(() => new BallotPreEncryptor(WithManifest(record, manifest), DeviceId));
    }

    [Fact]
    public void PreEncrypt_Public_ProducesUniqueShortCodesWithinEachContest()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(selectionLimit: 2), DeviceId);

        var ballot = encryptor.PreEncrypt("ballot-1", BallotStyleId, previousConfirmationCode: null);

        Assert.True(BallotPreEncryptor.HasUniqueShortCodesPerContest(ballot));
    }

    [Fact]
    public void HasUniqueShortCodesPerContest_RepeatedCodeWithinAContest_ReturnsFalse()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(), DeviceId);
        var ballot = PreEncrypt(encryptor, seed: 1);
        var codes = ballot.Contests[0].Selections.Select(s => s.ShortCode).ToList();

        Assert.Equal(codes.Distinct().Count() == codes.Count, BallotPreEncryptor.HasUniqueShortCodesPerContest(ballot));
        Assert.False(BallotPreEncryptor.HasUniqueShortCodesPerContest(WithCollidingShortCodes(ballot)));
    }

    private static PreEncryptedBallot WithCollidingShortCodes(PreEncryptedBallot ballot)
    {
        var contest = ballot.Contests[0];
        var duplicated = contest.Selections.Select(s => s with { ShortCode = contest.Selections[0].ShortCode }).ToList();
        return ballot with { Contests = [contest with { Selections = duplicated }] };
    }

    [Fact]
    public void GenerateWithUniqueShortCodes_ShortCodeCollision_DiscardsTheBallotAndTriesAgain()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(), DeviceId);
        var clean = encryptor.PreEncrypt("ballot-1", BallotStyleId, previousConfirmationCode: null);
        var generated = new Queue<PreEncryptedBallot>([WithCollidingShortCodes(clean), clean]);

        var ballot = BallotPreEncryptor.GenerateWithUniqueShortCodes(maxAttempts: 5, generated.Dequeue);

        Assert.Empty(generated);
        Assert.Same(clean, ballot);
    }

    [Fact]
    public void GenerateWithUniqueShortCodes_EveryAttemptCollides_ThrowsAfterMaxAttempts()
    {
        var encryptor = new BallotPreEncryptor(CreateEncryptionRecord(), DeviceId);
        var colliding = WithCollidingShortCodes(PreEncrypt(encryptor, seed: 1));
        int attempts = 0;

        Assert.Throws<InvalidOperationException>(() =>
            BallotPreEncryptor.GenerateWithUniqueShortCodes(maxAttempts: 3, () => { attempts++; return colliding; }));
        Assert.Equal(3, attempts);
    }

    [Fact]
    public void GenerateWithUniqueShortCodes_NonPositiveMaxAttempts_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BallotPreEncryptor.GenerateWithUniqueShortCodes(maxAttempts: 0, () => throw new InvalidOperationException("not called")));
    }
}
