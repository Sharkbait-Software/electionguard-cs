using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Testing.Common;
using System.Security.Cryptography;
using System.Text;

namespace ElectionGuard.Core.UnitTests.PreEncryption;

/// <summary>
/// The pre-encryption primitives (<see cref="PreEncryptionPrimitives"/>: eqs. 113-115 and 121, Ω,
/// §4.1.5, and §4.3's combination and proofs), and pre-encrypted ballots assembled from them and the
/// public hash and chaining types by the test-only <see cref="PreEncryptedBallotFixtures"/> (the
/// library has no encrypting tool, user decision Q35).
/// </summary>
public class PreEncryptionPrimitivesTests
{
    private const string DeviceId = "device-1";
    private const string BallotStyleId = "ballot-style-1";

    public PreEncryptionPrimitivesTests()
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
            // The record's manifest is parsed from its file (S10a), so the other manifest goes in as
            // a file; H_B and H_E stay the original record's claims.
            ManifestFile = ManifestSerializer.ToManifestFile(manifest),
            ElectionBaseHash = record.ElectionBaseHash,
            Guardians = record.Guardians,
            ElectionPublicKeys = record.ElectionPublicKeys,
            ExtendedBaseHash = record.ExtendedBaseHash,
        };
    }

    private static (SelectionEncryptionIdentifier Id, BallotNonce Nonce) Seed(int seed)
    {
        return (
            new SelectionEncryptionIdentifier(SHA256.HashData(Encoding.UTF8.GetBytes($"id-{seed}"))),
            new BallotNonce(SHA256.HashData(Encoding.UTF8.GetBytes($"nonce-{seed}"))));
    }

    private static PreEncryptedBallot PreEncrypt(EncryptionRecord record, int seed, ConfirmationCode? previousConfirmationCode = null)
    {
        var (id, nonce) = Seed(seed);
        return PreEncryptedBallotFixtures.PreEncrypt(record, DeviceId, "ballot-1", BallotStyleId, id, nonce, previousConfirmationCode);
    }

    private static SelectionEncryptionIdentifierHash SelectionHash(EncryptionRecord record, int seed) =>
        new(record.ExtendedBaseHash, Seed(seed).Id);

    // --- Generation: eqs. (113)-(115), (121), Ω -------------------------------------------------

    [Fact]
    public void PreEncrypt_SameSeed_ProducesSameHashesAndShortCodes()
    {
        var record = CreateEncryptionRecord();

        var first = PreEncrypt(record, seed: 1);
        var second = PreEncrypt(record, seed: 1);

        Assert.Equal(first.ConfirmationCode, second.ConfirmationCode);
        Assert.Equal(first.Contests[0].ContestHash, second.Contests[0].ContestHash);
        Assert.Equal(
            first.Contests[0].Selections.Select(s => (s.SelectionHash, s.ShortCode)),
            second.Contests[0].Selections.Select(s => (s.SelectionHash, s.ShortCode)));
    }

    [Fact]
    public void PreEncrypt_DifferentSeed_ProducesDifferentConfirmationCode()
    {
        var record = CreateEncryptionRecord();

        Assert.NotEqual(PreEncrypt(record, seed: 1).ConfirmationCode, PreEncrypt(record, seed: 2).ConfirmationCode);
    }

    [Fact]
    public void GenerateContest_HasOneSelectionVectorPerOptionThenSelectionLimitNullVectors()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var manifestContest = record.Manifest.Contests[0];

        var contest = PreEncrypt(record, seed: 1).Contests.Single();

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
    public void GenerateContest_VectorsEncryptOneOnlyAtTheirOwnPosition_WithEquation121Nonces()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var (_, ballotNonce) = Seed(1);
        var manifestContest = record.Manifest.Contests[0];
        var positions = Enumerable.Range(1, manifestContest.Choices.Count).ToList();
        var K = record.ElectionPublicKeys.VoteEncryptionKey;

        var ballot = PreEncrypt(record, seed: 1);

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
    public void GenerateSelection_IsTheContestsVectorOfThatIndex_AndRefusesAnIndexWithNoVector()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var manifestContest = record.Manifest.Contests[0];
        var selectionHash = SelectionHash(record, 1);
        var (_, ballotNonce) = Seed(1);
        var keys = record.ElectionPublicKeys;

        var contest = PreEncryptionPrimitives.GenerateContest(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, manifestContest);

        // m = 2 options (j = 1, 2) and L = 2 null vectors (j = 3, 4).
        foreach (var expected in contest.Selections)
        {
            var selection = PreEncryptionPrimitives.GenerateSelection(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, manifestContest, expected.SelectionIndex);
            Assert.Equal(expected.ChoiceId, selection.ChoiceId);
            Assert.Equal(expected.SelectionHash, selection.SelectionHash);
            Assert.Equal(expected.ShortCode, selection.ShortCode);
            Assert.Equal(expected.Vector.Select(x => (x.Alpha, x.Beta, x.EncryptionNonce)), selection.Vector.Select(x => (x.Alpha, x.Beta, x.EncryptionNonce)));
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => PreEncryptionPrimitives.GenerateSelection(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, manifestContest, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => PreEncryptionPrimitives.GenerateSelection(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, manifestContest, 5));
    }

    [Fact]
    public void GenerateContest_SelectionHashesAndShortCodesFollowTheSpec()
    {
        var record = CreateEncryptionRecord(hashTrimmingFunction: HashTrimmingFunction.LetterDigit);

        var ballot = PreEncrypt(record, seed: 1);

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

        var ballot = PreEncrypt(record, seed: 1);

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
    public void GenerateContest_SortedSelectionHashesAreInIncreasingOrder()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);

        var contest = PreEncrypt(record, seed: 1).Contests[0];

        Assert.Equal(contest.Selections.Select(s => s.SelectionHash).Order(), contest.SortedSelectionHashes);
    }

    [Fact]
    public void PreEncrypt_SimpleChaining_ChainsFromThePreviousConfirmationCode()
    {
        var record = CreateEncryptionRecord(chainingMode: ChainingMode.Simple);

        var first = PreEncrypt(record, seed: 1);
        var second = PreEncrypt(record, seed: 2, previousConfirmationCode: first.ConfirmationCode);

        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, DeviceId);
        Assert.Equal(ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, deviceHash, record.ExtendedBaseHash, null), first.ChainingField);
        Assert.Equal(ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, deviceHash, record.ExtendedBaseHash, first.ConfirmationCode), second.ChainingField);
    }

    [Fact]
    public void PreEncrypt_EncryptedBallotNonceCarriesAValidProof()
    {
        var ballot = PreEncrypt(CreateEncryptionRecord(), seed: 1);

        // §3.3.4: c = Hq(HI; 0x23, a, C0, C1) with a = g^v * C0^c.
        var data = ballot.EncryptedBallotNonce;
        var c0 = data.C0;
        var commitment = IntegerModP.PowModP(EGParameters.G, data.Response) * IntegerModP.PowModP(c0, data.Challenge);
        var expectedChallenge = EGHash.HashModQ(ballot.SelectionEncryptionIdentifierHash, [0x23], commitment, data.C0, data.C1);
        Assert.Equal(expectedChallenge, data.Challenge);
        Assert.Equal(32, data.C1.Length);
    }

    [Fact]
    public void GenerateContests_OrdersContestsByContestIndex()
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

        var ballot = PreEncrypt(WithManifest(record, manifest), seed: 1);

        Assert.Equal(["contest-earlier", "contest-later"], ballot.Contests.Select(c => c.ContestId));
    }

    [Fact]
    public void GenerateContests_LabelOrderDiffersFromIndexOrder_OrdersContestsAndOptionsByIndex()
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

        var ballot = PreEncrypt(reordered, seed: 1);

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
    public void GenerateContests_UnknownBallotStyle_Throws()
    {
        var record = CreateEncryptionRecord();
        var (_, nonce) = Seed(1);

        Assert.Throws<ArgumentException>(() => PreEncryptionPrimitives.GenerateContests(record, "no-such-style", SelectionHash(record, 1), nonce));
    }

    [Fact]
    public void GenerateContests_ManifestWithoutHashTrimmingFunction_Throws()
    {
        var record = CreateEncryptionRecord(hashTrimmingFunction: null);
        var (_, nonce) = Seed(1);

        Assert.Throws<ArgumentException>(() => PreEncryptionPrimitives.GenerateContests(record, BallotStyleId, SelectionHash(record, 1), nonce));
    }

    // --- §4.1.5 unique short codes ---------------------------------------------------------------

    [Fact]
    public void PreEncrypt_Random_ProducesUniqueShortCodesWithinEachContest()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);

        var (ballot, _) = PreEncryptedBallotFixtures.PreEncrypt(record, DeviceId, "ballot-1", BallotStyleId, previousConfirmationCode: null);

        Assert.All(ballot.Contests, contest => Assert.True(PreEncryptionPrimitives.HasUniqueShortCodes(contest)));
    }

    [Fact]
    public void HasUniqueShortCodes_RepeatedCodeWithinAContest_ReturnsFalse()
    {
        var contest = PreEncrypt(CreateEncryptionRecord(), seed: 1).Contests[0];
        var codes = contest.Selections.Select(s => s.ShortCode).ToList();
        var colliding = contest with { Selections = contest.Selections.Select(s => s with { ShortCode = contest.Selections[0].ShortCode }).ToList() };

        Assert.Equal(codes.Distinct().Count() == codes.Count, PreEncryptionPrimitives.HasUniqueShortCodes(contest));
        Assert.False(PreEncryptionPrimitives.HasUniqueShortCodes(colliding));
    }

    // --- §4.3 combination and proofs -------------------------------------------------------------

    [Fact]
    public void Combine_MultipliesComponentwise_AndSumsTheNonces()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var selections = PreEncrypt(record, seed: 1).Contests[0].Selections;
        var chosen = new[] { selections[1], selections[2] };

        var combined = PreEncryptionPrimitives.Combine(chosen);

        Assert.Equal(selections[0].Vector.Count, combined.Count);
        for (int k = 0; k < combined.Count; k++)
        {
            Assert.Equal(chosen[0].Vector[k].Alpha * chosen[1].Vector[k].Alpha, combined[k].Alpha);
            Assert.Equal(chosen[0].Vector[k].Beta * chosen[1].Vector[k].Beta, combined[k].Beta);
            Assert.Equal(chosen[0].Vector[k].EncryptionNonce!.Value + chosen[1].Vector[k].EncryptionNonce!.Value, combined[k].EncryptionNonce);

            // Option 2's vector and a null vector: the component encrypts 1 at option 2, 0 elsewhere.
            var K = record.ElectionPublicKeys.VoteEncryptionKey;
            Assert.Equal(IntegerModP.PowModP(K, combined[k].EncryptionNonce!.Value + (k == 1 ? 1 : 0)), combined[k].Beta);
        }
    }

    [Fact]
    public void Combine_RefusesNoVectors_VectorsOfDifferentLengths_AndVectorsWithoutNonces()
    {
        var selections = PreEncrypt(CreateEncryptionRecord(), seed: 1).Contests[0].Selections;
        var shortened = selections[1] with { Vector = selections[1].Vector.Take(1).ToList() };
        var withoutNonces = selections[1] with { Vector = selections[1].Vector.Select(x => new EncryptedValue { Alpha = x.Alpha, Beta = x.Beta }).ToList() };

        Assert.Throws<ArgumentException>(() => PreEncryptionPrimitives.Combine([]));
        Assert.Throws<ArgumentException>(() => PreEncryptionPrimitives.Combine([selections[0], shortened]));
        Assert.Throws<ArgumentException>(() => PreEncryptionPrimitives.Combine([selections[0], withoutNonces]));
    }

    /// <summary>
    /// The proofs <see cref="PreEncryptionPrimitives.ProveCombinedContest"/> generates are the
    /// standard ones: a ballot built from them passes Verifications 6, 7 and 15.
    /// </summary>
    [Fact]
    public void ProveCombinedContest_ProofsPassVerifications6And7()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var (id, ballotNonce) = Seed(1);
        var ballot = PreEncryptedBallotFixtures.PreEncrypt(record, DeviceId, "ballot-1", BallotStyleId, id, ballotNonce, null);
        var selections = new Ballot
        {
            Id = "ballot-1",
            BallotStyleId = BallotStyleId,
            Contests = [new BallotContest { Id = record.Manifest.Contests[0].Id, Choices = [new BallotChoice { Id = record.Manifest.Contests[0].Choices[1].Id, SelectionValue = 1 }] }],
        };

        var cast = PreEncryptedBallotFixtures.RecordCast(record, ballot, ballotNonce, selections);

        new SelectionEncryptionsWellFormedVerification().Verify(cast, record);
        new AdherenceToVoteLimitsVerification().Verify(cast, record);
        new SelectionVectorAccumulationVerification().Verify(cast, record);
        Assert.Equal(record.Manifest.Contests[0].Id, cast.Contests[0].Id);
        Assert.Equal(ballot.Contests[0].ContestHash, cast.Contests[0].ContestHash);
        Assert.Empty(cast.Contests[0].SupplementalFields);
        Assert.Null(cast.Contests[0].ContestData);
    }

    [Fact]
    public void ProveCombinedContest_RefusesValuesWithNoValidProof_AndMismatchedLengths()
    {
        var record = CreateEncryptionRecord(selectionLimit: 1);
        var contest = record.Manifest.Contests[0];
        var preEncrypted = PreEncrypt(record, seed: 1).Contests[0];
        var keys = record.ElectionPublicKeys;
        var selectionHash = SelectionHash(record, 1);
        var combined = PreEncryptionPrimitives.Combine([preEncrypted.Selections[0]]);

        EncryptedContest Prove(IReadOnlyList<EncryptedValue> components, IReadOnlyList<int> values) =>
            PreEncryptionPrimitives.ProveCombinedContest(keys, contest, selectionHash, components, values, preEncrypted.ContestHash);

        // R = 1 for a component, L = 1 for the contest.
        Assert.Throws<ArgumentOutOfRangeException>(() => Prove(combined, [2, 0]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Prove(combined, [-1, 0]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Prove(combined, [1, 1]));
        Assert.Throws<ArgumentException>(() => Prove(combined, [1]));
        Assert.Throws<ArgumentException>(() => Prove(combined.Take(1).ToList(), [1]));
        Assert.Throws<ArgumentException>(() => Prove(combined.Select(x => new EncryptedValue { Alpha = x.Alpha, Beta = x.Beta }).ToList(), [1, 0]));
        Assert.Equal(2, Prove(combined, [1, 0]).Choices.Count);
    }

    /// <summary>
    /// S9c review round 1: the per-contest primitives take a bare <see cref="Contest"/>, so they check
    /// the §3.1.3 option numbering themselves (only <see cref="PreEncryptionPrimitives.GenerateContests"/>
    /// sees the manifest). With option indices {1, 2, 4}, the first null vector would be numbered 5
    /// while every verifier expects m + 1 = 4 (eq. 121), and with {1, 3} or a reversed list the
    /// proofs would hash indices no verifier uses; each is refused as <see cref="InvalidManifestException"/>.
    /// A contest with no options is an <see cref="ArgumentException"/> from every one of them.
    /// </summary>
    [Fact]
    public void PerContestPrimitives_OptionsNotNumberedOneToM_OrNoOptions_Throw()
    {
        var record = CreateEncryptionRecord(selectionLimit: 1);
        var contest = record.Manifest.Contests[0];
        var keys = record.ElectionPublicKeys;
        var selectionHash = SelectionHash(record, 1);
        var (_, ballotNonce) = Seed(1);
        var preEncrypted = PreEncrypt(record, seed: 1).Contests[0];
        var combined = PreEncryptionPrimitives.Combine([preEncrypted.Selections[0]]);
        Assert.Equal([1, 2], contest.Choices.Select(x => x.Index));

        var gapped = contest with { Choices = [.. contest.Choices, contest.Choices[1] with { Id = "choice-4", Index = 4 }] };
        var skipped = contest with { Choices = [contest.Choices[0], contest.Choices[1] with { Index = 3 }] };
        var reversed = contest with { Choices = [contest.Choices[1], contest.Choices[0]] };
        foreach (var bad in new[] { gapped, skipped, reversed })
        {
            Assert.Throws<InvalidManifestException>(() => PreEncryptionPrimitives.GenerateContest(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, bad));
            Assert.Throws<InvalidManifestException>(() => PreEncryptionPrimitives.GenerateSelection(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, bad, 1));
            Assert.Throws<InvalidManifestException>(() => PreEncryptionPrimitives.ProveCombinedContest(keys, bad, selectionHash, combined, [1, 0], preEncrypted.ContestHash));
        }

        var empty = contest with { Choices = [] };
        Assert.Throws<ArgumentException>(() => PreEncryptionPrimitives.GenerateContest(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, empty));
        Assert.Throws<ArgumentException>(() => PreEncryptionPrimitives.GenerateSelection(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, empty, 1));
        Assert.Throws<ArgumentException>(() => PreEncryptionPrimitives.ProveCombinedContest(keys, empty, selectionHash, [], [], preEncrypted.ContestHash));

        // The manifest's own contest still works.
        Assert.Equal(3, PreEncryptionPrimitives.GenerateContest(keys, HashTrimmingFunction.TwoHex, selectionHash, ballotNonce, contest).Selections.Count);
    }
}
