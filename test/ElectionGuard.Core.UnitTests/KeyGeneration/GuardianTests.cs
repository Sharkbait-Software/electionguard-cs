using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.KeyGeneration;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.KeyGeneration;

public class GuardianTests
{
    public GuardianTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    // Mirrors GuardianPublicKeyVerification's "2.C" challenge recomputation (see
    // Verify/KeyGeneration/GuardianPublicKeyVerification.cs), but exercised independently here
    // at the GenerateKeys() level to pin that freshly generated keys always produce a
    // self-consistent Schnorr proof.
    private static IntegerModQ RecomputeSchnorrChallenge(
        GuardianIndex index,
        string encryptionKeyType,
        List<IntegerModP> commitments,
        IntegerModP communicationPublicKey,
        SchnorrProof proof)
    {
        int k = EGParameters.GuardianParameters.K;
        var hValues = new List<IntegerModP>();
        for (int j = 0; j < k; j++)
        {
            var hij = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, proof.Responses[j])
                * IntegerModP.PowModP(commitments[j], proof.Challenge);
            hValues.Add(hij);
        }

        var hik = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, proof.Responses[k])
            * IntegerModP.PowModP(communicationPublicKey, proof.Challenge);
        hValues.Add(hik);

        List<byte[]> bytesToHash = [
            [0x10],
            System.Text.Encoding.UTF8.GetBytes(encryptionKeyType),
            index,
        ];
        bytesToHash.AddRange(commitments.Select(c => c.ToByteArray()));
        bytesToHash.Add(communicationPublicKey.ToByteArray());
        bytesToHash.AddRange(hValues.Select(h => h.ToByteArray()));

        return EGHash.HashModQ(EGParameters.ParameterBaseHash, bytesToHash.ToArray());
    }

    // Fabricates a brand-new, internally self-consistent SchnorrProof + commitment set for the
    // "other ballot data" (or "vote") encryption key of an *existing* guardian's communication
    // key pair, by replicating Guardian.GenerateKeyProof's formula (that method is private, so we
    // reproduce the public-facing math here, the same way the Models phase hand-computes hashes).
    // Because the proof is generated with knowledge of real secret keys and matches exactly the
    // recomputation GuardianPublicKeyVerification performs, this proof passes Verification 2 (2.A
    // subgroup check + 2.C challenge check) even though the underlying secret values are
    // completely unrelated to what the guardian actually shared with anyone.
    private static (List<IntegerModP> Commitments, SchnorrProof Proof) GenerateSelfConsistentProof(
        GuardianIndex index,
        KeyPair communicationKeyPair,
        string encryptionKeyType)
    {
        int k = EGParameters.GuardianParameters.K;

        var keyPairs = new List<KeyPair>();
        for (int i = 0; i < k; i++)
        {
            keyPairs.Add(KeyPair.GenerateRandom());
        }

        var randomKeyPairs = new List<KeyPair>();
        for (int i = 0; i <= k; i++)
        {
            randomKeyPairs.Add(KeyPair.GenerateRandom());
        }

        List<byte[]> bytesToHash = [
            [0x10],
            System.Text.Encoding.UTF8.GetBytes(encryptionKeyType),
            index,
        ];
        bytesToHash.AddRange(keyPairs.Select(x => x.PublicKey.ToByteArray()));
        bytesToHash.Add(communicationKeyPair.PublicKey.ToByteArray());
        bytesToHash.AddRange(randomKeyPairs.Select(x => x.PublicKey.ToByteArray()));

        IntegerModQ challengeValue = EGHash.HashModQ(EGParameters.ParameterBaseHash, bytesToHash.ToArray());

        var responseValues = new List<IntegerModQ>();
        for (int i = 0; i < k; i++)
        {
            responseValues.Add(randomKeyPairs[i].SecretKey - challengeValue * keyPairs[i].SecretKey);
        }
        responseValues.Add(randomKeyPairs[k].SecretKey - challengeValue * communicationKeyPair.SecretKey);

        var proof = new SchnorrProof
        {
            Challenge = challengeValue,
            Responses = responseValues.ToArray(),
        };

        return (keyPairs.Select(x => x.PublicKey).ToList(), proof);
    }

    [Fact]
    public void Constructor_IndexGreaterThanN_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Guardian(new GuardianIndex(EGParameters.GuardianParameters.N + 1)));
    }

    // Inverted in S2 (audit G5). This used to pin that index 0 was accepted, which was the bug:
    // guardians are G_1..G_n (§3.2.1), and the share a guardian would send to index 0 is
    // P_i(0) = a_{i,0} = s_i, its secret key. Index 0 is now rejected as soon as it is made into a
    // GuardianIndex, so no Guardian, view or share can carry it.
    [Fact]
    public void Constructor_IndexZero_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Guardian(new GuardianIndex(0)));
    }

    [Fact]
    public void Constructor_IndexOneAndN_AreAccepted()
    {
        Assert.Null(Record.Exception(() => new Guardian(new GuardianIndex(1))));
        Assert.Null(Record.Exception(() => new Guardian(new GuardianIndex(EGParameters.GuardianParameters.N))));
    }

    [Fact]
    public void Constructor_NegativeIndex_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Guardian(new GuardianIndex(-1)));
    }

    [Fact]
    public void GenerateKeys_VoteEncryptionProof_IsSelfConsistentSchnorrProof()
    {
        var guardian = new Guardian(new GuardianIndex(1));

        var keys = guardian.GenerateKeys();
        var publicView = keys.ToPublicView();

        var recomputedChallenge = RecomputeSchnorrChallenge(
            publicView.Index,
            "pk_vote",
            publicView.VoteEncryptionCommitments,
            publicView.CommunicationPublicKey,
            publicView.VoteEncryptionProof);

        Assert.Equal(publicView.VoteEncryptionProof.Challenge, recomputedChallenge);
    }

    [Fact]
    public void GenerateKeys_OtherDataEncryptionProof_IsSelfConsistentSchnorrProof()
    {
        var guardian = new Guardian(new GuardianIndex(1));

        var keys = guardian.GenerateKeys();
        var publicView = keys.ToPublicView();

        var recomputedChallenge = RecomputeSchnorrChallenge(
            publicView.Index,
            "pk_data",
            publicView.OtherBallotDataEncryptionCommitments,
            publicView.CommunicationPublicKey,
            publicView.OtherDataEncryptionProof);

        Assert.Equal(publicView.OtherDataEncryptionProof.Challenge, recomputedChallenge);
    }

    [Fact]
    public void GenerateKeys_ProducesDistinctCommitmentsPerGuardian()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        var voteCommitments = guardianSet.GuardianPublicViews.Select(v => v.VoteEncryptionCommitments[0]).ToList();
        var communicationKeys = guardianSet.GuardianPublicViews.Select(v => v.CommunicationPublicKey).ToList();

        Assert.Equal(voteCommitments.Count, voteCommitments.Distinct().Count());
        Assert.Equal(communicationKeys.Count, communicationKeys.Distinct().Count());
    }

    [Fact]
    public void EncryptShares_DecryptShares_RoundTrip_ForFullGuardianSet_ProducesConsistentDecryptedShares()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        // Assert on the actual decrypted share values (closing the gap noted in research.md re:
        // CryptographicParameterTests.Guardian_EncryptedShares_Valid, which only asserts
        // "doesn't throw"). Each guardian's total secret share z_i must satisfy
        // g^z_i == product over every guardian g of (product over j of commitments_g[j]^(i^j)) --
        // the same joint-polynomial identity Guardian.Verify checks per-source internally, summed
        // here across the whole set for the guardian's combined share.
        foreach (var guardian in guardianSet.Guardians)
        {
            int i = guardian.Index.Index;
            var secretShare = guardianSet.SecretShares[guardian.Index];

            var expectedVoteShareKey = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, secretShare.VoteEncryptionKeyShare);
            var actualVoteShareKey = guardianSet.GuardianPublicViews
                .SelectMany(pv => pv.VoteEncryptionCommitments.Select((c, j) => IntegerModP.PowModP(c, BigInteger.Pow(i, j))))
                .Product();
            Assert.Equal(expectedVoteShareKey, actualVoteShareKey);

            var expectedOtherShareKey = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, secretShare.OtherBallotDataEncryptionKeyShare);
            var actualOtherShareKey = guardianSet.GuardianPublicViews
                .SelectMany(pv => pv.OtherBallotDataEncryptionCommitments.Select((c, j) => IntegerModP.PowModP(c, BigInteger.Pow(i, j))))
                .Product();
            Assert.Equal(expectedOtherShareKey, actualOtherShareKey);
        }
    }

    [Fact]
    public void EncryptShares_DecryptShares_TamperedShare_ThrowsInvalidOperationException()
    {
        // S2 (G5/G15): EncryptShares and DecryptShares now require one entry for each of the other
        // n - 1 guardians, so this runs the full default 3-guardian exchange and tampers one of the
        // two shares guardian 2 receives. The tamper and the expected exception are unchanged.
        var (guardians, _, shares) = ExchangeShares();
        var guardian2 = guardians[1];
        var shareToGuardian2 = shares.Single(x => x.SourceIndex.Index == 1 && x.DestinationIndex.Index == 2);
        var otherShareToGuardian2 = shares.Single(x => x.SourceIndex.Index == 3 && x.DestinationIndex.Index == 2);

        // C1 feeds directly into the Schnorr challenge (cBar) recomputed during decryption, so
        // tampering it (rather than the response/challenge fields) is what actually exercises the
        // "could not decrypt" path at Guardian.cs's DecryptShares.
        var tamperedC1 = (byte[])shareToGuardian2.C1.Clone();
        tamperedC1[0] ^= 0xFF;

        var tamperedShare = new GuardianEncryptedShare
        {
            SourceIndex = shareToGuardian2.SourceIndex,
            DestinationIndex = shareToGuardian2.DestinationIndex,
            C0 = shareToGuardian2.C0,
            C1 = tamperedC1,
            Challenge = shareToGuardian2.Challenge,
            Response = shareToGuardian2.Response,
        };

        Assert.Throws<InvalidOperationException>(() => guardian2.DecryptShares(new List<GuardianEncryptedShare> { tamperedShare, otherShareToGuardian2 }));
    }

    [Fact]
    public void Verify_ValidGuardianRecord_DoesNotThrow()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        var exception = Record.Exception(() => guardianSet.Guardians[0].Verify(guardianSet.GuardianRecord));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_MissingOriginalGuardianData_ThrowsException()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        // A guardian that never called EncryptShares/DecryptShares has no original data
        // (_guardians / _voteEncryptionSharePolynomials / _otherBallotDataEncryptionSharePolynomials
        // are all null) to compare the record against -- Guardian.Verify throws a plain
        // Exception here, not a VerificationFailedException.
        var freshGuardian = new Guardian(new GuardianIndex(1));

        var exception = Assert.Throws<Exception>(() => freshGuardian.Verify(guardianSet.GuardianRecord));

        Assert.Contains("Don't have original guardian data", exception.Message);
    }

    [Fact]
    public void Verify_MismatchedGuardianRecord_ThrowsOriginalValuesException()
    {
        // Was a GENUINE BUG (now fixed): Guardian.Verify's "original guardian values" comparison
        // built a fresh `valuesToHash` list from `record.Guardians` / `record.ElectionPublicKeys`,
        // but then computed `valuesHash` by hashing `originalValuesToHash` again (a copy-paste bug
        // -- it hashed the same array twice instead of hashing `valuesToHash`). That made the check
        // dead code: no matter how thoroughly the passed GuardianRecord disagreed with what this
        // guardian actually received, it could never fire.
        //
        // Fixed by hashing `valuesToHash` (the record under verification) instead of
        // `originalValuesToHash` a second time. This test proves the check now fires by feeding a
        // guardian a completely different (but independently self-consistent, individually-valid)
        // GuardianRecord from an unrelated guardian set -- exactly the canonical case this check
        // exists to catch.
        var setA = ElectionFixtureBuilder.CreateGuardianSet();
        var setB = ElectionFixtureBuilder.CreateGuardianSet();

        var verifyingGuardian = setA.Guardians[0];

        // S2: the H_G comparison (§3.2.2 step 1) now throws the typed KeyCeremonyException, a
        // subclass of Exception, so the exact-type assertion names it and also pins the step.
        var exception = Assert.Throws<KeyCeremonyException>(() => verifyingGuardian.Verify(setB.GuardianRecord));

        Assert.Contains("Original guardian values did not match", exception.Message);
        Assert.Equal(1, exception.Step);
        Assert.Null(exception.OffendingGuardian);
        Assert.IsNotType<VerificationFailedException>(exception);
    }

    [Fact]
    public void Verify_RecordFromAnUnrelatedGuardianSet_FailsStep1_BeforeEq28()
    {
        // Formerly Verify_VoteEncryptionPolynomialMismatch_ThrowsException. Since
        // Verify_MismatchedGuardianRecord_ThrowsOriginalValuesException's fix (the "original
        // guardian values" copy-paste bug), a record from a wholly unrelated guardian set is caught
        // by the H_G comparison of §3.2.2 step 1 and never reaches the eq. (28) share check of
        // step 4. That check is exercised on its own by
        // Verify_VoteShareInconsistentWithPublishedCommitments_FailsEq28_NamingTheSender.
        var setA = ElectionFixtureBuilder.CreateGuardianSet();
        var setB = ElectionFixtureBuilder.CreateGuardianSet();

        var verifyingGuardian = setA.Guardians[0];

        var exception = Assert.Throws<KeyCeremonyException>(() => verifyingGuardian.Verify(setB.GuardianRecord));

        Assert.Contains("Original guardian values did not match", exception.Message);
        Assert.Equal(1, exception.Step);
        Assert.IsNotType<VerificationFailedException>(exception);
    }

    [Fact]
    public void Verify_RecordWithReplacedBallotDataCommitments_FailsStep1_BeforeEq29()
    {
        // Formerly Verify_OtherBallotDataPolynomialMismatch_ThrowsException. The record (and only
        // the record) carries replaced K-hat commitments for one guardian, with a valid proof over
        // them. The verifying guardian still holds that guardian's original view, so the H_G
        // comparison of §3.2.2 step 1 catches it and the eq. (29) share check of step 4 is never
        // reached. That check is exercised on its own by
        // Verify_BallotDataShareInconsistentWithPublishedCommitments_FailsEq29_NamingTheSender, where
        // every guardian is shown the replaced view.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        var verifyingGuardian = guardianSet.Guardians[0];
        var targetIndex = guardianSet.Guardians[1].Index;

        var targetOriginalView = guardianSet.GuardianPublicViews.Single(v => v.Index == targetIndex);
        var targetCommunicationKeyPair = guardianSet.GuardianKeys.Single(k => k.Index == targetIndex).CommunicationKeyPair;

        // A self-consistent (but unrelated) "other ballot data" commitment set and proof for the
        // target guardian's own communication key; its vote-encryption commitments/proof are untouched.
        var (fakeCommitments, fakeProof) = GenerateSelfConsistentProof(targetIndex, targetCommunicationKeyPair, "pk_data");

        var tamperedView = new GuardianPublicView
        {
            Index = targetOriginalView.Index,
            VoteEncryptionCommitments = targetOriginalView.VoteEncryptionCommitments,
            VoteEncryptionProof = targetOriginalView.VoteEncryptionProof,
            CommunicationPublicKey = targetOriginalView.CommunicationPublicKey,
            OtherBallotDataEncryptionCommitments = fakeCommitments,
            OtherDataEncryptionProof = fakeProof,
        };

        var tamperedGuardians = guardianSet.GuardianPublicViews
            .Select(v => v.Index == targetIndex ? tamperedView : v)
            .ToList();

        var tamperedElectionPublicKeys = new ElectionPublicKeys(
            tamperedGuardians.Select(v => v.VoteEncryptionCommitments[0]),
            tamperedGuardians.Select(v => v.OtherBallotDataEncryptionCommitments[0]));

        var tamperedRecord = new GuardianRecord
        {
            CryptographicParameters = EGParameters.CryptographicParameters,
            GuardianParameters = EGParameters.GuardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = guardianSet.GuardianRecord.ManifestFile,
            ElectionBaseHash = guardianSet.GuardianRecord.ElectionBaseHash,
            Guardians = tamperedGuardians,
            ElectionPublicKeys = tamperedElectionPublicKeys,
        };

        // H_G hashes the entire guardian list and the election public keys, so this tamper (unlike a
        // share-only attack that never touches the public record) is detected at step 1.
        var exception = Assert.Throws<KeyCeremonyException>(() => verifyingGuardian.Verify(tamperedRecord));

        Assert.Contains("Original guardian values did not match", exception.Message);
        Assert.Equal(1, exception.Step);
        Assert.IsNotType<VerificationFailedException>(exception);
    }

    [Fact]
    public void Verify_DelegatesToParameterVerification_PropagatesVerificationFailedException()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        var tamperedParameters = new CryptographicParameters(
            "v2.0.0",
            CryptographicParameters.Q_DEFAULT_HEX,
            CryptographicParameters.P_DEFAULT_HEX,
            CryptographicParameters.R_DEFAULT_HEX,
            CryptographicParameters.G_DEFAULT_HEX);

        var tamperedRecord = new GuardianRecord
        {
            CryptographicParameters = tamperedParameters,
            GuardianParameters = guardianSet.GuardianRecord.GuardianParameters,
            ParameterBaseHash = guardianSet.GuardianRecord.ParameterBaseHash,
            ManifestFile = guardianSet.GuardianRecord.ManifestFile,
            ElectionBaseHash = guardianSet.GuardianRecord.ElectionBaseHash,
            Guardians = guardianSet.GuardianRecord.Guardians,
            ElectionPublicKeys = guardianSet.GuardianRecord.ElectionPublicKeys,
        };

        // Guardian.Verify delegates the CryptographicParameters check to ParameterVerification
        // (Verification 1), which throws the typed VerificationFailedException with a "1.*"
        // SubSection -- distinct from Guardian.Verify's own KeyCeremonyException throw sites
        // (steps 1 and 4) exercised by the tests above and below.
        var exception = Assert.Throws<VerificationFailedException>(() => guardianSet.Guardians[0].Verify(tamperedRecord));

        Assert.StartsWith("1.", exception.SubSection);
    }

    // --- S2: the guardian set, the shares, H_B and attribution (audit G5, G15, G26, G34) ---------

    /// <summary>
    /// Runs key generation and share encryption for the default n guardians, stopping before any
    /// guardian decrypts, so a test can feed DecryptShares a share set of its own choosing.
    /// </summary>
    private static (List<Guardian> Guardians, List<GuardianPublicView> Views, List<GuardianEncryptedShare> Shares) ExchangeShares()
    {
        int n = EGParameters.GuardianParameters.N;
        var guardians = Enumerable.Range(1, n).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();
        var shares = guardians
            .SelectMany(g => g.EncryptShares(views.Where(v => v.Index != g.Index).ToList()))
            .ToList();

        return (guardians, views, shares);
    }

    private static List<GuardianEncryptedShare> SharesTo(List<GuardianEncryptedShare> shares, int destination) =>
        shares.Where(x => x.DestinationIndex.Index == destination).ToList();

    private static GuardianEncryptedShare Readdressed(GuardianEncryptedShare share, int source, int destination) => new()
    {
        SourceIndex = new GuardianIndex(source),
        DestinationIndex = new GuardianIndex(destination),
        C0 = share.C0,
        C1 = share.C1,
        Challenge = share.Challenge,
        Response = share.Response,
    };

    private static GuardianPublicView WithIndex(GuardianPublicView view, int index) => new()
    {
        Index = new GuardianIndex(index),
        VoteEncryptionCommitments = view.VoteEncryptionCommitments,
        OtherBallotDataEncryptionCommitments = view.OtherBallotDataEncryptionCommitments,
        CommunicationPublicKey = view.CommunicationPublicKey,
        VoteEncryptionProof = view.VoteEncryptionProof,
        OtherDataEncryptionProof = view.OtherDataEncryptionProof,
    };

    private static GuardianRecord RecordFor(List<GuardianPublicView> views, ManifestFile manifestFile, ElectionBaseHash? electionBaseHash = null) => new()
    {
        CryptographicParameters = EGParameters.CryptographicParameters,
        GuardianParameters = EGParameters.GuardianParameters,
        ParameterBaseHash = EGParameters.ParameterBaseHash,
        ManifestFile = manifestFile,
        ElectionBaseHash = electionBaseHash ?? new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile),
        Guardians = views,
        ElectionPublicKeys = new ElectionPublicKeys(
            views.Select(v => v.VoteEncryptionCommitments[0]),
            views.Select(v => v.OtherBallotDataEncryptionCommitments[0])),
    };

    [Fact]
    public void EncryptShares_PeerListIncludingItself_Throws()
    {
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();

        // Guardian 1 would be sending P_1(1) to itself, in place of guardian 3's share.
        var exception = Assert.Throws<ArgumentException>(() => guardians[0].EncryptShares([views[0], views[1]]));

        Assert.Contains("this guardian itself (1)", exception.Message);
    }

    [Fact]
    public void EncryptShares_DuplicatePeer_Throws()
    {
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();

        var exception = Assert.Throws<ArgumentException>(() => guardians[0].EncryptShares([views[1], views[1]]));

        Assert.Contains("More than one guardian view for guardian 2", exception.Message);
    }

    [Fact]
    public void EncryptShares_MissingPeer_Throws()
    {
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();

        var exception = Assert.Throws<ArgumentException>(() => guardians[0].EncryptShares([views[1]]));

        Assert.Contains("missing guardian(s) 3", exception.Message);
    }

    [Fact]
    public void EncryptShares_ExtraPointsBeyondN_Throws()
    {
        // The attack G5 describes in its general form: with k extra evaluation points a recipient
        // could interpolate the whole polynomial, and with it s_i. Indices above n are refused.
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();

        var exception = Assert.Throws<ArgumentException>(() => guardians[0].EncryptShares([views[1], views[2], WithIndex(views[2], 4)]));

        Assert.Contains("guardian 4", exception.Message);
    }

    [Fact]
    public void EncryptShares_DoesNotModifyTheCallersList()
    {
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();
        var peers = new List<GuardianPublicView> { views[1], views[2] };

        guardians[0].EncryptShares(peers);

        Assert.Equal(new[] { views[1], views[2] }, peers);
    }

    [Fact]
    public void SingleGuardianElection_HasNoPeers_AndCompletes()
    {
        // n = 1 is allowed (1 <= k <= n): there is no other guardian, so the peer list and the
        // share list are both empty, and the record still verifies.
        using var scope = EGParameters.OverrideScope(new CryptographicParameters(), new GuardianParameters(1, 1));

        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(1, 1);

        Assert.Single(guardianSet.Guardians);
        Assert.Null(Record.Exception(() => guardianSet.Guardians[0].Verify(guardianSet.GuardianRecord)));
    }

    [Fact]
    public void DecryptShares_MissingShare_Throws()
    {
        var (guardians, _, shares) = ExchangeShares();
        var toGuardian2 = SharesTo(shares, 2).Where(x => x.SourceIndex.Index != 3).ToList();

        var exception = Assert.Throws<ArgumentException>(() => guardians[1].DecryptShares(toGuardian2));

        Assert.Contains("missing guardian(s) 3", exception.Message);
    }

    [Fact]
    public void DecryptShares_DuplicateShare_Throws()
    {
        // The share from guardian 1 replayed in place of guardian 3's: before S2 it was summed twice
        // into z_2 and nothing noticed until the tally failed to decrypt.
        var (guardians, _, shares) = ExchangeShares();
        var fromGuardian1 = SharesTo(shares, 2).Single(x => x.SourceIndex.Index == 1);

        var exception = Assert.Throws<ArgumentException>(() => guardians[1].DecryptShares([fromGuardian1, fromGuardian1]));

        Assert.Contains("More than one share for guardian 1", exception.Message);
    }

    [Fact]
    public void DecryptShares_ShareAddressedToAnotherGuardian_Throws()
    {
        var (guardians, _, shares) = ExchangeShares();
        var toGuardian2 = SharesTo(shares, 2);
        var fromGuardian1ToGuardian3 = SharesTo(shares, 3).Single(x => x.SourceIndex.Index == 1);

        var exception = Assert.Throws<ArgumentException>(() => guardians[1].DecryptShares([toGuardian2[0], fromGuardian1ToGuardian3]));

        Assert.Contains("addressed to guardian 3", exception.Message);
    }

    [Fact]
    public void DecryptShares_ShareClaimingToComeFromItself_Throws()
    {
        var (guardians, _, shares) = ExchangeShares();
        var toGuardian2 = SharesTo(shares, 2);

        var exception = Assert.Throws<ArgumentException>(() => guardians[1].DecryptShares([toGuardian2[0], Readdressed(toGuardian2[1], 2, 2)]));

        Assert.Contains("this guardian itself (2)", exception.Message);
    }

    [Fact]
    public void DecryptShares_ShareFromAnIndexAboveN_Throws()
    {
        var (guardians, _, shares) = ExchangeShares();
        var toGuardian2 = SharesTo(shares, 2);

        var exception = Assert.Throws<ArgumentException>(() => guardians[1].DecryptShares([toGuardian2[0], Readdressed(toGuardian2[1], 4, 2)]));

        Assert.Contains("guardian 4", exception.Message);
    }

    [Fact]
    public void Verify_ShareInconsistentWithItsSendersCommitments_NamesTheSender()
    {
        // §3.2.2 step 4 (eqs. 28, 29). Guardian 1 sends shares of one polynomial, then publishes
        // commitments to another: every share it sent decrypts (its encryption proof is about the
        // nonce, not the polynomial) but fails eq. (28) at the recipient, which names guardian 1.
        var manifestFile = ElectionFixtureBuilder.CreateMinimalManifest().ManifestFile;
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();

        var sharesFromGuardian1 = guardians[0].EncryptShares([views[1], views[2]]);
        views[0] = guardians[0].GenerateKeys().ToPublicView();

        var shares = sharesFromGuardian1
            .Concat(guardians[1].EncryptShares([views[0], views[2]]))
            .Concat(guardians[2].EncryptShares([views[0], views[1]]))
            .ToList();
        guardians[1].DecryptShares(SharesTo(shares, 2));

        var exception = Assert.Throws<KeyCeremonyException>(() => guardians[1].Verify(RecordFor(views, manifestFile), manifestFile));

        Assert.Equal(4, exception.Step);
        Assert.Equal(new GuardianIndex(1), exception.OffendingGuardian);
    }

    /// <summary>
    /// Guardian 1 publishes, and shows every other guardian, a view whose commitments for one key
    /// (<paramref name="encryptionKeyType"/>, "pk_vote" or "pk_data") are replaced by commitments
    /// to an unrelated polynomial, with a valid proof over them; everything else is its real key
    /// data. It still sends shares of its real polynomials. Every guardian agrees on the record, so
    /// H_G (step 1), Verification 2 (step 2) and Verification 3 (step 3) all pass, and the only
    /// failure left is the matching half of step 4 at guardian 2.
    /// </summary>
    private static KeyCeremonyException VerifyWithGuardian1CommitmentsReplaced(string encryptionKeyType)
    {
        var manifestFile = ElectionFixtureBuilder.CreateMinimalManifest().ManifestFile;
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var keys = guardians.Select(g => g.GenerateKeys()).ToList();
        var views = keys.Select(k => k.ToPublicView()).ToList();

        var real = views[0];
        var (fakeCommitments, fakeProof) = GenerateSelfConsistentProof(real.Index, keys[0].CommunicationKeyPair, encryptionKeyType);
        bool replaceVote = encryptionKeyType == "pk_vote";
        views[0] = new GuardianPublicView
        {
            Index = real.Index,
            VoteEncryptionCommitments = replaceVote ? fakeCommitments : real.VoteEncryptionCommitments,
            VoteEncryptionProof = replaceVote ? fakeProof : real.VoteEncryptionProof,
            CommunicationPublicKey = real.CommunicationPublicKey,
            OtherBallotDataEncryptionCommitments = replaceVote ? real.OtherBallotDataEncryptionCommitments : fakeCommitments,
            OtherDataEncryptionProof = replaceVote ? real.OtherDataEncryptionProof : fakeProof,
        };

        // Guardian 1 encrypts shares of its real polynomials; guardians 2 and 3 receive (and so
        // hold, for the H_G comparison) the replaced view of guardian 1.
        var shares = guardians[0].EncryptShares([views[1], views[2]])
            .Concat(guardians[1].EncryptShares([views[0], views[2]]))
            .Concat(guardians[2].EncryptShares([views[0], views[1]]))
            .ToList();
        guardians[1].DecryptShares(SharesTo(shares, 2));

        var record = RecordFor(views, manifestFile);

        // Steps 1-3 on their own pass over this record: the failure below is step 4 and nothing earlier.
        new GuardianPublicKeyVerification().Verify(record.Guardians);
        new ElectionPublicKeyVerification().Verify(record.Guardians, record.ElectionPublicKeys);

        return Assert.Throws<KeyCeremonyException>(() => guardians[1].Verify(record, manifestFile));
    }

    [Fact]
    public void Verify_VoteShareInconsistentWithPublishedCommitments_FailsEq28_NamingTheSender()
    {
        var exception = VerifyWithGuardian1CommitmentsReplaced("pk_vote");

        Assert.Equal(4, exception.Step);
        Assert.Equal(new GuardianIndex(1), exception.OffendingGuardian);
        Assert.Contains("vote encryption polynomial", exception.Message);
        Assert.DoesNotContain("other ballot data", exception.Message);
    }

    [Fact]
    public void Verify_BallotDataShareInconsistentWithPublishedCommitments_FailsEq29_NamingTheSender()
    {
        // G15 covers both halves of step 4. Here guardian 1's vote commitments are its real ones,
        // so eq. (28) passes for every sender and only eq. (29) (P-hat_1(2) against K-hat_{1,j}) fails.
        var exception = VerifyWithGuardian1CommitmentsReplaced("pk_data");

        Assert.Equal(4, exception.Step);
        Assert.Equal(new GuardianIndex(1), exception.OffendingGuardian);
        Assert.Contains("other ballot data encryption polynomial", exception.Message);
    }

    [Theory]
    [InlineData("pk_vote", 0)]
    [InlineData("pk_data", 0)]
    [InlineData("pk_vote", 3)]
    [InlineData("pk_data", 3)]
    public void Verify_PeerViewWithWrongNumberOfCommitments_FailsStep1_NamingThatGuardian(string encryptionKeyType, int commitmentCount)
    {
        // EncryptShares reads only a peer view's index and communication key, so guardian 2 can be
        // handed a view of guardian 3 whose commitment list is empty (or k + 1 long) and still
        // complete the share exchange. Step 1 builds K = prod K_{i,0} from the views it holds; it
        // must report guardian 3, not throw an out-of-range error from indexing an empty list.
        var manifestFile = ElectionFixtureBuilder.CreateMinimalManifest().ManifestFile;
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();

        var real = views[2];
        var reshaped = Enumerable.Range(0, commitmentCount).Select(j => real.VoteEncryptionCommitments[j % real.VoteEncryptionCommitments.Count]).ToList();
        bool reshapeVote = encryptionKeyType == "pk_vote";
        var malformedView = new GuardianPublicView
        {
            Index = real.Index,
            VoteEncryptionCommitments = reshapeVote ? reshaped : real.VoteEncryptionCommitments,
            OtherBallotDataEncryptionCommitments = reshapeVote ? real.OtherBallotDataEncryptionCommitments : reshaped,
            CommunicationPublicKey = real.CommunicationPublicKey,
            VoteEncryptionProof = real.VoteEncryptionProof,
            OtherDataEncryptionProof = real.OtherDataEncryptionProof,
        };

        var shares = guardians[0].EncryptShares([views[1], views[2]])
            .Concat(guardians[1].EncryptShares([views[0], malformedView]))
            .Concat(guardians[2].EncryptShares([views[0], views[1]]))
            .ToList();
        guardians[1].DecryptShares(SharesTo(shares, 2));

        var exception = Assert.Throws<KeyCeremonyException>(() => guardians[1].Verify(RecordFor(views, manifestFile), manifestFile));

        Assert.Equal(1, exception.Step);
        Assert.Equal(new GuardianIndex(3), exception.OffendingGuardian);
    }

    [Theory]
    [InlineData("pk_vote")]
    [InlineData("pk_data")]
    public void Verify_GuardianWithAnInvalidKeyProof_FailsStep2(string encryptionKeyType)
    {
        // §3.2.2 step 2 (Verification 2) is the only check this record fails. Guardian 1's view
        // carries its real commitments and sends real shares, but one response of one proof is
        // changed. Every guardian is shown that same view, so H_G agrees (step 1 hashes no proofs);
        // K and K-hat are the real products (step 3); every share matches its commitments (step 4).
        var manifestFile = ElectionFixtureBuilder.CreateMinimalManifest().ManifestFile;
        var guardians = Enumerable.Range(1, 3).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(g => g.GenerateKeys().ToPublicView()).ToList();

        var real = views[0];
        bool corruptVote = encryptionKeyType == "pk_vote";
        var proofToCorrupt = corruptVote ? real.VoteEncryptionProof : real.OtherDataEncryptionProof;
        var responses = proofToCorrupt.Responses.ToArray();
        responses[0] = responses[0] + new IntegerModQ(1);
        var corruptedProof = new SchnorrProof { Challenge = proofToCorrupt.Challenge, Responses = responses };
        views[0] = new GuardianPublicView
        {
            Index = real.Index,
            VoteEncryptionCommitments = real.VoteEncryptionCommitments,
            OtherBallotDataEncryptionCommitments = real.OtherBallotDataEncryptionCommitments,
            CommunicationPublicKey = real.CommunicationPublicKey,
            VoteEncryptionProof = corruptVote ? corruptedProof : real.VoteEncryptionProof,
            OtherDataEncryptionProof = corruptVote ? real.OtherDataEncryptionProof : corruptedProof,
        };

        var shares = guardians[0].EncryptShares([views[1], views[2]])
            .Concat(guardians[1].EncryptShares([views[0], views[2]]))
            .Concat(guardians[2].EncryptShares([views[0], views[1]]))
            .ToList();
        guardians[1].DecryptShares(SharesTo(shares, 2));

        var record = RecordFor(views, manifestFile);

        // Step 3 passes on its own, so the failure below is Verification 2 and nothing later.
        new ElectionPublicKeyVerification().Verify(record.Guardians, record.ElectionPublicKeys);

        var exception = Assert.Throws<VerificationFailedException>(() => guardians[1].Verify(record, manifestFile));

        Assert.Equal("2.C", exception.SubSection);
    }

    [Fact]
    public void Verify_RecordWhoseManifestDoesNotMatchItsElectionBaseHash_Fails1F()
    {
        // §3.2.2 step 1: the guardian checks H_B by performing Verification 1. Before S2 the
        // guardian record had no manifest or H_B at all, and 1.F was never run anywhere.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var otherManifest = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true).ManifestFile;
        var tamperedRecord = RecordFor(guardianSet.GuardianPublicViews, otherManifest, guardianSet.GuardianRecord.ElectionBaseHash);

        var exception = Assert.Throws<VerificationFailedException>(() => guardianSet.Guardians[0].Verify(tamperedRecord));

        Assert.Equal("1.F", exception.SubSection);
    }

    [Fact]
    public void Verify_RecordWithAnElectionBaseHashOverAnotherManifest_Fails1F()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var otherManifest = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true).ManifestFile;
        var tamperedRecord = RecordFor(
            guardianSet.GuardianPublicViews,
            guardianSet.GuardianRecord.ManifestFile,
            new ElectionBaseHash(EGParameters.ParameterBaseHash, otherManifest));

        var exception = Assert.Throws<VerificationFailedException>(() => guardianSet.Guardians[0].Verify(tamperedRecord));

        Assert.Equal("1.F", exception.SubSection);
    }

    [Fact]
    public void Verify_RecordOverAManifestOtherThanTheGuardiansOwn_FailsStep1()
    {
        // A record that is internally consistent (1.F passes) but built over a manifest other than
        // the one this guardian holds: H_G keyed with the guardian's own H_B (eq. 27) differs.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var otherManifest = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true).ManifestFile;
        var record = RecordFor(guardianSet.GuardianPublicViews, otherManifest);

        Assert.Null(Record.Exception(() => guardianSet.Guardians[0].Verify(record)));

        var exception = Assert.Throws<KeyCeremonyException>(() => guardianSet.Guardians[0].Verify(record, guardianSet.GuardianRecord.ManifestFile));

        Assert.Equal(1, exception.Step);
    }

    [Fact]
    public void Verify_WithTheGuardiansOwnMatchingManifest_Passes()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        foreach (var guardian in guardianSet.Guardians)
        {
            Assert.Null(Record.Exception(() => guardian.Verify(guardianSet.GuardianRecord, guardianSet.GuardianRecord.ManifestFile)));
        }
    }

    [Fact]
    public void GuardianRecordHash_IsKeyedWithTheElectionBaseHash()
    {
        // Eq. (27) keys H_G with H_B (G34; it was keyed with H_P). The KAT pins the value; this
        // pins that the key is what the caller passes, not a process-wide H_P.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var record = guardianSet.GuardianRecord;

        var keyedWithHB = Guardian.ComputeGuardianRecordHash(record.ElectionBaseHash, record.ElectionPublicKeys, record.Guardians);
        var keyedWithHP = Guardian.ComputeGuardianRecordHash(EGParameters.ParameterBaseHash, record.ElectionPublicKeys, record.Guardians);
        var reversedOrder = Guardian.ComputeGuardianRecordHash(record.ElectionBaseHash, record.ElectionPublicKeys, record.Guardians.AsEnumerable().Reverse());

        Assert.NotEqual(keyedWithHB, keyedWithHP);
        Assert.Equal(keyedWithHB, reversedOrder);
    }
}
