using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.TestFixtures;
using ElectionGuard.Core.Verify;
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

    // Gap-closing test (verified via mutation): the lower-bound half of Guardian's range check
    // (`index < 0`) had no covering test -- every fixture and every other test in this file
    // constructs guardians with indices in [1, N], so mutating the check to `index <= 0` (which
    // would additionally reject index 0) left the entire GuardianTests + GuardianIndexTests suite
    // green. This pins that index 0 is accepted (it is a valid boundary per the current `< 0`
    // check) and index -1 is rejected, so a boundary-flip mutation on the lower bound fails here.
    [Fact]
    public void Constructor_IndexZero_DoesNotThrow()
    {
        var exception = Record.Exception(() => new Guardian(new GuardianIndex(0)));

        Assert.Null(exception);
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
        var guardian1 = new Guardian(new GuardianIndex(1));
        var guardian2 = new Guardian(new GuardianIndex(2));

        guardian1.GenerateKeys();
        var guardian2Keys = guardian2.GenerateKeys();

        var sharesFromGuardian1 = guardian1.EncryptShares(new List<GuardianPublicView> { guardian2Keys.ToPublicView() });
        var shareToGuardian2 = sharesFromGuardian1.Single();

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

        Assert.Throws<InvalidOperationException>(() => guardian2.DecryptShares(new List<GuardianEncryptedShare> { tamperedShare }));
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
    public void Verify_MismatchedGuardianRecord_DoesNotThrowOriginalValuesException_DueToComparisonBug()
    {
        // GENUINE BUG, PINNED NOT FIXED (per CLAUDE.md / task instructions -- production code is
        // not modified as part of test generation): Guardian.Verify's "original guardian values"
        // comparison builds a fresh `valuesToHash` list from `record.Guardians` /
        // `record.ElectionPublicKeys`, but then computes `valuesHash` by hashing
        // `originalValuesToHash` again (a copy-paste bug -- it should hash `valuesToHash`).
        // `originalValuesHash` and `valuesHash` are therefore always computed from the exact same
        // array and can never differ, so the exception "Original guardian values did not match
        // values in the guardian record." is dead code: no matter how thoroughly the passed
        // GuardianRecord disagrees with what this guardian actually received, this specific check
        // will never fire.
        //
        // This test proves that by feeding a guardian a *completely different* (but
        // independently self-consistent, individually-valid) GuardianRecord from an unrelated
        // guardian set. If the comparison worked as apparently intended, this would be the
        // canonical case it exists to catch. Instead, verification only fails later, and
        // incidentally, via the per-source polynomial checks further down Guardian.Verify.
        var setA = ElectionFixtureBuilder.CreateGuardianSet();
        var setB = ElectionFixtureBuilder.CreateGuardianSet();

        var verifyingGuardian = setA.Guardians[0];

        var exception = Assert.Throws<Exception>(() => verifyingGuardian.Verify(setB.GuardianRecord));

        Assert.DoesNotContain("Original guardian values did not match", exception.Message);
        Assert.IsNotType<VerificationFailedException>(exception);
    }

    [Fact]
    public void Verify_VoteEncryptionPolynomialMismatch_ThrowsException()
    {
        var setA = ElectionFixtureBuilder.CreateGuardianSet();
        var setB = ElectionFixtureBuilder.CreateGuardianSet();

        // setB's own GuardianRecord is fully self-consistent (CreateGuardianSet already verified
        // it internally for every guardian in set B), so Verification 1/2/3 all pass against it.
        // But setA's guardian 1 decrypted its real vote-encryption shares against setA's
        // guardians' actual commitments -- comparing those decrypted values against setB's
        // (different, but individually valid) commitments must fail the internal polynomial
        // check, which is a plain Exception, not a VerificationFailedException.
        var verifyingGuardian = setA.Guardians[0];

        var exception = Assert.Throws<Exception>(() => verifyingGuardian.Verify(setB.GuardianRecord));

        Assert.Contains("vote encryption polynomial", exception.Message);
    }

    [Fact]
    public void Verify_OtherBallotDataPolynomialMismatch_ThrowsException()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        var verifyingGuardian = guardianSet.Guardians[0];
        var targetIndex = guardianSet.Guardians[1].Index;

        var targetOriginalView = guardianSet.GuardianPublicViews.Single(v => v.Index == targetIndex);
        var targetCommunicationKeyPair = guardianSet.GuardianKeys.Single(k => k.Index == targetIndex).CommunicationKeyPair;

        // Fabricate a self-consistent (but unrelated) "other ballot data" proof for the target
        // guardian's own communication key, leaving its vote-encryption commitments/proof
        // untouched. This isolates the failure to the other-ballot-data polynomial check
        // specifically -- the vote-encryption check (which runs first in Guardian.Verify) still
        // passes because those commitments are unchanged.
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
            Guardians = tamperedGuardians,
            ElectionPublicKeys = tamperedElectionPublicKeys,
        };

        var exception = Assert.Throws<Exception>(() => verifyingGuardian.Verify(tamperedRecord));

        Assert.Contains("other ballot data encryption polynomial", exception.Message);
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
            Guardians = guardianSet.GuardianRecord.Guardians,
            ElectionPublicKeys = guardianSet.GuardianRecord.ElectionPublicKeys,
        };

        // Guardian.Verify delegates the CryptographicParameters check to ParameterVerification
        // (Verification 1), which throws the typed VerificationFailedException with a "1.*"
        // SubSection -- distinct from Guardian.Verify's own internal plain-Exception throw sites
        // exercised by the tests above.
        var exception = Assert.Throws<VerificationFailedException>(() => guardianSet.Guardians[0].Verify(tamperedRecord));

        Assert.StartsWith("1.", exception.SubSection);
    }
}
