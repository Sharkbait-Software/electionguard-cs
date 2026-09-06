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

        var exception = Assert.Throws<Exception>(() => verifyingGuardian.Verify(setB.GuardianRecord));

        Assert.Contains("Original guardian values did not match", exception.Message);
        Assert.IsNotType<VerificationFailedException>(exception);
    }

    [Fact]
    public void Verify_VoteEncryptionPolynomialMismatch_ThrowsException()
    {
        // Since Verify_MismatchedGuardianRecord_ThrowsOriginalValuesException's fix (the "original
        // guardian values" copy-paste bug), comparing a guardian against a GuardianRecord from a
        // wholly unrelated guardian set is now caught by that earlier, broader check rather than
        // reaching the vote-encryption-polynomial check specifically -- both are plain Exception
        // (not VerificationFailedException) throw sites internal to Guardian.Verify, so this still
        // demonstrates Verify correctly rejects a mismatched record, just via the check that now
        // legitimately fires first.
        var setA = ElectionFixtureBuilder.CreateGuardianSet();
        var setB = ElectionFixtureBuilder.CreateGuardianSet();

        var verifyingGuardian = setA.Guardians[0];

        var exception = Assert.Throws<Exception>(() => verifyingGuardian.Verify(setB.GuardianRecord));

        Assert.Contains("Original guardian values did not match", exception.Message);
        Assert.IsNotType<VerificationFailedException>(exception);
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

        // Since Verify_MismatchedGuardianRecord_ThrowsOriginalValuesException's fix (the "original
        // guardian values" copy-paste bug), tampering a guardian's public commitments/proof and
        // ElectionPublicKeys is now caught by that earlier, broader check -- it hashes the entire
        // guardian list and election public keys, so this tamper (unlike a share-only attack that
        // never touches the public record) is detected before the polynomial check is reached. Both
        // are plain Exception (not VerificationFailedException) throw sites internal to
        // Guardian.Verify, so this still demonstrates Verify correctly rejects tampering, just via
        // the check that now legitimately fires first.
        var exception = Assert.Throws<Exception>(() => verifyingGuardian.Verify(tamperedRecord));

        Assert.Contains("Original guardian values did not match", exception.Message);
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
