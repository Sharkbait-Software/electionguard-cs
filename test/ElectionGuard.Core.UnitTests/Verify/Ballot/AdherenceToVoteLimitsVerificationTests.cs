using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.TestFixtures;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

public class AdherenceToVoteLimitsVerificationTests
{
    public AdherenceToVoteLimitsVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static (EncryptedBallot Ballot, EncryptionRecord EncryptionRecord) BuildValidBallot()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");
        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });
        var encryptedBallot = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot);

        return (encryptedBallot, encryptionRecordResult.EncryptionRecord);
    }

    private static EncryptedBallot CloneWithContests(EncryptedBallot ballot, List<EncryptedContest> contests)
    {
        return new EncryptedBallot
        {
            Id = ballot.Id,
            SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
            BallotStyleId = ballot.BallotStyleId,
            Contests = contests,
            ConfirmationCode = ballot.ConfirmationCode,
            Weight = ballot.Weight,
            DeviceId = ballot.DeviceId,
        };
    }

    private static EncryptedBallot WithTamperedFirstContest(EncryptedBallot ballot, Func<EncryptedContest, EncryptedContest> mutate)
    {
        var newContests = ballot.Contests.Select((c, i) => i == 0 ? mutate(c) : c).ToList();
        return CloneWithContests(ballot, newContests);
    }

    [Fact]
    public void Verify_ValidEncryptedContest_DoesNotThrow()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Record.Exception(() => verification.Verify(ballot, encryptionRecord));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_ProofCountMismatch_Throws_SubSection7()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstContest(ballot, c => c with { Proofs = c.Proofs.Take(c.Proofs.Length - 1).ToArray() });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7", exception.SubSection);
    }

    [Fact]
    public void Verify_AggregatedAlphaOrBetaNotInSubgroup_Throws_SubSection7A()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();

        // Tampering any one selection's Alpha to 0 forces the aggregated (product-of-all-choices)
        // alpha to 0 as well, since anything multiplied by 0 mod P is 0.
        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var newChoices = c.Choices.Select((s, i) => i == 0 ? s with { Alpha = new IntegerModP(0) } : s).ToList();
            return c with { Choices = newChoices };
        });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.A", exception.SubSection);
    }

    [Fact]
    public void Verify_ProofChallengeOutOfRange_Throws_SubSection7BC()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();

        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var proofs = (ChallengeResponsePair[])c.Proofs.Clone();
            proofs[0] = proofs[0] with { Challenge = new IntegerModQ(0) };
            return c with { Proofs = proofs };
        });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.B/C", exception.SubSection);
    }

    [Fact]
    public void Verify_ProofResponseOutOfRange_Throws_SubSection7BC()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();

        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var proofs = (ChallengeResponsePair[])c.Proofs.Clone();
            proofs[0] = proofs[0] with { Response = new IntegerModQ(0) };
            return c with { Proofs = proofs };
        });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.B/C", exception.SubSection);
    }

    [Fact]
    public void Verify_ProofChallengeSumMismatch_Throws_SubSection7D()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();

        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var proofs = (ChallengeResponsePair[])c.Proofs.Clone();
            proofs[0] = proofs[0] with { Challenge = proofs[0].Challenge + 1 };
            return c with { Proofs = proofs };
        });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.D", exception.SubSection);
    }

    [Fact]
    public void Verify_AggregatedAlphaNotInSubgroup_NonZeroValue_Throws_SubSection7A()
    {
        // Verify_AggregatedAlphaOrBetaNotInSubgroup_Throws_SubSection7A above uses Alpha = 0,
        // which only exercises the `value <= 0` clause of VerifyIsInZpr. This test uses a small
        // nonzero value that has an overwhelmingly small chance of landing in the order-q
        // subgroup of Z_p*, so it independently exercises the `PowModP(value, Q) != 1`
        // subgroup-membership clause. Because the subgroup is closed under multiplication,
        // aggregating one non-member factor with the remaining valid (subgroup-member) factors
        // keeps the product outside the subgroup.
        var (ballot, encryptionRecord) = BuildValidBallot();

        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var newChoices = c.Choices.Select((s, i) => i == 0 ? s with { Alpha = new IntegerModP(2) } : s).ToList();
            return c with { Choices = newChoices };
        });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.A", exception.SubSection);
    }
}
