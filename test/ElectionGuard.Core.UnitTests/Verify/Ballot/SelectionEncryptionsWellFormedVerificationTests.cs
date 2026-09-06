using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.TestFixtures;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

public class SelectionEncryptionsWellFormedVerificationTests
{
    public SelectionEncryptionsWellFormedVerificationTests()
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

    private static EncryptedBallot WithTamperedFirstSelection(EncryptedBallot ballot, Func<EncryptedSelection, EncryptedSelection> mutate)
    {
        var firstContest = ballot.Contests[0];
        var newChoices = firstContest.Choices.Select((c, i) => i == 0 ? mutate(c) : c).ToList();
        var newContest = firstContest with { Choices = newChoices };
        var newContests = ballot.Contests.Select((c, i) => i == 0 ? newContest : c).ToList();
        return CloneWithContests(ballot, newContests);
    }

    [Fact]
    public void Verify_ValidEncryptedBallot_DoesNotThrow()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Record.Exception(() => verification.Verify(ballot, encryptionRecord));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_ProofCountMismatch_Throws_SubSection6()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstSelection(ballot, s => s with { Proofs = s.Proofs.Take(s.Proofs.Length - 1).ToArray() });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6", exception.SubSection);
    }

    [Fact]
    public void Verify_AlphaNotInSubgroup_Throws_SubSection6A()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstSelection(ballot, s => s with { Alpha = new IntegerModP(0) });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.A", exception.SubSection);
    }

    [Fact]
    public void Verify_BetaNotInSubgroup_Throws_SubSection6A()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstSelection(ballot, s => s with { Beta = new IntegerModP(0) });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.A", exception.SubSection);
    }

    [Fact]
    public void Verify_ProofChallengeOutOfRange_Throws_SubSection6BC()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();

        // IntegerModQ's public constructor always reduces into [0, Q), so the only reachable
        // "out of Zq" value via the public API is the <= 0 boundary (0 itself).
        var tampered = WithTamperedFirstSelection(ballot, s =>
        {
            var proofs = (ChallengeResponsePair[])s.Proofs.Clone();
            proofs[0] = proofs[0] with { Challenge = new IntegerModQ(0) };
            return s with { Proofs = proofs };
        });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.B/C", exception.SubSection);
    }

    [Fact]
    public void Verify_ProofResponseOutOfRange_Throws_SubSection6BC()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();

        var tampered = WithTamperedFirstSelection(ballot, s =>
        {
            var proofs = (ChallengeResponsePair[])s.Proofs.Clone();
            proofs[0] = proofs[0] with { Response = new IntegerModQ(0) };
            return s with { Proofs = proofs };
        });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.B/C", exception.SubSection);
    }

    [Fact]
    public void Verify_ProofChallengeSumMismatch_Throws_SubSection6D()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();

        var tampered = WithTamperedFirstSelection(ballot, s =>
        {
            var proofs = (ChallengeResponsePair[])s.Proofs.Clone();
            proofs[0] = proofs[0] with { Challenge = proofs[0].Challenge + 1 };
            return s with { Proofs = proofs };
        });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.D", exception.SubSection);
    }

    [Fact]
    public void Verify_AlphaNotInSubgroup_NonZeroValue_Throws_SubSection6A()
    {
        // Verify_AlphaNotInSubgroup_Throws_SubSection6A above uses Alpha = 0, which only
        // exercises the `value <= 0` clause of VerifyIsInZpr. This test uses a small nonzero
        // value that has an overwhelmingly small chance of landing in the order-q subgroup of
        // Z_p*, so it independently exercises the `PowModP(value, Q) != 1`
        // subgroup-membership clause.
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstSelection(ballot, s => s with { Alpha = new IntegerModP(2) });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.A", exception.SubSection);
    }
}
