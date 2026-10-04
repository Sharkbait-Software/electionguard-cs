using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
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
        return WithTamperedSelection(ballot, 0, mutate);
    }

    private static EncryptedBallot WithTamperedSelection(EncryptedBallot ballot, int index, Func<EncryptedSelection, EncryptedSelection> mutate)
    {
        var firstContest = ballot.Contests[0];
        var newChoices = firstContest.Choices.Select((c, i) => i == index ? mutate(c) : c).ToList();
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

    [Fact]
    public void Verify_QuadraticResidueOutsideSubgroup_Throws_SubSection6A()
    {
        // 2 * alpha is a quadratic residue, so it passes a Jacobi-symbol screen, but it is not in
        // the order-q subgroup. Only the exact test, here read off the proof's squaring chain,
        // catches it.
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedSelection(ballot, 1, s => s with { Alpha = s.Alpha * new IntegerModP(2) });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.A", exception.SubSection);
    }

    [Fact]
    public void Verify_SumMismatchBeforeANonMember_StillThrows_SubSection6A()
    {
        // 6.A for any selection is reported before 6.D for any selection, even though the proof
        // checks now find the 6.D failure on the first selection before reaching the second.
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedSelection(ballot, 0, s =>
        {
            var proofs = (ChallengeResponsePair[])s.Proofs.Clone();
            proofs[0] = proofs[0] with { Challenge = proofs[0].Challenge + 1 };
            return s with { Proofs = proofs };
        });
        tampered = WithTamperedSelection(tampered, 1, s => s with { Beta = new IntegerModP(2) });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.A", exception.SubSection);
    }

    [Fact]
    public void Verify_ProofCountMismatchBeforeANonMember_StillThrows_SubSection6A()
    {
        // A structural failure sends the ballot down the in-order path, which checks 6.A first.
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedSelection(ballot, 0, s => s with { Proofs = s.Proofs.Take(s.Proofs.Length - 1).ToArray() });
        tampered = WithTamperedSelection(tampered, 1, s => s with { Alpha = new IntegerModP(2) });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.A", exception.SubSection);
    }

    [Fact]
    public void Verify_SumMismatchOnTheLastSelection_Throws_SubSection6D()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedSelection(ballot, 1, s =>
        {
            var proofs = (ChallengeResponsePair[])s.Proofs.Clone();
            proofs[1] = proofs[1] with { Response = proofs[1].Response + 1 };
            return s with { Proofs = proofs };
        });

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.D", exception.SubSection);
    }

    [Fact]
    public void Verify_NonMemberWithAValidProof_Throws_SubSection6A()
    {
        // The only kind of 6.A failure that the proof checks cannot also catch: -alpha with a proof
        // that passes 6.D. See NonMemberRangeProof.
        var (ballot, encryptionRecord) = BuildValidBallot();
        var manifestContest = encryptionRecord.Manifest.Contests.Single();
        var tampered = WithTamperedSelection(ballot, 0, s =>
        {
            var manifestChoice = manifestContest.Choices.Single(x => x.Id == s.ChoiceId);
            var (negatedAlpha, proofs) = NonMemberRangeProof.Forge(
                s.Alpha, s.Beta, s.EncryptionNonce!.Value, value: 1, limit: manifestContest.OptionSelectionLimit,
                encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, ballot.SelectionEncryptionIdentifierHash,
                manifestContest.Index, manifestChoice.Index);
            return s with { Alpha = negatedAlpha, Proofs = proofs };
        });

        // The forged proof really does pass the challenge-sum check, so only 6.A can reject it.
        var forged = tampered.Contests[0].Choices[0];
        var forgedChoice = manifestContest.Choices.Single(x => x.Id == forged.ChoiceId);
        Span<byte> prefix = stackalloc byte[9];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), manifestContest.Index);
        RangeProofChallenge.WriteIndex(prefix.Slice(5, 4), forgedChoice.Index);
        var c = new RangeProofChallenge(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey)
            .Compute(ballot.SelectionEncryptionIdentifierHash, prefix, forged.Alpha, forged.Beta, forged.Proofs);
        Assert.Equal(c, forged.Proofs.Aggregate(new IntegerModQ(), (sum, proof) => sum + proof.Challenge));

        var verification = new SelectionEncryptionsWellFormedVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("6.A", exception.SubSection);
    }
}
