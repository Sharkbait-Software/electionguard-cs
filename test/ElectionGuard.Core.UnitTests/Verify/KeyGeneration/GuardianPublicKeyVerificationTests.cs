using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.KeyGeneration;

namespace ElectionGuard.Core.UnitTests.Verify.KeyGeneration;

public class GuardianPublicKeyVerificationTests
{
    public GuardianPublicKeyVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    /// <summary>
    /// Builds a copy of a GuardianPublicView with one or more fields overridden, so tests can
    /// tamper a single value while leaving the rest of a real, otherwise-valid guardian record
    /// intact.
    /// </summary>
    private static GuardianPublicView Clone(
        GuardianPublicView source,
        List<IntegerModP>? voteEncryptionCommitments = null,
        List<IntegerModP>? otherBallotDataEncryptionCommitments = null,
        IntegerModP? communicationPublicKey = null,
        SchnorrProof? voteEncryptionProof = null,
        SchnorrProof? otherDataEncryptionProof = null)
    {
        return new GuardianPublicView
        {
            Index = source.Index,
            VoteEncryptionCommitments = voteEncryptionCommitments ?? source.VoteEncryptionCommitments,
            OtherBallotDataEncryptionCommitments = otherBallotDataEncryptionCommitments ?? source.OtherBallotDataEncryptionCommitments,
            CommunicationPublicKey = communicationPublicKey ?? source.CommunicationPublicKey,
            VoteEncryptionProof = voteEncryptionProof ?? source.VoteEncryptionProof,
            OtherDataEncryptionProof = otherDataEncryptionProof ?? source.OtherDataEncryptionProof,
        };
    }

    [Fact]
    public void Verify_ValidGuardianPublicView_DoesNotThrow()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var verification = new GuardianPublicKeyVerification();

        var singleException = Record.Exception(() => verification.Verify(guardianSet.GuardianPublicViews[0]));
        var enumerableException = Record.Exception(() => verification.Verify(guardianSet.GuardianPublicViews));

        Assert.Null(singleException);
        Assert.Null(enumerableException);
    }

    [Fact]
    public void Verify_VoteEncryptionCommitmentNotInSubgroup_Throws_SubSection2A()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];

        // A small integer like 2 has an overwhelmingly small chance of landing in the order-q
        // subgroup of Z_p*, so PowModP(2, Q) != 1 and the 2.A subgroup check fails.
        var tamperedCommitments = new List<IntegerModP>(original.VoteEncryptionCommitments)
        {
            [0] = new IntegerModP(2),
        };
        var tampered = Clone(original, voteEncryptionCommitments: tamperedCommitments);

        var verification = new GuardianPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered));
        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_OtherBallotDataCommitmentNotInSubgroup_Throws_SubSection2A()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];

        var tamperedCommitments = new List<IntegerModP>(original.OtherBallotDataEncryptionCommitments)
        {
            [0] = new IntegerModP(2),
        };
        var tampered = Clone(original, otherBallotDataEncryptionCommitments: tamperedCommitments);

        var verification = new GuardianPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered));
        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_CommunicationPublicKeyNotInSubgroup_Throws_SubSection2A()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];

        var tampered = Clone(original, communicationPublicKey: new IntegerModP(2));

        var verification = new GuardianPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered));
        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_VoteEncryptionChallengeMismatch_Throws_SubSection2C()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];

        // Changing the stored challenge (while keeping the responses the same) changes the
        // recomputed h-values fed into the challenge hash, so the recomputed ci will no longer
        // equal the (now tampered) stored challenge.
        var tamperedProof = new SchnorrProof
        {
            Challenge = original.VoteEncryptionProof.Challenge + 1,
            Responses = original.VoteEncryptionProof.Responses,
        };
        var tampered = Clone(original, voteEncryptionProof: tamperedProof);

        var verification = new GuardianPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered));
        Assert.Equal("2.C", exception.SubSection);
    }

    [Fact]
    public void Verify_OtherDataEncryptionChallengeMismatch_Throws_SubSection2C()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];

        var tamperedProof = new SchnorrProof
        {
            Challenge = original.OtherDataEncryptionProof.Challenge + 1,
            Responses = original.OtherDataEncryptionProof.Responses,
        };
        var tampered = Clone(original, otherDataEncryptionProof: tamperedProof);

        var verification = new GuardianPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered));
        Assert.Equal("2.C", exception.SubSection);
    }

    // 2.B: since S2 (audit G14) it requires exactly k + 1 responses per proof; see the
    // response-count tests below. That each response is in Z_q holds by construction (IntegerModQ
    // reduces), so that half has no reachable failure; strict parsing is audit G23 (stage S3).

    [Fact]
    public void Verify_ExtraVoteEncryptionCommitment_Throws_SubSection2A()
    {
        // G14: an extra, valid-looking commitment K_{i,k} is covered by no proof and would raise the
        // degree of the guardian's polynomial, and with it the decryption threshold.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];
        var extra = IntegerModP.PowModP(EGParameters.G, new System.Numerics.BigInteger(5));
        var tampered = Clone(original, voteEncryptionCommitments: [.. original.VoteEncryptionCommitments, extra]);

        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify(tampered));

        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_ExtraOtherBallotDataCommitment_Throws_SubSection2A()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];
        var extra = IntegerModP.PowModP(EGParameters.G, new System.Numerics.BigInteger(5));
        var tampered = Clone(original, otherBallotDataEncryptionCommitments: [.. original.OtherBallotDataEncryptionCommitments, extra]);

        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify(tampered));

        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_TooFewCommitments_Throws_SubSection2A_NotIndexOutOfRange()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];
        var tampered = Clone(original, voteEncryptionCommitments: original.VoteEncryptionCommitments.Take(1).ToList());

        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify(tampered));

        Assert.Equal("2.A", exception.SubSection);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void Verify_WrongNumberOfVoteEncryptionResponses_Throws_SubSection2B(int delta)
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];
        var responses = original.VoteEncryptionProof.Responses;
        var resized = delta < 0 ? responses[..^1] : [.. responses, responses[0]];
        var tampered = Clone(original, voteEncryptionProof: original.VoteEncryptionProof with { Responses = resized });

        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify(tampered));

        Assert.Equal("2.B", exception.SubSection);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void Verify_WrongNumberOfOtherDataEncryptionResponses_Throws_SubSection2B(int delta)
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];
        var responses = original.OtherDataEncryptionProof.Responses;
        var resized = delta < 0 ? responses[..^1] : [.. responses, responses[0]];
        var tampered = Clone(original, otherDataEncryptionProof: original.OtherDataEncryptionProof with { Responses = resized });

        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify(tampered));

        Assert.Equal("2.B", exception.SubSection);
    }

    [Fact]
    public void Verify_GuardianSetMissingAGuardian_Throws_SubSection2A()
    {
        // G25: "for each guardian G_i, 1 <= i <= n". A ceremony run with fewer guardians than H_P
        // claims must not pass.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();

        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify(guardianSet.GuardianPublicViews.Take(2)));

        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_GuardianSetWithADuplicatedGuardian_Throws_SubSection2A()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var views = guardianSet.GuardianPublicViews;

        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify([views[0], views[1], views[1]]));

        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_GuardianSetWithAnIndexAboveN_Throws_SubSection2A()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var views = guardianSet.GuardianPublicViews;
        var renumbered = new GuardianPublicView
        {
            Index = new GuardianIndex(4),
            VoteEncryptionCommitments = views[2].VoteEncryptionCommitments,
            OtherBallotDataEncryptionCommitments = views[2].OtherBallotDataEncryptionCommitments,
            CommunicationPublicKey = views[2].CommunicationPublicKey,
            VoteEncryptionProof = views[2].VoteEncryptionProof,
            OtherDataEncryptionProof = views[2].OtherDataEncryptionProof,
        };

        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify([views[0], views[1], renumbered]));

        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_EmptyGuardianSet_Throws_SubSection2A()
    {
        var exception = Assert.Throws<VerificationFailedException>(() => new GuardianPublicKeyVerification().Verify(new List<GuardianPublicView>()));

        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_LastVoteEncryptionCommitmentNotInSubgroup_Throws_SubSection2A()
    {
        // The existing "NotInSubgroup" cases above all tamper index 0. GuardianParameters.K is 2,
        // so the commitment lists here have exactly 2 elements; this test tampers the *last*
        // element instead, so the 2.A subgroup-check loop is verified to cover every commitment
        // index -- not just the first one -- guarding against an off-by-one loop bound.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];

        var lastIndex = original.VoteEncryptionCommitments.Count - 1;
        Assert.True(lastIndex > 0, "Test assumes more than one vote-encryption commitment.");
        var tamperedCommitments = new List<IntegerModP>(original.VoteEncryptionCommitments)
        {
            [lastIndex] = new IntegerModP(2),
        };
        var tampered = Clone(original, voteEncryptionCommitments: tamperedCommitments);

        var verification = new GuardianPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered));
        Assert.Equal("2.A", exception.SubSection);
    }

    [Fact]
    public void Verify_LastOtherBallotDataCommitmentNotInSubgroup_Throws_SubSection2A()
    {
        // Mirrors Verify_LastVoteEncryptionCommitmentNotInSubgroup_Throws_SubSection2A for the
        // OtherBallotDataEncryptionCommitments subgroup-check loop.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var original = guardianSet.GuardianPublicViews[0];

        var lastIndex = original.OtherBallotDataEncryptionCommitments.Count - 1;
        Assert.True(lastIndex > 0, "Test assumes more than one other-ballot-data commitment.");
        var tamperedCommitments = new List<IntegerModP>(original.OtherBallotDataEncryptionCommitments)
        {
            [lastIndex] = new IntegerModP(2),
        };
        var tampered = Clone(original, otherBallotDataEncryptionCommitments: tamperedCommitments);

        var verification = new GuardianPublicKeyVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered));
        Assert.Equal("2.A", exception.SubSection);
    }
}
