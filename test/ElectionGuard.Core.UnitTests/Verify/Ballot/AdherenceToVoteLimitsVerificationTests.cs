using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using System.Numerics;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

public class AdherenceToVoteLimitsVerificationTests
{
    public AdherenceToVoteLimitsVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    /// <summary>
    /// A valid ballot whose contest declares no supplemental fields, so that its selection-limit
    /// proof is over the plain aggregate of eq. (62), which these tests recompute. The supplemental
    /// fields' combined proof and relation proof are covered by
    /// <see cref="SupplementalFieldVerificationTests"/>.
    /// </summary>
    private static (EncryptedBallot Ballot, EncryptionRecord EncryptionRecord) BuildValidBallot()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(supplementalFields: []);
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
            Status = ballot.Status,
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

    /// <summary>
    /// G33: Z_q = {x : 0 &lt;= x &lt; q}, so a challenge of 0 passes 7.B. Tampered in without
    /// re-proving, it then fails only the challenge sum, 7.D. (7.B/7.C used to reject 0.)
    /// </summary>
    [Fact]
    public void Verify_ZeroChallenge_IsInZq_FailsOnlyTheSumCheck_SubSection7D()
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
        Assert.Equal("7.D", exception.SubSection);
    }

    /// <summary>G33: a response of 0 passes 7.C, and the tampered proof fails only 7.D.</summary>
    [Fact]
    public void Verify_ZeroResponse_IsInZq_FailsOnlyTheSumCheck_SubSection7D()
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
        Assert.Equal("7.D", exception.SubSection);
    }

    /// <summary>
    /// G33: a valid contest proof whose simulated branch has c_j = 0 and v_j = 0 passes
    /// Verification 7. See <see cref="ZeroChallengeRangeProof"/>.
    /// </summary>
    [Fact]
    public void Verify_ValidProofWithAZeroChallengeAndResponse_Passes()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var manifestContest = encryptionRecord.Manifest.Contests.Single();
        var tampered = WithTamperedFirstContest(ballot, contest =>
        {
            IntegerModP alphaBar = contest.Choices.Select(x => x.Alpha).Aggregate((x, y) => x * y);
            IntegerModP betaBar = contest.Choices.Select(x => x.Beta).Aggregate((x, y) => x * y);
            IntegerModQ nonceBar = contest.Choices.Select(x => x.EncryptionNonce!.Value).Aggregate((x, y) => x + y);
            var proofs = ZeroChallengeRangeProof.Prove(
                alphaBar, betaBar, nonceBar, value: 1, limit: manifestContest.SelectionLimit,
                encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, ballot.SelectionEncryptionIdentifierHash,
                manifestContest.Index);
            return contest with { Proofs = proofs };
        });
        Assert.Contains(
            tampered.Contests[0].Proofs,
            proof => proof.Challenge == new IntegerModQ(0) && proof.Response == new IntegerModQ(0));

        var exception = Record.Exception(() => new AdherenceToVoteLimitsVerification().Verify(tampered, encryptionRecord));

        Assert.Null(exception);
    }

    /// <summary>
    /// G36 (user decision Q8, "per-selection as written"): 7.A checks each alpha_i and beta_i (p.37,
    /// subscript i, no overbar), not only the aggregates. Negating the alphas of two selections of
    /// one contest makes both non-members, (-1)·(-1) = 1 leaves the aggregate alpha-bar unchanged, and
    /// so the contest proof, which is over the aggregate, still passes untouched. A check of the
    /// aggregates alone accepted this ballot; the per-selection check rejects it.
    /// </summary>
    [Fact]
    public void Verify_TwoNonMemberSelectionsWhoseProductIsAMember_Throws_SubSection7A()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var newChoices = c.Choices
                .Select(s => s with { Alpha = new IntegerModP(EGParameters.P - s.Alpha.ToBigInteger()) })
                .ToList();
            return c with { Choices = newChoices };
        });
        Assert.Equal(2, tampered.Contests[0].Choices.Count);
        Assert.All(tampered.Contests[0].Choices, s => Assert.False(SubgroupMembership.IsMember(s.Alpha)));

        // The aggregate is exactly the honest one, a member, and the untouched contest proof checks.
        var challenge = new RangeProofChallenge(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey);
        var (honestAlpha, honestBeta) = challenge.Aggregate(ballot.Contests[0].Choices);
        var (alpha, beta) = challenge.Aggregate(tampered.Contests[0].Choices);
        Assert.Equal(honestAlpha, alpha);
        Assert.Equal(honestBeta, beta);
        Assert.True(SubgroupMembership.IsMember(alpha));
        var manifestContest = encryptionRecord.Manifest.Contests.Single();
        Span<byte> prefix = stackalloc byte[5];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), manifestContest.Index);
        var c = challenge.Compute(ballot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, tampered.Contests[0].Proofs);
        Assert.Equal(c, tampered.Contests[0].Proofs.Aggregate(new IntegerModQ(), (sum, proof) => sum + proof.Challenge));

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.A", exception.SubSection);
    }

    /// <summary>
    /// G36, the case only the per-selection membership test can catch. The test above negates the
    /// alphas, and -1 is a quadratic non-residue mod p (p = 3 mod 4), so its non-members fail the
    /// exact Jacobi pass and the batch test never runs. Here both tampered betas are quadratic
    /// residues outside Z_p^r: beta_1·x and beta_2·x^-1, with x = 2^(2q) mod p, a square of order
    /// dividing r' (p - 1 = 2·q·r'). They pass the Jacobi pass, their product is the honest aggregate
    /// beta-bar, and the contest proof still checks, so only a ^q (or batch) test of each selection
    /// rejects the ballot. A check that ran Jacobi per selection but the ^q test only on the
    /// aggregates would accept it.
    /// </summary>
    [Fact]
    public void Verify_TwoQuadraticResidueNonMembersWhoseProductIsAMember_Throws_SubSection7A()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        BigInteger p = EGParameters.P;
        BigInteger x = BigInteger.ModPow(2, 2 * EGParameters.Q, p);
        BigInteger xInverse = BigInteger.ModPow(x, p - 2, p);
        Assert.NotEqual(BigInteger.One, x);
        Assert.False(SubgroupMembership.IsMember(new IntegerModP(x)));

        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var newChoices = c.Choices.Select((s, i) => i switch
            {
                0 => s with { Beta = s.Beta * new IntegerModP(x) },
                1 => s with { Beta = s.Beta * new IntegerModP(xInverse) },
                _ => s,
            }).ToList();
            return c with { Choices = newChoices };
        });
        Assert.Equal(2, tampered.Contests[0].Choices.Count);
        Assert.All(tampered.Contests[0].Choices, s =>
        {
            // Euler's criterion: a quadratic residue, so the Jacobi pass lets it through...
            Assert.Equal(BigInteger.One, BigInteger.ModPow(s.Beta.ToBigInteger(), (p - 1) / 2, p));
            // ...but not a member.
            Assert.False(SubgroupMembership.IsMember(s.Beta));
        });

        // The aggregate is exactly the honest one, a member, and the untouched contest proof checks.
        var challenge = new RangeProofChallenge(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey);
        var (honestAlpha, honestBeta) = challenge.Aggregate(ballot.Contests[0].Choices);
        var (alpha, beta) = challenge.Aggregate(tampered.Contests[0].Choices);
        Assert.Equal(honestAlpha, alpha);
        Assert.Equal(honestBeta, beta);
        Assert.True(SubgroupMembership.IsMember(beta));
        var manifestContest = encryptionRecord.Manifest.Contests.Single();
        Span<byte> prefix = stackalloc byte[5];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), manifestContest.Index);
        var c = challenge.Compute(ballot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, tampered.Contests[0].Proofs);
        Assert.Equal(c, tampered.Contests[0].Proofs.Aggregate(new IntegerModQ(), (sum, proof) => sum + proof.Challenge));

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.A", exception.SubSection);
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

    [Fact]
    public void Verify_AggregateIsAQuadraticResidueOutsideSubgroup_Throws_SubSection7A()
    {
        // Doubling one beta makes that beta, and the aggregate beta, a quadratic residue outside the
        // order-q subgroup: a Jacobi-symbol screen passes it, the batch membership test does not.
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var newChoices = c.Choices.Select((s, i) => i == 1 ? s with { Beta = s.Beta * new IntegerModP(2) } : s).ToList();
            return c with { Choices = newChoices };
        });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.A", exception.SubSection);
    }

    [Fact]
    public void Verify_SumMismatchAndNonMember_Throws_SubSection7A()
    {
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var proofs = (ChallengeResponsePair[])c.Proofs.Clone();
            proofs[0] = proofs[0] with { Challenge = proofs[0].Challenge + 1 };
            var newChoices = c.Choices.Select((s, i) => i == 0 ? s with { Alpha = new IntegerModP(2) } : s).ToList();
            return c with { Proofs = proofs, Choices = newChoices };
        });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.A", exception.SubSection);
    }

    [Fact]
    public void Verify_ProofCountMismatchAndNonMember_Throws_SubSection7A()
    {
        // 7.A, for every selection on the ballot, is checked before the proof count.
        var (ballot, encryptionRecord) = BuildValidBallot();
        var tampered = WithTamperedFirstContest(ballot, c =>
        {
            var newChoices = c.Choices.Select((s, i) => i == 0 ? s with { Alpha = new IntegerModP(2) } : s).ToList();
            return c with { Proofs = c.Proofs.Take(c.Proofs.Length - 1).ToArray(), Choices = newChoices };
        });

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.A", exception.SubSection);
    }

    [Fact]
    public void Verify_AggregateNonMemberWithAValidProof_Throws_SubSection7A()
    {
        // Negating one selection's alpha negates the aggregate alpha, -alpha_bar, which is outside
        // Z_p^r; the contest proof is then forged for it so that it passes 7.D. Only 7.A can reject
        // this ballot. See NonMemberRangeProof.
        var (ballot, encryptionRecord) = BuildValidBallot();
        var manifestContest = encryptionRecord.Manifest.Contests.Single();
        var tampered = WithTamperedFirstContest(ballot, contest =>
        {
            IntegerModP alphaBar = contest.Choices.Select(x => x.Alpha).Aggregate((x, y) => x * y);
            IntegerModP betaBar = contest.Choices.Select(x => x.Beta).Aggregate((x, y) => x * y);
            IntegerModQ nonceBar = contest.Choices.Select(x => x.EncryptionNonce!.Value).Aggregate((x, y) => x + y);
            var (_, proofs) = NonMemberRangeProof.Forge(
                alphaBar, betaBar, nonceBar, value: 1, limit: manifestContest.SelectionLimit,
                encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, ballot.SelectionEncryptionIdentifierHash,
                manifestContest.Index);

            var first = contest.Choices[0];
            var newChoices = contest.Choices.Select((s, i) => i == 0 ? s with { Alpha = new IntegerModP(EGParameters.P - first.Alpha.ToBigInteger()) } : s).ToList();
            return contest with { Choices = newChoices, Proofs = proofs };
        });

        // The forged proof really does pass the challenge-sum check, so only 7.A can reject it.
        var forgedContest = tampered.Contests[0];
        var challenge = new RangeProofChallenge(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey);
        var (alpha, beta) = challenge.Aggregate(forgedContest.Choices);
        Span<byte> prefix = stackalloc byte[5];
        prefix[0] = 0x24;
        RangeProofChallenge.WriteIndex(prefix.Slice(1, 4), manifestContest.Index);
        var c = challenge.Compute(ballot.SelectionEncryptionIdentifierHash, prefix, alpha, beta, forgedContest.Proofs);
        Assert.Equal(c, forgedContest.Proofs.Aggregate(new IntegerModQ(), (sum, proof) => sum + proof.Challenge));

        var verification = new AdherenceToVoteLimitsVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(tampered, encryptionRecord));
        Assert.Equal("7.A", exception.SubSection);
    }
}
