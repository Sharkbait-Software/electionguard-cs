using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 7 (Adherence to vote limits)
/// </summary>
public class AdherenceToVoteLimitsVerification
{
    public void Verify(EncryptedBallot encryptedBallot, EncryptionRecord encryptionRecord)
    {
        // The aggregate ciphertext of each contest, the product of its selections' ciphertexts.
        var aggregates = encryptedBallot.Contests
            .Select(contest => (
                alpha: contest.Choices.Select(x => x.Alpha).Product(),
                beta: contest.Choices.Select(x => x.Beta).Product()))
            .ToList();

        // 7.A for every contest on the ballot at once, before any proof is checked. Testing the
        // aggregates as one batch is what makes this affordable; see SubgroupMembership for why the
        // batch test is sound.
        var components = aggregates.SelectMany(x => new[] { x.alpha, x.beta }).ToList();
        if (SubgroupMembership.IndexOfFirstNonMember(components) >= 0)
        {
            throw new VerificationFailedException("7.A", "Value was not in Zpr.");
        }

        for (int i = 0; i < encryptedBallot.Contests.Count; i++)
        {
            var contest = encryptedBallot.Contests[i];
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
            Verify(contest, manifestContest, aggregates[i].alpha, aggregates[i].beta, encryptionRecord, encryptedBallot);
        }
    }

    private void Verify(EncryptedContest encryptedContest, Contest contest, IntegerModP alpha, IntegerModP beta, EncryptionRecord encryptionRecord, EncryptedBallot encryptedBallot)
    {
        if (encryptedContest.Proofs.Length != contest.SelectionLimit + 1)
        {
            throw new VerificationFailedException("7", $"A challenge/response value was not provided for all possible values of the contest selection limit of {contest.SelectionLimit}.");
        }

        List<(IntegerModP a, IntegerModP b)> calculatedValues = new();
        for (int i = 0; i < encryptedContest.Proofs.Length; i++)
        {
            var crPair = encryptedContest.Proofs[i];

            VerifyIsInZq(crPair.Challenge);
            VerifyIsInZq(crPair.Response);

            var a = MontgomeryModP.PowModP(EGParameters.G, crPair.Response)
                * MontgomeryModP.PowModP(alpha, crPair.Challenge);
            var w = crPair.Response - i * crPair.Challenge;
            var b = MontgomeryModP.PowModP(encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, w)
                * MontgomeryModP.PowModP(beta, crPair.Challenge);
            calculatedValues.Add((a, b));
        }

        List<byte[]> bytesToHash = [
                [0x24],
                contest.Index.ToByteArray(),
                alpha,
                beta];
        foreach (var val in calculatedValues)
        {
            bytesToHash.Add(val.a);
            bytesToHash.Add(val.b);
        }

        var c = EGHash.HashModQ(encryptedBallot.SelectionEncryptionIdentifierHash, bytesToHash.ToArray());

        var sumC = encryptedContest.Proofs.Select(x => x.Challenge).Sum();
        if (sumC != c)
        {
            throw new VerificationFailedException("7.D", "Sum of challenge values did not equal c.");
        }
    }

    private void VerifyIsInZq(IntegerModQ value)
    {
        if (value <= 0
            || value > EGParameters.Q)
        {
            throw new VerificationFailedException("7.B/C", "Value was not in Zq.");
        }
    }
}

