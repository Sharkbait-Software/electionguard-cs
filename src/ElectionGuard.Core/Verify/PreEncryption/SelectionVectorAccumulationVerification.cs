using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.PreEncryption;

/// <summary>
/// Verification 15 (Validation of correct accumulation of selection vectors), §4.5 p.64 and §6.2.8
/// p.94, for a cast pre-encrypted ballot's record (<see cref="EncryptedBallot.PreEncryptedContests"/>):
/// (15.A) the selection vector Ψ published for each contest (the combined vector, the contest's
/// <see cref="EncryptedContest.Choices"/>) is the componentwise product of the selected vectors Ψ_{i,m}
/// whose short codes the record lists as selected.
///
/// The spec states 15.A for contests whose selection limit is greater than 1. This applies it to
/// every contest: with L = 1 the product is the single selected vector, which "will be identical to
/// one of the pre-encryption selection vectors" (§4.4), and nothing else ties the combined vector
/// to the vector the voter's short code names. Verification 6 proves each component of the combined
/// vector and Verification 7 its sum, so together they show the vote counted is the one the short
/// codes name.
/// </summary>
public class SelectionVectorAccumulationVerification
{
    /// <summary>
    /// Checks the structure ("15.structure", <see cref="BallotStructure.RequirePreEncryptedCast"/>),
    /// then 15.A for each contest, component by component in option order.
    /// </summary>
    public void Verify(EncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        BallotStructure.RequirePreEncryptedCast(ballot, encryptionRecord.Manifest, 15);

        for (int i = 0; i < ballot.Contests.Count; i++)
        {
            var contest = ballot.Contests[i];
            var selected = ballot.PreEncryptedContests![i].SelectedVectors;

            // BallotStructure has required exactly the manifest's options, each once; the vectors'
            // positions follow the options in option index order (eq. 112).
            var options = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id).Choices;
            for (int k = 0; k < options.Count; k++)
            {
                IntegerModP alpha = 1;
                IntegerModP beta = 1;
                foreach (var vector in selected)
                {
                    alpha *= vector.Vector[k].Alpha;
                    beta *= vector.Vector[k].Beta;
                }

                var published = contest.Choices.Single(x => x.ChoiceId == options[k].Id);
                if (published.Alpha != alpha || published.Beta != beta)
                {
                    throw new VerificationFailedException("15.A", $"The selection vector of contest {contest.Id} on pre-encrypted ballot {ballot.Id} is not the product of the selected pre-encryption vectors at option {options[k].Id} (position {k + 1}).");
                }
            }
        }
    }
}
