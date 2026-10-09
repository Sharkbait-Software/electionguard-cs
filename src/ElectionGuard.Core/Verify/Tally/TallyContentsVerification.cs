using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Tally;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 11 (Validation of contents of tallies), §3.6.5 p.49 and §6.2.5 p.90: the text
/// labels of a decrypted tally match the manifest's. For each contest in the decrypted tally:
/// (11.A) its label is a contest label of the manifest; (11.B) each of its option labels is an
/// option label of that manifest contest; (11.C) each option label the manifest lists for the
/// contest occurs in the tally contest. And (11.D) every contest label that occurs on at least one
/// submitted ballot occurs in the tally.
///
/// Labels are the manifest's ids (<see cref="Contest.Id"/>, <see cref="Choice.Id"/>), which
/// <see cref="Manifest.Validate"/> keeps unique. "Submitted" ballots are every ballot in the record:
/// cast, challenged and spoiled ones alike (user decision S10b #4: "If we have it in the election
/// record at all, it was by definition submitted"). 11.D is about which contests were voted on, not
/// which were counted.
/// </summary>
public class TallyContentsVerification
{
    /// <summary>
    /// Verification 11 on the decrypted tally decoded from the election record (design §4.8): a
    /// contest or field label its items list twice fails 11.structure (the domain tally is keyed by
    /// label, so it cannot hold both); then <see cref="RecordItemNotEvaluableException"/> if another
    /// verification's range finding is on it (10.x); then
    /// <see cref="Verify(Manifest, DecryptedTally, IReadOnlyCollection{string})"/>. See <see cref="RecordItemGate"/>.
    /// </summary>
    internal void Verify(Manifest manifest, RecordDecoded<DecryptedTally> decryptedTally, IReadOnlyCollection<string> contestIdsOnSubmittedBallots)
    {
        Verify(manifest, RecordItemGate.Require(decryptedTally, 11), contestIdsOnSubmittedBallots);
    }

    /// <summary>
    /// Checks 11.A-11.D, with 11.D over the contests of <paramref name="submittedBallots"/>.
    /// Throws <see cref="VerificationFailedException"/> with the failing sub-section.
    /// </summary>
    public void Verify(Manifest manifest, DecryptedTally decryptedTally, IEnumerable<EncryptedBallot> submittedBallots)
    {
        var contestIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var ballot in submittedBallots)
        {
            foreach (var contest in ballot.Contests)
            {
                contestIds.Add(contest.Id);
            }
        }

        Verify(manifest, decryptedTally, contestIds);
    }

    /// <summary>
    /// Checks 11.A-11.D, with 11.D over <paramref name="contestIdsOnSubmittedBallots"/>: the set of
    /// contest labels that occur on at least one submitted ballot. For callers that stream ballots
    /// and collect the set as they go rather than holding every ballot.
    /// </summary>
    public void Verify(Manifest manifest, DecryptedTally decryptedTally, IReadOnlyCollection<string> contestIdsOnSubmittedBallots)
    {
        foreach (var (contestId, decryptedContest) in decryptedTally.Contests)
        {
            var contest = manifest.Contests.FirstOrDefault(x => x.Id == contestId)
                ?? throw new VerificationFailedException("11.A", $"Tally contents verification failed: the tally's contest {contestId} is not a contest of the manifest.");

            // "Option labels" include the supplemental fields the manifest declares for the contest
            // (§3.1.3 p.19: they are listed with the options).
            foreach (var choiceId in decryptedContest.Choices.Keys)
            {
                if (!contest.VerifiableFields().Any(x => x.Id == choiceId))
                {
                    throw new VerificationFailedException("11.B", $"Tally contents verification failed: the tally's option {choiceId} is not an option of manifest contest {contestId}.");
                }
            }

            foreach (var choice in contest.VerifiableFields())
            {
                if (!decryptedContest.Choices.ContainsKey(choice.Id))
                {
                    throw new VerificationFailedException("11.C", $"Tally contents verification failed: manifest option {choice.Id} of contest {contestId} does not occur in the tally.");
                }
            }
        }

        foreach (var contestId in contestIdsOnSubmittedBallots.Order(StringComparer.Ordinal))
        {
            if (!decryptedTally.Contests.ContainsKey(contestId))
            {
                throw new VerificationFailedException("11.D", $"Tally contents verification failed: contest {contestId} occurs on a submitted ballot but not in the tally.");
            }
        }
    }
}
