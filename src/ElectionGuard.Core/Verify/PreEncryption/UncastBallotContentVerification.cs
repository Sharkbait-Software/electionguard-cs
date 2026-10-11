using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Core.Verify.PreEncryption;

/// <summary>
/// Verification 19 (Validation of content of uncast pre-encrypted ballots), §4.5 p.67 and §6.2.8
/// p.99: "the selections listed in text match the corresponding text in the election manifest".
/// For an uncast pre-encrypted ballot:
/// <list type="bullet">
/// <item>(19.A) each contest label on the ballot occurs in the list of contests of the ballot's
/// ballot style;</item>
/// <item>(19.B) each contest of the ballot style appears on the ballot;</item>
/// <item>(19.C) each option label on a contest occurs as an option label of that contest in the
/// manifest;</item>
/// <item>(19.D) each option label the manifest lists for the contest occurs for an option on the
/// ballot.</item>
/// </list>
/// A null vector carries no option label (§4.1.5: "labels for null votes are not included within the
/// manifest file", §4.2.1), so it takes no part in 19.C and 19.D. A ballot style missing from the
/// manifest, a contest or option label listed twice, and a null or empty list are reported as
/// "19.structure"; the count of null vectors and every vector's length are Verification 16's
/// structure (<see cref="BallotStructure"/>).
/// </summary>
public class UncastBallotContentVerification
{
    public void Verify(Manifest manifest, PreEncryptedUncastBallot uncast)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(uncast);

        var ballot = uncast.Ballot ?? throw Failure("19.structure", "the uncast pre-encrypted ballot record has no ballot.");
        string where = $"uncast pre-encrypted ballot {ballot.Id}";

        var style = manifest.BallotStyles.FirstOrDefault(x => x.Id == ballot.BallotStyleId)
            ?? throw Failure("19.structure", $"{where} names ballot style {ballot.BallotStyleId}, which is not in the manifest.");

        var contests = ballot.Contests ?? throw Failure("19.structure", $"{where} has no contest list.");
        var seenContests = new HashSet<string>(StringComparer.Ordinal);
        foreach (var contest in contests)
        {
            if (contest?.ContestId is null || contest.Selections is null || contest.Selections.Any(x => x is null))
            {
                throw Failure("19.structure", $"{where} has a null contest, selection list or selection.");
            }

            if (!seenContests.Add(contest.ContestId))
            {
                throw Failure("19.structure", $"{where} lists contest {contest.ContestId} more than once.");
            }
        }

        // 19.A, then 19.B.
        foreach (var contest in contests)
        {
            if (!style.ContestIds.Contains(contest.ContestId, StringComparer.Ordinal))
            {
                throw Failure("19.A", $"contest {contest.ContestId} on {where} is not a contest of its ballot style {style.Id}.");
            }
        }

        foreach (var contestId in style.ContestIds)
        {
            if (!seenContests.Contains(contestId))
            {
                throw Failure("19.B", $"contest {contestId} of ballot style {style.Id} does not appear on {where}.");
            }
        }

        // 19.C, then 19.D, contest by contest. Every contest is a manifest contest by 19.A, since
        // a ballot style lists only manifest contests (Manifest.Validate, BallotStructure).
        foreach (var contest in contests)
        {
            var manifestContest = manifest.Contests.Single(x => x.Id == contest.ContestId);
            var labels = new HashSet<string>(StringComparer.Ordinal);
            foreach (var selection in contest.Selections)
            {
                if (selection.ChoiceId is not string label)
                {
                    continue;
                }

                if (!manifestContest.Choices.Any(x => x.Id == label))
                {
                    throw Failure("19.C", $"option {label} of contest {contest.ContestId} on {where} is not an option of that contest in the manifest.");
                }

                if (!labels.Add(label))
                {
                    throw Failure("19.structure", $"{where} lists option {label} of contest {contest.ContestId} more than once.");
                }
            }

            foreach (var option in manifestContest.Choices)
            {
                if (!labels.Contains(option.Id))
                {
                    throw Failure("19.D", $"option {option.Id} of contest {contest.ContestId} does not occur on {where}.");
                }
            }
        }
    }

    private static VerificationFailedException Failure(string subSection, string message)
    {
        return new VerificationFailedException(subSection, $"Uncast pre-encrypted ballot content verification failed: {message}");
    }
}
