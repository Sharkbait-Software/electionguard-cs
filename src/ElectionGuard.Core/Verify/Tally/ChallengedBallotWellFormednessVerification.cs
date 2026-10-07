using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;

namespace ElectionGuard.Core.Verify.Tally;

/// <summary>
/// Verification 14 (Validation of well-formedness and content of challenged ballots), §3.6.7 p.55 and
/// §6.2.7 p.93. For a decrypted challenged ballot the verifier confirms that its labels match the
/// manifest:
/// <list type="bullet">
/// <item>(14.A) each contest label occurs in the list of contests of the ballot's ballot style;</item>
/// <item>(14.B) each contest of the ballot style appears on the decrypted ballot (the spec's text
/// says "on the uncast pre-encrypted ballot", the wording of Verification 19.B; for a challenged
/// ballot it is the decrypted challenged ballot);</item>
/// <item>(14.C) each option label of a contest occurs as an option label of that contest in the
/// manifest;</item>
/// <item>(14.D) each option label the manifest lists for the contest occurs in the decrypted
/// contest;</item>
/// </list>
/// and that it is well formed, for each contest:
/// <list type="bullet">
/// <item>(14.E) each selection σ is a valid value ("usually either a 0 or a 1"): 0..R, the option
/// selection limit, for an option; 0..the field's range bound for a supplemental field (§3.3.9; an
/// indicator 0..1, the undervote difference 0..L, the write-in count 0..the number of write-in
/// fields);</item>
/// <item>(14.F) the sum of all selections is at most the selection limit L. Write-ins count toward the
/// limit exactly like selections (user decision Q13), so the sum is that of the options plus the
/// write-in count where the contest declares one; the indicators and the undervote difference are not
/// selections.</item>
/// </list>
/// Supplemental fields (§3.1.3 p.19: "treated like and listed with the option selection fields") are
/// checked by 14.C and 14.D like options. A partial decryption that leaves out contests, which
/// Verification 13 accepts in an RLA setting, fails 14.B as written.
/// </summary>
public class ChallengedBallotWellFormednessVerification
{
    /// <summary>
    /// Verifies <paramref name="decrypted"/>, the decryption of the challenged <paramref name="ballot"/>,
    /// against <paramref name="manifest"/>, whose ballot style the ballot names. Throws
    /// <see cref="VerificationFailedException"/>: "14.structure" if the decryption is for another
    /// ballot, the ballot is not recorded as challenged, its ballot style is not in the manifest, or a
    /// list or entry of the decryption is missing or repeated; otherwise "14.A" to "14.D" for the first
    /// label check that fails over the whole ballot, then "14.E" or "14.F" for the first contest that is
    /// not well formed.
    /// </summary>
    public void Verify(Manifest manifest, EncryptedBallot ballot, DecryptedChallengedBallot decrypted)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(decrypted);

        string where = $"challenged ballot {ballot.Id}";
        if (decrypted.BallotId != ballot.Id)
        {
            throw Failure("14.structure", $"the decryption is for ballot {decrypted.BallotId}, not ballot {ballot.Id}.");
        }

        if (ballot.Status != BallotStatus.Challenged)
        {
            throw Failure("14.structure", $"{where} is recorded as {ballot.Status}, not as challenged.");
        }

        var style = manifest.BallotStyles.FirstOrDefault(x => x.Id == ballot.BallotStyleId)
            ?? throw Failure("14.structure", $"{where} names ballot style {ballot.BallotStyleId}, which is not in the manifest.");

        var contests = decrypted.Contests ?? throw Failure("14.structure", $"the decryption of {where} has no contest list.");
        var seenContests = new HashSet<string>(StringComparer.Ordinal);
        foreach (var contest in contests)
        {
            if (contest?.ContestId is null || contest.Choices is null || contest.SupplementalFields is null
                || contest.Choices.Any(x => x?.Id is null) || contest.SupplementalFields.Any(x => x?.Id is null))
            {
                throw Failure("14.structure", $"the decryption of {where} has a null contest, option list or option entry.");
            }

            if (!seenContests.Add(contest.ContestId))
            {
                throw Failure("14.structure", $"the decryption of {where} lists contest {contest.ContestId} more than once.");
            }
        }

        // 14.A, then 14.B.
        foreach (var contest in contests)
        {
            if (!style.ContestIds.Contains(contest.ContestId, StringComparer.Ordinal))
            {
                throw Failure("14.A", $"contest {contest.ContestId} on {where} is not a contest of its ballot style {style.Id}.");
            }
        }

        foreach (var contestId in style.ContestIds)
        {
            if (!seenContests.Contains(contestId))
            {
                throw Failure("14.B", $"contest {contestId} of ballot style {style.Id} does not appear on the decryption of {where}.");
            }
        }

        // 14.C, then 14.D, contest by contest. Every contest is a manifest contest by 14.A, since
        // Manifest.Validate requires a ballot style's contests to be in the manifest.
        foreach (var contest in contests)
        {
            var manifestContest = manifest.Contests.Single(x => x.Id == contest.ContestId);
            CheckLabels(contest.ContestId, contest.Choices, manifestContest.Choices, "option");
            CheckLabels(contest.ContestId, contest.SupplementalFields, manifestContest.SupplementalFields, "supplemental field");
        }

        // 14.E, then 14.F, contest by contest.
        foreach (var contest in contests)
        {
            var manifestContest = manifest.Contests.Single(x => x.Id == contest.ContestId);
            long sum = 0;
            foreach (var option in contest.Choices)
            {
                var manifestOption = manifestContest.Choices.Single(x => x.Id == option.Id);
                CheckRange(contest.ContestId, option, manifestContest.RangeBound(manifestOption));
                sum += option.Value;
            }

            foreach (var field in contest.SupplementalFields)
            {
                var manifestField = manifestContest.SupplementalFields.Single(x => x.Id == field.Id);
                CheckRange(contest.ContestId, field, manifestContest.RangeBound(manifestField));
                if (manifestField.Kind == SupplementalFieldKind.WriteInCount)
                {
                    sum += field.Value;
                }
            }

            if (sum > manifestContest.SelectionLimit)
            {
                throw Failure("14.F", $"contest {contest.ContestId} on {where} has selections (with write-ins, user decision Q13) summing to {sum}, above its selection limit {manifestContest.SelectionLimit}.");
            }
        }

        void CheckLabels<T>(string contestId, List<DecryptedChallengedField> released, List<T> declared, string kind)
            where T : Choice
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in released)
            {
                if (!declared.Any(x => x.Id == field.Id))
                {
                    throw Failure("14.C", $"{kind} {field.Id} of contest {contestId} on {where} is not a {kind} of that contest in the manifest.");
                }

                if (!seen.Add(field.Id))
                {
                    throw Failure("14.structure", $"contest {contestId} on the decryption of {where} lists {kind} {field.Id} more than once.");
                }
            }

            foreach (var field in declared)
            {
                if (!seen.Contains(field.Id))
                {
                    throw Failure("14.D", $"{kind} {field.Id} of contest {contestId} in the manifest does not occur on the decryption of {where}.");
                }
            }
        }

        void CheckRange(string contestId, DecryptedChallengedField field, int bound)
        {
            if (field.Value < 0 || field.Value > bound)
            {
                throw Failure("14.E", $"the selection {field.Value} for {field.Id} of contest {contestId} on {where} is not a valid value (0..{bound}).");
            }
        }

        static VerificationFailedException Failure(string subSection, string message) =>
            new(subSection, $"Challenged ballot well-formedness verification failed: {message}");
    }
}
