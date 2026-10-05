using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// The shape a ballot must have before any per-selection verification means anything: its ballot
/// style is in the manifest, it lists exactly that style's contests, each once, and each contest
/// lists exactly the manifest's options for that contest, each once.
///
/// The spec has no lettered sub-check for this. It is implicit in its index-keyed model: one
/// ciphertext per (contest index, option index) (§3.1.3 p.17; §3.4 "unique contest index"), and
/// Verifications 6, 7 and 9 range over "each selectable option within each contest" and "all
/// possible selections for the contest" (pp.36, 37, 45). Without it, a ballot that repeats a valid
/// contest verbatim, or repeats an option in a contest with slack under its selection limit, passes
/// Verifications 5-9 and is tallied twice: the proofs are bound to H_I and the indices, not to the
/// position of a ciphertext in the ballot's lists.
///
/// A failure is reported as sub-section <c>"N.structure"</c>, N being the verification that found
/// it (6, 7, 8, 9 for regular ballots, 16 for pre-encrypted ones), and is checked before any of that
/// verification's lettered checks: it decides which ciphertexts those checks range over.
///
/// The pass path allocates nothing; it runs on every ballot in Verifications 6, 7, 8 and in every
/// <see cref="Tally.EncryptedTally.AddBallot"/>. The manifest itself is trusted to have unique
/// contest and option labels (<see cref="Manifest.Validate"/>, run when the
/// <see cref="EncryptionRecord"/> was built).
/// </summary>
public static class BallotStructure
{
    /// <summary>The suffix of the sub-section a structural failure is reported under.</summary>
    public const string SubSectionSuffix = "structure";

    /// <summary>Lists up to this long are tracked in stack memory.</summary>
    private const int MaxStackAllocCount = 256;

    /// <summary>
    /// Throws <see cref="VerificationFailedException"/> with sub-section
    /// <c>"{verification}.structure"</c> unless <paramref name="ballot"/> lists exactly its ballot
    /// style's contests and exactly the manifest's options in each, each once.
    /// </summary>
    public static void Require(EncryptedBallot ballot, Manifest manifest, int verification)
    {
        if (FindViolation(ballot, manifest) is string violation)
        {
            throw Failure(verification, violation);
        }
    }

    /// <summary>
    /// Verification 16's structure for a pre-encrypted ballot (eqs. 112-116, 16.A-16.C): its ballot
    /// style is in the manifest; it lists exactly that style's contests, each once, under the
    /// manifest's contest index; and each contest with m options and selection limit L has m + L
    /// selection vectors of m encryptions each, one for each option exactly once and L null vectors.
    /// </summary>
    public static void Require(PreEncryptedBallot ballot, Manifest manifest, int verification)
    {
        if (FindViolation(ballot, manifest) is string violation)
        {
            throw Failure(verification, violation);
        }
    }

    private static VerificationFailedException Failure(int verification, string violation)
    {
        return new VerificationFailedException(
            $"{verification}.{SubSectionSuffix}",
            $"{violation} (ballot structure, §3.1.3: one ciphertext per contest and option index; checked before Verification {verification}'s lettered checks)");
    }

    /// <summary>A description of the first structural violation, or null when there is none.</summary>
    internal static string? FindViolation(EncryptedBallot ballot, Manifest manifest)
    {
        var style = FindBallotStyle(manifest, ballot.BallotStyleId);
        if (style is null)
        {
            return $"Ballot {ballot.Id} names ballot style {ballot.BallotStyleId}, which is not in the manifest.";
        }

        var manifestContests = manifest.Contests;
        Span<bool> inStyle = Flags(manifestContests.Count, stackalloc bool[MaxStackAllocCount]);
        if (MarkStyleContests(style, manifestContests, inStyle) is string styleViolation)
        {
            return styleViolation;
        }

        Span<bool> onBallot = Flags(manifestContests.Count, stackalloc bool[MaxStackAllocCount]);
        Span<bool> optionBuffer = stackalloc bool[MaxStackAllocCount];
        int contestHint = 0;
        foreach (var contest in ballot.Contests)
        {
            if (MarkContest(ballot.Id, style, contest.Id, manifestContests, inStyle, onBallot, ref contestHint, out var manifestContest) is string contestViolation)
            {
                return contestViolation;
            }

            var options = manifestContest!.Choices;
            Span<bool> seen = Flags(options.Count, optionBuffer);
            var selections = contest.Choices;
            int optionHint = 0;
            for (int i = 0; i < selections.Count; i++)
            {
                string optionId = selections[i].ChoiceId;
                int position = i < options.Count && string.Equals(options[i].Id, optionId, StringComparison.Ordinal)
                    ? i
                    : PositionOf(options, optionId, static x => x.Id, ref optionHint);
                if (position < 0)
                {
                    return $"Contest {contest.Id} on ballot {ballot.Id} has a selection for {optionId}, which is not an option of that contest in the manifest.";
                }

                if (seen[position])
                {
                    return $"Contest {contest.Id} on ballot {ballot.Id} lists option {optionId} more than once.";
                }

                seen[position] = true;
            }

            if (FirstUnset(seen) is int missing and >= 0)
            {
                return $"Contest {contest.Id} on ballot {ballot.Id} has no selection for option {options[missing].Id}.";
            }
        }

        return MissingStyleContest(ballot.Id, style, manifestContests, inStyle, onBallot);
    }

    /// <summary>A description of the first structural violation, or null when there is none.</summary>
    internal static string? FindViolation(PreEncryptedBallot ballot, Manifest manifest)
    {
        var style = FindBallotStyle(manifest, ballot.BallotStyleId);
        if (style is null)
        {
            return $"Pre-encrypted ballot {ballot.Id} names ballot style {ballot.BallotStyleId}, which is not in the manifest.";
        }

        var manifestContests = manifest.Contests;
        Span<bool> inStyle = Flags(manifestContests.Count, stackalloc bool[MaxStackAllocCount]);
        if (MarkStyleContests(style, manifestContests, inStyle) is string styleViolation)
        {
            return styleViolation;
        }

        Span<bool> onBallot = Flags(manifestContests.Count, stackalloc bool[MaxStackAllocCount]);
        Span<bool> optionBuffer = stackalloc bool[MaxStackAllocCount];
        int contestHint = 0;
        foreach (var contest in ballot.Contests)
        {
            if (MarkContest(ballot.Id, style, contest.ContestId, manifestContests, inStyle, onBallot, ref contestHint, out var manifestContest) is string contestViolation)
            {
                return contestViolation;
            }

            if (contest.ContestIndex != manifestContest!.Index)
            {
                return $"Contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} claims contest index {contest.ContestIndex}; the manifest gives it index {manifestContest.Index}.";
            }

            // Eqs. (113)-(115): m option vectors and L null vectors, each of m encryptions.
            var options = manifestContest.Choices;
            int m = options.Count;
            int limit = manifestContest.SelectionLimit;
            if (contest.Selections.Count != m + limit)
            {
                return $"Contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} has {contest.Selections.Count} selection vectors; with {m} options and selection limit {limit} it must have {m + limit}.";
            }

            Span<bool> seen = Flags(m, optionBuffer);
            int nullVectors = 0;
            int optionHint = 0;
            foreach (var selection in contest.Selections)
            {
                if (selection.Vector.Count != m)
                {
                    return $"Selection vector {selection.SelectionIndex} of contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} has {selection.Vector.Count} encryptions; the contest has {m} options.";
                }

                if (selection.ChoiceId is null)
                {
                    nullVectors++;
                    continue;
                }

                int position = PositionOf(options, selection.ChoiceId, static x => x.Id, ref optionHint);
                if (position < 0)
                {
                    return $"Contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} has a selection vector for {selection.ChoiceId}, which is not an option of that contest in the manifest.";
                }

                if (seen[position])
                {
                    return $"Contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} has more than one selection vector for option {selection.ChoiceId}.";
                }

                seen[position] = true;
            }

            if (nullVectors != limit)
            {
                return $"Contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} has {nullVectors} null vectors; its selection limit is {limit}.";
            }

            if (FirstUnset(seen) is int missing and >= 0)
            {
                return $"Contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} has no selection vector for option {options[missing].Id}.";
            }
        }

        return MissingStyleContest(ballot.Id, style, manifestContests, inStyle, onBallot);
    }

    private static BallotStyle? FindBallotStyle(Manifest manifest, string ballotStyleId)
    {
        foreach (var style in manifest.BallotStyles)
        {
            if (string.Equals(style.Id, ballotStyleId, StringComparison.Ordinal))
            {
                return style;
            }
        }

        return null;
    }

    /// <summary>Marks the manifest positions of <paramref name="style"/>'s contests.</summary>
    private static string? MarkStyleContests(BallotStyle style, List<Contest> manifestContests, Span<bool> inStyle)
    {
        int hint = 0;
        foreach (var contestId in style.ContestIds)
        {
            int position = PositionOf(manifestContests, contestId, static x => x.Id, ref hint);
            if (position < 0)
            {
                return $"Ballot style {style.Id} lists contest {contestId}, which is not in the manifest.";
            }

            if (inStyle[position])
            {
                return $"Ballot style {style.Id} lists contest {contestId} more than once.";
            }

            inStyle[position] = true;
        }

        return null;
    }

    /// <summary>
    /// Finds the ballot contest <paramref name="contestId"/> in the manifest and marks it, failing
    /// if it is not in the manifest, not on the ballot style, or already on the ballot.
    /// </summary>
    private static string? MarkContest(
        string ballotId,
        BallotStyle style,
        string contestId,
        List<Contest> manifestContests,
        ReadOnlySpan<bool> inStyle,
        Span<bool> onBallot,
        ref int hint,
        out Contest? manifestContest)
    {
        manifestContest = null;
        int position = PositionOf(manifestContests, contestId, static x => x.Id, ref hint);
        if (position < 0)
        {
            return $"Ballot {ballotId} lists contest {contestId}, which is not in the manifest.";
        }

        if (!inStyle[position])
        {
            return $"Ballot {ballotId} lists contest {contestId}, which is not on its ballot style {style.Id}.";
        }

        if (onBallot[position])
        {
            return $"Ballot {ballotId} lists contest {contestId} more than once.";
        }

        onBallot[position] = true;
        manifestContest = manifestContests[position];
        return null;
    }

    private static string? MissingStyleContest(string ballotId, BallotStyle style, List<Contest> manifestContests, ReadOnlySpan<bool> inStyle, ReadOnlySpan<bool> onBallot)
    {
        for (int i = 0; i < inStyle.Length; i++)
        {
            if (inStyle[i] && !onBallot[i])
            {
                return $"Ballot {ballotId} omits contest {manifestContests[i].Id} of its ballot style {style.Id}.";
            }
        }

        return null;
    }

    /// <summary>
    /// The position of the item with <paramref name="id"/>, searching from <paramref name="hint"/>
    /// and wrapping around, or -1. Lists in manifest order are found at the hint, so a canonical
    /// ballot costs one comparison per lookup. <paramref name="hint"/> moves past each match.
    /// </summary>
    private static int PositionOf<T>(List<T> items, string id, Func<T, string> getId, ref int hint)
    {
        int count = items.Count;
        for (int step = 0; step < count; step++)
        {
            int i = hint + step;
            if (i >= count)
            {
                i -= count;
            }

            if (string.Equals(getId(items[i]), id, StringComparison.Ordinal))
            {
                hint = i + 1 < count ? i + 1 : 0;
                return i;
            }
        }

        return -1;
    }

    private static int FirstUnset(ReadOnlySpan<bool> flags)
    {
        return flags.IndexOf(false);
    }

    /// <summary>A cleared span of <paramref name="count"/> flags, in <paramref name="buffer"/> when it fits.</summary>
    private static Span<bool> Flags(int count, Span<bool> buffer)
    {
        Span<bool> flags = count <= buffer.Length ? buffer[..count] : new bool[count];
        flags.Clear();
        return flags;
    }
}
