using ElectionGuard.Core.PreEncryption;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Models;

public record Manifest
{
    public required string ElectionId { get; init; }
    public required List<Contest> Contests { get; init; }
    public required List<BallotStyle> BallotStyles { get; init; }
    public required int OptionalContestDataMaxLength { get; init; }
    public bool IncludeOvervotes { get; init; }
    public bool IncludeNullvotes { get; init; }
    public bool IncludeUndervotes { get; init; }
    public bool IncludeWriteins { get; init; }
    public ChainingMode ChainingMode { get; init; }

    /// <summary>
    /// §4.1.5: the hash-trimming function that turns selection hashes into short codes on
    /// pre-encrypted ballots. Null when the election does not use pre-encrypted ballots; omitted
    /// from JSON then, so manifests that do not use it serialize exactly as before.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public HashTrimmingFunction? HashTrimmingFunction { get; init; }

    /// <summary>
    /// §3.1.3 Indices: a contest index is the contest's 1-based position in the manifest's contest
    /// list, and an option index is the option's 1-based position in its contest's option list.
    /// Every nonce, proof challenge and contest hash hashes these indices, so a manifest whose
    /// <see cref="Contest.Index"/>/<see cref="Choice.Index"/> disagree with the positions would
    /// produce values no conformant implementation reproduces, and two options sharing an index
    /// would share a nonce. The labels (<see cref="Contest.Id"/>, <see cref="Choice.Id"/> within
    /// its contest, <see cref="BallotStyle.Id"/>) must be unique so that the lists are bijective.
    ///
    /// Throws <see cref="InvalidManifestException"/> on the first violation. Called when an
    /// <see cref="EncryptionRecord"/> is built (which covers deserialization) and again by the
    /// ballot encryptors' constructors, the write path where non-conformant indices would be baked
    /// into ballots. The verifications do not call it: they recompute against a record that was
    /// validated when it was built, and re-validating per ballot would cost O(manifest) each time.
    /// </summary>
    public void Validate()
    {
        if (Contests == null)
        {
            throw new InvalidManifestException($"Manifest {ElectionId} has no contest list.");
        }

        for (int position = 0; position < Contests.Count; position++)
        {
            var contest = Contests[position];
            if (contest.Index != position + 1)
            {
                throw new InvalidManifestException(
                    $"Contest {contest.Id} is at position {position + 1} of the manifest's contest list but has index {contest.Index}; a contest index must be its 1-based position (§3.1.3).");
            }

            if (contest.Choices == null)
            {
                throw new InvalidManifestException($"Contest {contest.Id} has no option list.");
            }

            for (int choicePosition = 0; choicePosition < contest.Choices.Count; choicePosition++)
            {
                var choice = contest.Choices[choicePosition];
                if (choice.Index != choicePosition + 1)
                {
                    throw new InvalidManifestException(
                        $"Option {choice.Id} is at position {choicePosition + 1} of contest {contest.Id}'s option list but has index {choice.Index}; an option index must be its 1-based position (§3.1.3).");
                }
            }

            if (FirstDuplicateId(contest.Choices, static x => x.Id) is string duplicateChoiceId)
            {
                throw new InvalidManifestException($"Option id {duplicateChoiceId} appears more than once in contest {contest.Id}; option labels must be unique within a contest (§3.1.3).");
            }
        }

        if (FirstDuplicateId(Contests, static x => x.Id) is string duplicateContestId)
        {
            throw new InvalidManifestException($"Contest id {duplicateContestId} appears more than once in the manifest; contest labels must be unique (§3.1.3).");
        }

        if (BallotStyles != null && FirstDuplicateId(BallotStyles, static x => x.Id) is string duplicateBallotStyleId)
        {
            throw new InvalidManifestException($"Ballot style id {duplicateBallotStyleId} appears more than once in the manifest; ballot style labels must be unique (§3.1.3).");
        }
    }

    /// <summary>
    /// Lists up to this long are checked for duplicates pairwise, without allocating. Callers such
    /// as the perf harness and the console construct a <see cref="BallotEncryption.BallotEncryptor"/>
    /// per ballot, so the constructor's validation sits on the encryption path.
    /// </summary>
    private const int PairwiseDuplicateCheckLimit = 64;

    /// <summary>The first id that repeats an earlier one in <paramref name="items"/>, or null.</summary>
    private static string? FirstDuplicateId<T>(List<T> items, Func<T, string> getId)
    {
        if (items.Count <= PairwiseDuplicateCheckLimit)
        {
            for (int i = 1; i < items.Count; i++)
            {
                var id = getId(items[i]);
                for (int j = 0; j < i; j++)
                {
                    if (string.Equals(id, getId(items[j]), StringComparison.Ordinal))
                    {
                        return id;
                    }
                }
            }

            return null;
        }

        var seen = new HashSet<string>(items.Count, StringComparer.Ordinal);
        foreach (var item in items)
        {
            var id = getId(item);
            if (!seen.Add(id))
            {
                return id;
            }
        }

        return null;
    }
}

/// <summary>
/// A manifest that breaks a structural rule of §3.1.3 (see <see cref="Manifest.Validate"/>).
/// </summary>
public class InvalidManifestException : ArgumentException
{
    public InvalidManifestException(string message) : base(message)
    {
    }
}

public enum ChainingMode
{
    None = 0,
    Simple = 1,
}

public record Contest
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required int SelectionLimit { get; init; }
    public required int OptionSelectionLimit { get; init; }
    public required int Index { get; init; }
    public required List<Choice> Choices { get; init; }
}

public record Choice
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required int Index { get; init; }
}

public record BallotStyle
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required List<string> ContestIds { get; init; }
}
