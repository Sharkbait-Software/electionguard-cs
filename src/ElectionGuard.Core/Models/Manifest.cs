using ElectionGuard.Core.PreEncryption;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Models;

public record Manifest
{
    public required string ElectionId { get; init; }
    public required List<Contest> Contests { get; init; }
    public required List<BallotStyle> BallotStyles { get; init; }
    public required int OptionalContestDataMaxLength { get; init; }
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

            // §3.1.3 p.17: the option selection limit R is "a positive integer". The contest
            // selection limit L is "the maximal total value for the sum of all selections"; the spec
            // does not say it is positive, but with L = 0 every selection overvotes and the contest
            // records nothing, and with L < 0 no selection-limit proof exists, so the encryptor would
            // write ballots that cannot verify. L >= 1 is also what keeps the undervote difference
            // proof's challenge input distinct from the difference count's own range proof (see
            // AdherenceToVoteLimitsVerification.ComputeUndervoteDifferenceChallenge).
            if (contest.OptionSelectionLimit < 1)
            {
                throw new InvalidManifestException($"Contest {contest.Id} has option selection limit {contest.OptionSelectionLimit}; the option selection limit R is a positive integer (§3.1.3).");
            }

            if (contest.SelectionLimit < 1)
            {
                throw new InvalidManifestException($"Contest {contest.Id} has contest selection limit {contest.SelectionLimit}; the contest selection limit L, the maximal total value for the sum of all selections (§3.1.3), must be at least 1, since with L = 0 every selection is an overvote.");
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

            ValidateSupplementalFields(contest);
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
    /// §3.1.3 p.19 and §3.3.9: the supplemental verifiable fields a contest declares are "treated
    /// like and listed with the option selection fields", so each takes the next option index after
    /// the selectable options (m + 1, m + 2, ... in the order declared) and a label unique among the
    /// contest's options and fields. The spec describes one field of each kind per contest. Which
    /// fields count toward the contest selection limit "must also be specified in the manifest"; see
    /// <see cref="SupplementalField.CountsTowardSelectionLimit"/> for the combinations that admit a
    /// selection-limit proof at all.
    /// </summary>
    private static void ValidateSupplementalFields(Contest contest)
    {
        if (contest.WriteInFieldCount < 0)
        {
            throw new InvalidManifestException($"Contest {contest.Id} offers {contest.WriteInFieldCount} write-in fields; the number of write-in fields cannot be negative.");
        }

        var fields = contest.SupplementalFields;
        if (fields == null)
        {
            throw new InvalidManifestException($"Contest {contest.Id} has no supplemental field list; an empty list declares none.");
        }

        int optionCount = contest.Choices.Count;
        Span<bool> kindSeen = stackalloc bool[SupplementalField.KindCount + 1];
        for (int position = 0; position < fields.Count; position++)
        {
            var field = fields[position];
            if (field.Index != optionCount + position + 1)
            {
                throw new InvalidManifestException(
                    $"Supplemental field {field.Id} is at position {position + 1} of contest {contest.Id}'s supplemental field list, after {optionCount} options, but has index {field.Index}; a supplemental field's option index continues after the selectable options ({optionCount + position + 1}) (§3.1.3).");
            }

            if (field.Kind is <= SupplementalFieldKind.Undefined or > (SupplementalFieldKind)SupplementalField.KindCount)
            {
                throw new InvalidManifestException($"Supplemental field {field.Id} of contest {contest.Id} has kind {field.Kind}, which is not a supplemental field kind of §3.3.9.");
            }

            if (kindSeen[(int)field.Kind])
            {
                throw new InvalidManifestException($"Contest {contest.Id} declares more than one {field.Kind} field; §3.3.9 describes at most one supplemental field of each kind per contest.");
            }

            kindSeen[(int)field.Kind] = true;

            bool mustCount = field.Kind == SupplementalFieldKind.OvervoteIndicator;
            bool mayCount = mustCount || field.Kind == SupplementalFieldKind.WriteInCount;
            if (mustCount && !field.CountsTowardSelectionLimit)
            {
                throw new InvalidManifestException($"Overvote indicator {field.Id} of contest {contest.Id} must count toward the selection limit: its validity is enforced by adding L times it to the selection-limit proof (§3.3.9 p.39).");
            }

            if (!mayCount && field.CountsTowardSelectionLimit)
            {
                string reason = field.Kind == SupplementalFieldKind.NullVoteIndicator
                    ? "§3.3.9 p.39 suggests enforcing its validity like the overvote indicator's, by adding L times it to the selection-limit proof, but that optional relation is not implemented (user decision Q2 limits the relations to the overvote term, the write-in count and the undervote difference), so the indicator is proved only by its range proof"
                    : "on an overvoted contest it is nonzero (the undervote fields are computed on the zeroed selections) while the overvote indicator already takes the whole limit, so an honest overvoted ballot would have no selection-limit proof";
                throw new InvalidManifestException($"Supplemental field {field.Id} of contest {contest.Id} ({field.Kind}) cannot count toward the selection limit: {reason}.");
            }

            if (field.Kind == SupplementalFieldKind.WriteInCount && contest.WriteInFieldCount < 1)
            {
                throw new InvalidManifestException($"Contest {contest.Id} declares a write-in count field but offers {contest.WriteInFieldCount} write-in fields; the write-in count ranges over 0..the number of write-in fields (§3.3.9 p.39).");
            }

            foreach (var choice in contest.Choices)
            {
                if (string.Equals(choice.Id, field.Id, StringComparison.Ordinal))
                {
                    throw new InvalidManifestException($"Supplemental field id {field.Id} of contest {contest.Id} is also an option id of that contest; supplemental fields are listed with the options, so their labels must be unique among them (§3.1.3 p.19).");
                }
            }
        }

        if (FirstDuplicateId(fields, static x => x.Id) is string duplicateFieldId)
        {
            throw new InvalidManifestException($"Supplemental field id {duplicateFieldId} appears more than once in contest {contest.Id}; labels must be unique within a contest (§3.1.3).");
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

    /// <summary>The selectable options, with option indices 1..m.</summary>
    public required List<Choice> Choices { get; init; }

    /// <summary>
    /// The supplemental verifiable fields this contest declares (§3.1.3 p.19, §3.3.9), in manifest
    /// order, with option indices m + 1, m + 2, ... continuing after <see cref="Choices"/>. Each is
    /// encrypted, proved, hashed into the contest hash (eq. 70), aggregated, decrypted and verified
    /// like an option. Empty when the contest declares none.
    /// </summary>
    public List<SupplementalField> SupplementalFields { get; init; } = [];

    /// <summary>
    /// The number of write-in fields the ballot offers in this contest. It bounds the number of
    /// write-ins a voter can use, and so the range of the write-in count field (§3.3.9 p.39: "between
    /// zero and the number of write-in fields that are offered"). 0 when the contest offers none.
    /// </summary>
    public int WriteInFieldCount { get; init; }

    /// <summary>
    /// Every verifiable field of the contest in manifest order: the selectable options, then the
    /// supplemental fields (§3.4.1 eq. 70: "all verifiable fields ... in order specified by the
    /// election manifest"). This is what the tally, decryption and Verifications 9 to 11 range over.
    /// Allocates an enumerator; per-ballot paths walk the two lists directly.
    /// </summary>
    public IEnumerable<Choice> VerifiableFields()
    {
        foreach (var choice in Choices)
        {
            yield return choice;
        }

        if (SupplementalFields != null)
        {
            foreach (var field in SupplementalFields)
            {
                yield return field;
            }
        }
    }

    /// <summary>The number of verifiable fields: options plus supplemental fields.</summary>
    public int VerifiableFieldCount() => Choices.Count + (SupplementalFields?.Count ?? 0);

    /// <summary>The declared supplemental field of <paramref name="kind"/>, or null.</summary>
    public SupplementalField? SupplementalFieldOfKind(SupplementalFieldKind kind)
    {
        if (SupplementalFields != null)
        {
            foreach (var field in SupplementalFields)
            {
                if (field.Kind == kind)
                {
                    return field;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// The largest value a field of this contest may encrypt, and so the bound of its range proof,
    /// which has this many plus one commitments: R (<see cref="OptionSelectionLimit"/>) for a
    /// selectable option; for a supplemental field (§3.3.9), 1 for an indicator, L
    /// (<see cref="SelectionLimit"/>) for the undervote difference count and
    /// <see cref="WriteInFieldCount"/> for the write-in count.
    /// </summary>
    public int RangeBound(Choice field)
    {
        return field is SupplementalField supplemental ? RangeBound(supplemental.Kind) : OptionSelectionLimit;
    }

    /// <summary>
    /// How many times the encryption of <paramref name="field"/> enters the contest's
    /// selection-limit proof (§3.3.8, §3.3.9 p.39): L for the overvote indicator (footnote 42: the
    /// ciphertext raised to the contest selection limit), 1 for a field that counts toward the limit
    /// (the write-in count, when the manifest says so), 0 otherwise. Every selectable option enters
    /// once. The fields of weight 1 and the options make up the "sum of the selections" that the
    /// undervote fields are computed from.
    /// </summary>
    public int SelectionLimitWeight(SupplementalField field)
    {
        if (field.Kind == SupplementalFieldKind.OvervoteIndicator)
        {
            return SelectionLimit;
        }

        return field.CountsTowardSelectionLimit ? 1 : 0;
    }

    /// <summary>The range bound of a supplemental field of <paramref name="kind"/>; see <see cref="RangeBound(Choice)"/>.</summary>
    public int RangeBound(SupplementalFieldKind kind)
    {
        return kind switch
        {
            SupplementalFieldKind.OvervoteIndicator or SupplementalFieldKind.NullVoteIndicator or SupplementalFieldKind.UndervoteIndicator => 1,
            SupplementalFieldKind.UndervoteDifferenceCount => SelectionLimit,
            SupplementalFieldKind.WriteInCount => WriteInFieldCount,
            _ => throw new InvalidManifestException($"Contest {Id} has a supplemental field of kind {kind}, which is not a supplemental field kind of §3.3.9."),
        };
    }
}

public record Choice
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required int Index { get; init; }
}

/// <summary>
/// A supplemental verifiable field of a contest (§3.1.3 pp.18-19, §3.3.9 pp.38-39): a counter that
/// "functions very much like a selectable option field", listed after the contest's options with
/// its own option index (<see cref="Choice.Index"/>) and a label (<see cref="Choice.Id"/>) unique
/// among the contest's options and fields. The voter never sets it: the encryptor derives its value
/// from the selections and the number of write-ins used (see
/// <see cref="BallotEncryption.BallotEncryptor"/>).
/// </summary>
public record SupplementalField : Choice
{
    /// <summary>The number of defined kinds; <see cref="SupplementalFieldKind"/> runs 1..this.</summary>
    internal const int KindCount = 5;

    public required SupplementalFieldKind Kind { get; init; }

    /// <summary>
    /// Whether the field enters the contest selection-limit proof (§3.1.3 p.19: "Which of those
    /// fields are counted while ensuring adherence to the contest selection limit must also be
    /// specified in the manifest"). <see cref="Manifest.Validate"/> admits only the settings for
    /// which every honest ballot has a selection-limit proof:
    /// <list type="bullet">
    /// <item>the overvote indicator must count, and counts L times (§3.3.9 p.39 and footnote 42:
    /// the sum of the selections plus L times the indicator does not exceed L);</item>
    /// <item>the write-in count may count, once (§3.3.9 p.39: "The number of write-ins should be
    /// incorporated into the proof of meeting the selection limit");</item>
    /// <item>the undervote indicator and the undervote difference count must not: on an overvoted
    /// contest they are computed on the zeroed selections, so they are nonzero (1 and L) while the
    /// overvote term already takes the whole limit, and no honest overvoted ballot would have a
    /// selection-limit proof (the indicator's 1 on an overvote is open S5 user question 4, see
    /// <c>BallotEncryptor.SupplementalValue</c>; were it 0, this reason would cover only the
    /// difference count);</item>
    /// <item>the null-vote indicator must not either, for a different reason: it is 0 on an
    /// overvote (user decision Q3), and §3.3.9 p.39 suggests enforcing its validity "just as the
    /// validity of the encrypted overvote indicator", i.e. by adding L times it to the limit proof,
    /// which every honest ballot would pass. That optional relation is not implemented (user
    /// decision Q2 lists only the overvote term, the write-in count and the undervote difference),
    /// so a once-weighted flag would mean something the spec does not describe.</item>
    /// </list>
    /// </summary>
    public bool CountsTowardSelectionLimit { get; init; }
}

/// <summary>
/// The kinds of supplemental verifiable field §3.3.9 describes. Serialized by name.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<SupplementalFieldKind>))]
public enum SupplementalFieldKind
{
    /// <summary>Not a kind; a manifest that leaves the kind out is rejected.</summary>
    Undefined = 0,

    /// <summary>1 if the contest was overvoted, 0 otherwise (§3.3.9 p.38). Range 0..1.</summary>
    OvervoteIndicator = 1,

    /// <summary>1 if no selection was made, 0 otherwise, and 0 on an overvoted contest (§3.3.9 p.39; user decision Q3). Range 0..1.</summary>
    NullVoteIndicator = 2,

    /// <summary>1 if the sum of the selections is below the contest selection limit L, 0 otherwise (§3.3.9 p.38). Range 0..1.</summary>
    UndervoteIndicator = 3,

    /// <summary>L minus the sum of the selections (§3.1.3 p.18, §3.3.9 p.38). Range 0..L.</summary>
    UndervoteDifferenceCount = 4,

    /// <summary>The number of write-in fields used (§3.1.3 p.19, §3.3.9 p.39). Range 0..<see cref="Contest.WriteInFieldCount"/>.</summary>
    WriteInCount = 5,
}

public record BallotStyle
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required List<string> ContestIds { get; init; }
}
