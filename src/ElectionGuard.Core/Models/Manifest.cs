using ElectionGuard.Core.PreEncryption;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Models;

public record Manifest
{
    public required string ElectionId { get; init; }
    public required List<Contest> Contests { get; init; }
    public required List<BallotStyle> BallotStyles { get; init; }
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

        // §3.4.4 p.42 specifies the no chaining (0x00000000) and simple chaining (0x00000001) modes;
        // "other modes must be uniquely identified by a 4-byte identifier and specified in the
        // election manifest". This manifest model specifies no other mode, so any other value (JSON
        // accepts any integer for the enum) would get rules the spec never gave it.
        if (ChainingMode is not (ChainingMode.None or ChainingMode.Simple))
        {
            throw new InvalidManifestException($"Manifest {ElectionId} has chaining mode {(int)ChainingMode}; only the no chaining mode 0x00000000 and the simple chaining mode 0x00000001 are specified (§3.4.4).");
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

            // §3.3.10 p.40: D_Λ has 32·b_Λ bytes and the KDF hashes b(b_Λ·256, 4), so a contest that
            // has contest data needs 1 <= b_Λ < 2^24; 0 declares none (user decision Q7).
            if (contest.ContestDataBlocks < 0 || contest.ContestDataBlocks >= Contest.ContestDataBlocksLimit)
            {
                throw new InvalidManifestException($"Contest {contest.Id} declares {contest.ContestDataBlocks} contest data blocks; b_Λ is 0 (no contest data) or satisfies 1 <= b_Λ < 2^24 (§3.3.10 p.40).");
            }
        }

        if (HashTrimmingFunction is { } omega)
        {
            ValidatePreEncryption(omega);
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
    /// An election that uses pre-encrypted ballots (§4; <see cref="HashTrimmingFunction"/> set) names
    /// one of the §4.6 functions Ω1-Ω8, and none of its contests declares supplemental fields
    /// (§3.3.9), write-in fields or contest data (§3.3.10).
    ///
    /// §4.1's selection vectors have one entry per selectable option (eqs. 112-114) and a contest has
    /// L null vectors, with no slot for a supplemental field, and p.66 says "contests on pre-encrypted
    /// ballots do not have encrypted contest data". A recorded pre-encrypted ballot therefore carries
    /// neither, while <see cref="Verify.BallotStructure"/> requires every ballot to carry every field
    /// its contest declares, so that a ballot's shape does not reveal how it was made (S5, S6). The
    /// spec does not say how the two kinds of ballot share such a contest; refusing the combination
    /// is the safe reading until that is decided (S9 open question). A contest that offers write-in
    /// fields must declare the write-in count (user decision Q19), so it is refused here as well.
    /// </summary>
    private void ValidatePreEncryption(HashTrimmingFunction omega)
    {
        if (omega is < PreEncryption.HashTrimmingFunction.TwoHex or > PreEncryption.HashTrimmingFunction.Number101To356)
        {
            throw new InvalidManifestException($"Manifest {ElectionId} names hash-trimming function {(int)omega}; the pre-specified functions are Ω1-Ω8 (§4.6), and Ω must be completely specified in the manifest (§4.1.5).");
        }

        foreach (var contest in Contests)
        {
            if (contest.SupplementalFields is { Count: > 0 } || contest.WriteInFieldCount > 0)
            {
                throw new InvalidManifestException($"Contest {contest.Id} declares supplemental fields or write-in fields, but the election uses pre-encrypted ballots (it names a hash-trimming function): a pre-encrypted selection vector has no slot for a supplemental field (§4.1, eqs. 112-114), so pre-encrypted and regular ballots could not share the contest's shape.");
            }

            if (contest.ContestDataBlocks > 0)
            {
                throw new InvalidManifestException($"Contest {contest.Id} declares contest data (b_Λ = {contest.ContestDataBlocks}), but the election uses pre-encrypted ballots (it names a hash-trimming function): \"contests on pre-encrypted ballots do not have encrypted contest data\" (p.66), so pre-encrypted and regular ballots could not share the contest's shape.");
            }
        }
    }

    /// <summary>
    /// §3.1.3 p.19 and §3.3.9: the supplemental verifiable fields a contest declares are "treated
    /// like and listed with the option selection fields", so each takes the next option index after
    /// the selectable options (m + 1, m + 2, ... in the order declared) and a label unique among the
    /// contest's options and fields. The spec describes one field of each kind per contest. There is
    /// no per-field counts-toward-limit setting (user decision Q14): a declared ("tracked") field
    /// takes part in the selection-limit relations its kind calls for (see
    /// <see cref="Verify.Ballot.AdherenceToVoteLimitsVerification"/>), and an undeclared one does not
    /// exist. Write-ins always count toward the limit (Q13), so a contest that offers write-in fields
    /// must declare the write-in count: without its ciphertext no proof could include them.
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

        // User decision Q13: "Any write in should count towards the limit". Only the write-in count's
        // ciphertext can carry the write-ins into the selection-limit proof, so a contest that offers
        // write-in fields must track that count (user decision Q19: "Reject manifest", rather than let
        // untracked write-ins not count at all).
        if (contest.WriteInFieldCount > 0 && !kindSeen[(int)SupplementalFieldKind.WriteInCount])
        {
            throw new InvalidManifestException($"Contest {contest.Id} offers {contest.WriteInFieldCount} write-in fields but declares no write-in count field; write-ins count toward the contest selection limit (user decision Q13), which only the write-in count's encryption can show (§3.3.9 p.39: \"The number of write-ins should be incorporated into the proof of meeting the selection limit\").");
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
    /// b_Λ (§3.3.10 p.40): the contest's contest data field is exactly 32·b_Λ bytes, "specified in
    /// the election manifest to be the smallest value large enough for D_Λ to capture all additional
    /// information about this contest" (user decision Q7: per contest). 0, the default, declares no
    /// contest data: no ballot may carry any for the contest. Above 0, every ballot carries exactly
    /// one encrypted contest data field for the contest, whether or not the voter wrote anything
    /// (an empty field encrypts 32·b_Λ zero bytes), so the ballot's shape never reveals whether
    /// write-in text was entered. <see cref="BallotEncryption.ContestDataEncoding"/> turns a string
    /// into such a field.
    /// </summary>
    public int ContestDataBlocks { get; init; }

    /// <summary>b_Λ is below this (2^24), so that b(b_Λ·256, 4) fits in four bytes (§3.3.10 p.40).</summary>
    public const int ContestDataBlocksLimit = 1 << 24;

    /// <summary>The length in bytes of the contest's data field D_Λ and of C_1: 32·<see cref="ContestDataBlocks"/>.</summary>
    public int ContestDataLength() => 32 * ContestDataBlocks;

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

    /// <summary>1 if no selection and no write-in was made (user decision Q13), 0 otherwise, and 0 on an overvoted contest (§3.3.9 p.39; user decision Q3). Range 0..1.</summary>
    NullVoteIndicator = 2,

    /// <summary>1 if the sum of the selections and write-ins is below the contest selection limit L, 0 otherwise and 0 on an overvoted contest (§3.3.9 p.38; user decisions Q11, Q13). Range 0..1.</summary>
    UndervoteIndicator = 3,

    /// <summary>L minus the sum of the selections and write-ins, and 0 on an overvoted contest whose overvote indicator is declared (§3.1.3 p.18, §3.3.9 p.38; user decision Q15). Range 0..L.</summary>
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
