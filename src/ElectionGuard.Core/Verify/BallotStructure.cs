using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// The shape a ballot must have before any per-selection verification means anything: its ballot
/// style is in the manifest, it lists exactly that style's contests, each once, and each contest
/// lists exactly the manifest's options for that contest, each once, and exactly the supplemental
/// fields the manifest declares for it (§3.3.9), each once; and it carries an encrypted contest data
/// field exactly where the manifest declares contest data for the contest, with C_1 of exactly
/// 32·b_Λ bytes (§3.3.10); and it carries the encrypted ballot nonce C_ξB, with C_ξB,1 of exactly
/// 32 bytes (§3.3.4), its 36-byte chaining field B_C (§3.4.4), and the device id S_device it was
/// encrypted on (§3.4.3).
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
    /// Verification 16's structure for a pre-encrypted ballot (eqs. 112-116, 16.A-16.C): the manifest
    /// names a hash-trimming function, so the election uses pre-encrypted ballots (§4.1.5); its ballot
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
        Span<bool> fieldBuffer = stackalloc bool[SupplementalField.KindCount];
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

            if (SupplementalFieldViolation(ballot.Id, contest, manifestContest, fieldBuffer) is string fieldViolation)
            {
                return fieldViolation;
            }

            if (ContestDataViolation(ballot.Id, contest, manifestContest) is string contestDataViolation)
            {
                return contestDataViolation;
            }
        }

        if (MissingStyleContest(ballot.Id, style, manifestContests, inStyle, onBallot) is string missingContest)
        {
            return missingContest;
        }

        return BallotNonceViolation(ballot.Id, ballot.EncryptedBallotNonce)
            ?? ChainingFieldViolation(ballot.Id, ballot.ChainingField)
            ?? DeviceIdViolation(ballot.Id, ballot.DeviceId);
    }

    /// <summary>
    /// The ballot names the device it was encrypted on, S_device (§3.4.3 eq. 72; §4.1.4 eq. 119):
    /// Verifications 8 and 16 hash it into H_DI, and the recording tool regenerates a pre-encrypted
    /// ballot on its device. The property is required, but a JSON document that writes null (or a
    /// protobuf message without the field) yields a ballot without it, which would otherwise surface
    /// as an <see cref="ArgumentNullException"/> far from the cause, or, on the pre-encrypted nonce
    /// path, after the guardians had already decrypted their shares (S9 review round 3).
    /// </summary>
    private static string? DeviceIdViolation(string ballotId, string? deviceId)
    {
        return deviceId is null
            ? $"Ballot {ballotId} names no device; every ballot carries the S_device it was encrypted on (§3.4.3 eq. 72, §4.1.4 eq. 119)."
            : null;
    }

    /// <summary>
    /// The ballot carries the 36-byte chaining field B_C its confirmation code was computed with
    /// (§3.4.4; eqs. 71, 116). Both decoders refuse any other length; a default (empty) value only
    /// comes from code that built the ballot without one, and would otherwise be hashed as no B_C.
    /// </summary>
    private static string? ChainingFieldViolation(string ballotId, ChainingField chainingField)
    {
        return chainingField.IsWellFormed
            ? null
            : $"Ballot {ballotId} has a chaining field of {((byte[])chainingField)?.Length ?? 0} bytes; B_C is exactly {ChainingField.ByteLength} (§3.4.4).";
    }

    /// <summary>
    /// §3.3.4: "every ElectionGuard ballot contains an encryption of the ballot nonce", C_ξB, whose
    /// C_ξB,1 is b(ξ_B, 32) ⊕ k_1, exactly 32 bytes (eq. 37). It is the only way a challenged ballot
    /// is opened (§3.6.7); a ballot without it could never be audited. Neither the protobuf decoder
    /// (which refuses a missing field) nor the JSON one (which refuses a missing property) yields
    /// one without it; a JSON document that writes null does.
    /// </summary>
    private static string? BallotNonceViolation(string ballotId, EncryptedBallotNonce? nonce)
    {
        if (nonce is null)
        {
            return $"Ballot {ballotId} has no encrypted ballot nonce C_ξB; every ballot carries one (§3.3.4, §4.2).";
        }

        if (nonce.C1 is not { Length: BallotNonceEncryption.NonceBytes })
        {
            return $"Ballot {ballotId} has an encrypted ballot nonce whose C_ξB,1 is {nonce.C1?.Length ?? 0} bytes; it is exactly {BallotNonceEncryption.NonceBytes} (eq. 37).";
        }

        return null;
    }

    /// <summary>
    /// The contest lists exactly the supplemental fields its manifest contest declares, each once
    /// (§3.1.3 p.19: they are listed with the options, so the same one-ciphertext-per-index rule
    /// applies). An undeclared field would be hashed and tallied as nothing the manifest defines; a
    /// missing one would leave its count unverifiable.
    ///
    /// A null list (or a null entry) is a violation even where the manifest declares no fields: the
    /// list is required, every encoder writes it (empty when there are none), and the protobuf
    /// decoder yields an empty list, so null only comes from a malformed JSON document. Every
    /// consumer after <see cref="Require(EncryptedBallot, Manifest, int)"/> walks the list unguarded.
    /// </summary>
    private static string? SupplementalFieldViolation(string ballotId, EncryptedContest contest, Contest manifestContest, Span<bool> buffer)
    {
        var declared = manifestContest.SupplementalFields;
        var encrypted = contest.SupplementalFields;
        if (encrypted is null)
        {
            return $"Contest {contest.Id} on ballot {ballotId} has a null supplemental field list; a contest with no supplemental fields lists none (the manifest declares {declared.Count}).";
        }

        Span<bool> seen = Flags(declared.Count, buffer);
        int hint = 0;
        for (int i = 0; i < encrypted.Count; i++)
        {
            if (encrypted[i] is null)
            {
                return $"Contest {contest.Id} on ballot {ballotId} has a null entry in its supplemental field list.";
            }

            string fieldId = encrypted[i].FieldId;
            int position = i < declared.Count && string.Equals(declared[i].Id, fieldId, StringComparison.Ordinal)
                ? i
                : PositionOf(declared, fieldId, static x => x.Id, ref hint);
            if (position < 0)
            {
                return $"Contest {contest.Id} on ballot {ballotId} has supplemental field {fieldId}, which the manifest does not declare for that contest.";
            }

            if (seen[position])
            {
                return $"Contest {contest.Id} on ballot {ballotId} lists supplemental field {fieldId} more than once.";
            }

            seen[position] = true;
        }

        if (FirstUnset(seen) is int missing and >= 0)
        {
            return $"Contest {contest.Id} on ballot {ballotId} has no encryption of supplemental field {declared[missing].Id}, which the manifest declares.";
        }

        return null;
    }

    /// <summary>
    /// §3.3.10 with user decision Q7: a contest whose manifest entry declares b_Λ >= 1 carries one
    /// encrypted contest data field on every ballot, its C_1 exactly 32·b_Λ bytes (eq. 68; the
    /// length is fixed so that it reveals nothing about the data); a contest that declares none
    /// carries none. Eq. (70) hashes the field into the contest hash only when it is present, so a
    /// field the manifest does not call for, or one of another length, would be hashed and
    /// decrypted as something the manifest does not define.
    /// </summary>
    private static string? ContestDataViolation(string ballotId, EncryptedContest contest, Contest manifestContest)
    {
        var data = contest.ContestData;
        int blocks = manifestContest.ContestDataBlocks;
        if (blocks == 0)
        {
            return data is null
                ? null
                : $"Contest {contest.Id} on ballot {ballotId} carries contest data, but the manifest declares none for that contest (b_Λ = 0).";
        }

        if (data is null)
        {
            return $"Contest {contest.Id} on ballot {ballotId} carries no contest data; the manifest declares b_Λ = {blocks} for that contest, so every ballot carries the field (§3.3.10).";
        }

        if (data.C1 is null || data.C1.Length != manifestContest.ContestDataLength())
        {
            return $"Contest {contest.Id} on ballot {ballotId} has a contest data C_1 of {data.C1?.Length ?? 0} bytes; with b_Λ = {blocks} it is exactly {manifestContest.ContestDataLength()} (§3.3.10 eq. 68).";
        }

        return null;
    }

    /// <summary>A description of the first structural violation, or null when there is none.</summary>
    internal static string? FindViolation(PreEncryptedBallot ballot, Manifest manifest)
    {
        // §4.1.5: an election that uses pre-encrypted ballots names Ω in its manifest. Without one
        // there is no pre-encrypted ballot to verify or whose nonce to decrypt, and a request built
        // around a regular ballot's id_B, H_I and C_ξB (the same construction, §4.2) is refused
        // here (S9-6; the guardians also check the issued list and the record, user decision Q31).
        if (manifest.HashTrimmingFunction is null)
        {
            return $"Pre-encrypted ballot {ballot.Id}: the manifest names no hash-trimming function, so the election does not use pre-encrypted ballots (§4.1.5).";
        }

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
        Span<bool> nullBuffer = stackalloc bool[MaxStackAllocCount];
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
            Span<bool> nullSeen = Flags(limit, nullBuffer);
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
                    // Eq. (121): the l-th null vector is j = m + l (§4.2.1 p.61, "the sequence of
                    // indices should be extended accordingly"), each once.
                    nullVectors++;
                    if (selection.SelectionIndex <= m || selection.SelectionIndex > m + limit || nullSeen[selection.SelectionIndex - m - 1])
                    {
                        return $"Null vector {selection.SelectionIndex} of contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} does not have its own index among m + 1..m + L = {m + 1}..{m + limit} (eq. 121).";
                    }

                    nullSeen[selection.SelectionIndex - m - 1] = true;
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

                // Eq. (121): an option's vector is j = its option index.
                if (selection.SelectionIndex != options[position].Index)
                {
                    return $"The selection vector of option {selection.ChoiceId} in contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} has index {selection.SelectionIndex}; its option index is {options[position].Index} (eq. 121).";
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

        return MissingStyleContest(ballot.Id, style, manifestContests, inStyle, onBallot)
            ?? BallotNonceViolation(ballot.Id, ballot.EncryptedBallotNonce)
            ?? ChainingFieldViolation(ballot.Id, ballot.ChainingField)
            ?? DeviceIdViolation(ballot.Id, ballot.DeviceId);
    }

    /// <summary>
    /// The structure of a cast pre-encrypted ballot (§4.3.1, §4.4), checked by Verifications 15, 16
    /// and 17 before their lettered checks: the standard ballot structure
    /// (<see cref="Require(EncryptedBallot, Manifest, int)"/>), and then that the ballot is a
    /// pre-encrypted one of an election that uses them (the manifest names a hash-trimming function),
    /// recorded as cast (an uncast one is published with its nonces, Verification 18), whose <see cref="EncryptedBallot.PreEncryptedContests"/> has one entry per contest of the
    /// ballot, in the same order and under the same label, each with the contest's m + L selection
    /// hashes (eqs. 113-115) in strictly increasing order (§4.4 "sorted numerically"; two equal
    /// hashes would be one vector twice) and exactly L selected vectors (the recording tool pads an
    /// undervote with null vectors) of m encryptions each, in strictly increasing order of their
    /// selection hashes, each with a short code.
    /// </summary>
    public static void RequirePreEncryptedCast(EncryptedBallot ballot, Manifest manifest, int verification)
    {
        if ((FindViolation(ballot, manifest) ?? FindPreEncryptedCastViolation(ballot, manifest)) is string violation)
        {
            throw Failure(verification, violation);
        }
    }

    /// <summary>The first violation of the pre-encryption part of a cast pre-encrypted ballot, or null.</summary>
    internal static string? FindPreEncryptedCastViolation(EncryptedBallot ballot, Manifest manifest)
    {
        var preEncrypted = ballot.PreEncryptedContests;
        if (preEncrypted is null)
        {
            return $"Ballot {ballot.Id} is not a pre-encrypted ballot: it carries no pre-encryption data (§4.4).";
        }

        // This record is what the recording tool makes of a cast ballot (§4.3.1, §4.4). A
        // pre-encrypted ballot that is not cast is published as the ballot with its released nonces
        // (PreEncryptedUncastBallot) and audited by Verification 18; under any other status this
        // record would leave the tally silently and be audited by nothing.
        if (ballot.Status != BallotStatus.Cast)
        {
            return $"Pre-encrypted ballot {ballot.Id} is recorded as {ballot.Status}; a pre-encrypted ballot's record is a cast ballot's, and an uncast one is published with its nonces and checked by Verification 18 (§4.3, §4.4).";
        }

        if (manifest.HashTrimmingFunction is null)
        {
            return $"Ballot {ballot.Id} is a pre-encrypted ballot, but the manifest names no hash-trimming function, so the election does not use pre-encrypted ballots (§4.1.5).";
        }

        if (preEncrypted.Count != ballot.Contests.Count)
        {
            return $"Pre-encrypted ballot {ballot.Id} has pre-encryption data for {preEncrypted.Count} contests; it lists {ballot.Contests.Count}.";
        }

        for (int i = 0; i < preEncrypted.Count; i++)
        {
            var contest = preEncrypted[i];
            if (contest is null || !string.Equals(contest.ContestId, ballot.Contests[i].Id, StringComparison.Ordinal))
            {
                return $"Entry {i + 1} of pre-encrypted ballot {ballot.Id}'s pre-encryption data is for contest {contest?.ContestId}; the ballot's contest {i + 1} is {ballot.Contests[i].Id}.";
            }

            // FindViolation has already found the contest in the manifest.
            var manifestContest = manifest.Contests.Single(x => x.Id == contest.ContestId);
            int m = manifestContest.Choices.Count;
            int limit = manifestContest.SelectionLimit;

            var hashes = contest.SelectionHashes;
            if (hashes is null || hashes.Count != m + limit)
            {
                return $"Contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} publishes {hashes?.Count ?? 0} selection hashes; with {m} options and selection limit {limit} it has {m + limit} (§4.4).";
            }

            for (int h = 0; h < hashes.Count; h++)
            {
                if (!hashes[h].IsWellFormed)
                {
                    return $"Selection hash {h + 1} of contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} is not {SelectionHash.ByteLength} bytes.";
                }

                if (h > 0 && hashes[h - 1].CompareTo(hashes[h]) >= 0)
                {
                    return $"The selection hashes of contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} are not in strictly increasing order (§4.4: sorted numerically).";
                }
            }

            var selected = contest.SelectedVectors;
            if (selected is null || selected.Count != limit)
            {
                return $"Contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} publishes {selected?.Count ?? 0} selected vectors; the recording tool combines exactly L = {limit} (null vectors pad an undervote).";
            }

            for (int v = 0; v < selected.Count; v++)
            {
                var vector = selected[v];
                if (vector?.Vector is null || vector.Vector.Count != m || !vector.SelectionHash.IsWellFormed || vector.ShortCode.Value is null)
                {
                    return $"Selected vector {v + 1} of contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} does not have {m} encryptions, a {SelectionHash.ByteLength}-byte selection hash and a short code.";
                }

                if (v > 0 && selected[v - 1].SelectionHash.CompareTo(vector.SelectionHash) >= 0)
                {
                    return $"The selected vectors of contest {contest.ContestId} on pre-encrypted ballot {ballot.Id} are not distinct and in increasing order of their selection hashes.";
                }
            }
        }

        return null;
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
