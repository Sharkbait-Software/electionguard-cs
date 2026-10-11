using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Tally;
using System.Reflection;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-4 (design §9.2): every public property of every domain type the record carries is pinned to
/// the schema field that holds it, or to an explicit exclusion with its reason. This replaces the
/// "add a field to both the domain type and its DTO" hazard (CLAUDE.md, Serialization): a property
/// added to a recorded type fails here until its mapping, or its exclusion, is decided. And no
/// schema field can hold a secret: design §1, "No message in the schema has a field for any of
/// them".
/// </summary>
public class RecordCompletenessTests
{
    private const string Section = "(the device section's DeviceHeader)";
    private const string Computed = "(computed from other members; not stored)";
    private const string Never = "(never recorded: a nonce of a cast ballot's ciphertext, design §1)";

    /// <summary>Type -> member -> where the record keeps it (a schema field path, or a parenthesized reason).</summary>
    public static readonly Dictionary<Type, Dictionary<string, string>> Mapping = new()
    {
        [typeof(EncryptedBallot)] = new()
        {
            ["Id"] = "EncryptedBallot.ballot_ref", ["SelectionEncryptionIdentifier"] = "EncryptedBallot.id_b", ["SelectionEncryptionIdentifierHash"] = "EncryptedBallot.h_i",
            ["BallotStyleId"] = "EncryptedBallot.ballot_style", ["Contests"] = "EncryptedBallot.contests", ["ConfirmationCode"] = "EncryptedBallot.confirmation_code",
            ["ChainingField"] = "EncryptedBallot.chaining_field", ["EncryptedBallotNonce"] = "EncryptedBallot.encrypted_ballot_nonce", ["Weight"] = "EncryptedBallot.weight",
            ["DeviceId"] = Section, ["EncryptionTimestamp"] = "EncryptedBallot.encrypted_at", ["PreEncryptedContests"] = "PreEncryptedCastBallot.contests",
            ["IsPreEncrypted"] = "(the item type: pre_encrypted_cast_ballot)", ["Status"] = "EncryptedBallot.status",
        },
        [typeof(EncryptedContest)] = new()
        {
            ["Id"] = "EncryptedContest.index", ["Choices"] = "EncryptedContest.fields", ["SupplementalFields"] = "EncryptedContest.fields", ["Proofs"] = "EncryptedContest.limit_proof",
            ["UndervoteDifferenceProof"] = "EncryptedContest.undervote_difference_proof", ["NullVoteProof"] = "EncryptedContest.null_vote_proof",
            ["ContestData"] = "EncryptedContest.contest_data", ["ContestHash"] = "EncryptedContest.contest_hash",
        },
        [typeof(EncryptedSelection)] = new() { ["ChoiceId"] = "(its position in EncryptedContest.fields, manifest order)", ["Alpha"] = "EncryptedField.alpha", ["Beta"] = "EncryptedField.beta", ["Proofs"] = "EncryptedField.range_proof", ["EncryptionNonce"] = Never },
        [typeof(EncryptedSupplementalField)] = new() { ["FieldId"] = "(its position in EncryptedContest.fields, manifest order)", ["Alpha"] = "EncryptedField.alpha", ["Beta"] = "EncryptedField.beta", ["Proofs"] = "EncryptedField.range_proof", ["EncryptionNonce"] = Never },
        [typeof(ChallengeResponsePair)] = new() { ["Challenge"] = "(c of a packed c || v pair)", ["Response"] = "(v of a packed c || v pair)" },
        [typeof(EncryptedContestData)] = new() { ["C0"] = "HashedCiphertext.c0", ["C1"] = "HashedCiphertext.c1", ["Challenge"] = "HashedCiphertext.c2", ["Response"] = "HashedCiphertext.c2" },
        [typeof(EncryptedBallotNonce)] = new() { ["C0"] = "HashedCiphertext.c0", ["C1"] = "HashedCiphertext.c1", ["Challenge"] = "HashedCiphertext.c2", ["Response"] = "HashedCiphertext.c2" },
        [typeof(PreEncryptedCastContest)] = new() { ["ContestId"] = "EncryptedContest.index", ["SelectionHashes"] = "PreEncryptedCastContest.selection_hashes", ["SelectedVectors"] = "PreEncryptedCastContest.selected" },
        [typeof(PreEncryptedCastSelection)] = new() { ["Vector"] = "SelectedVector.vector", ["SelectionHash"] = "SelectedVector.psi", ["ShortCode"] = "SelectedVector.short_code" },
        [typeof(PreEncryptedBallot)] = new()
        {
            ["Id"] = "PreEncryptedUncastBallot.ballot_ref", ["BallotStyleId"] = "PreEncryptedUncastBallot.ballot_style", ["SelectionEncryptionIdentifier"] = "PreEncryptedUncastBallot.id_b",
            ["SelectionEncryptionIdentifierHash"] = "PreEncryptedUncastBallot.h_i", ["EncryptedBallotNonce"] = "PreEncryptedUncastBallot.encrypted_ballot_nonce",
            ["Contests"] = "PreEncryptedUncastBallot.contests", ["ChainingField"] = "PreEncryptedUncastBallot.chaining_field", ["ConfirmationCode"] = "PreEncryptedUncastBallot.confirmation_code", ["DeviceId"] = Section,
        },
        [typeof(PreEncryptedContest)] = new() { ["ContestId"] = "UncastContest.label", ["ContestIndex"] = "UncastContest.index", ["Selections"] = "UncastContest.selections", ["ContestHash"] = "UncastContest.contest_hash", ["SortedSelectionHashes"] = Computed },
        [typeof(PreEncryptedSelection)] = new() { ["SelectionIndex"] = "UncastSelection.selection_index", ["ChoiceId"] = "UncastSelection.option_label", ["IsNullVote"] = Computed, ["Vector"] = "UncastSelection.vector", ["SelectionHash"] = "UncastSelection.psi", ["ShortCode"] = "UncastSelection.short_code" },
        [typeof(PreEncryptedUncastBallot)] = new() { ["Ballot"] = "(the printed item)", ["BallotNonce"] = "UncastNonceRelease.ballot_nonce", ["Contests"] = "UncastNonceRelease.contests" },
        [typeof(PreEncryptedReleasedContest)] = new() { ["ContestId"] = "UncastContestNonces.index", ["Selections"] = "UncastContestNonces.nonces" },
        [typeof(PreEncryptedReleasedSelection)] = new() { ["SelectionIndex"] = "(aligned with the printed selections)", ["Nonces"] = "UncastContestNonces.nonces" },
        [typeof(DeviceChainRecord)] = new()
        {
            ["DeviceId"] = "DeviceHeader.device_id", ["DeviceInformationHash"] = "DeviceHeader.h_di", ["BallotKind"] = "DeviceHeader.kind", ["ChainingMode"] = "DeviceHeader.chaining_mode",
            ["ConfirmationCodes"] = "(the section's ballot items, in order)", ["InitialHash"] = "DeviceHeader.initial_hash", ["ClosingChainingField"] = "DeviceClose.closing_chaining_field", ["ClosingHash"] = "DeviceClose.closing_hash",
        },
        [typeof(EncryptionRecord)] = new()
        {
            ["CryptographicParameters"] = "Parameters", ["GuardianParameters"] = "Parameters.n, Parameters.k", ["ParameterBaseHash"] = "Parameters.h_p", ["ManifestFile"] = "ManifestFile.content",
            ["ElectionBaseHash"] = "ManifestFile.h_b", ["Guardians"] = "GuardianPublicKey", ["ElectionPublicKeys"] = "ElectionKeys.k, ElectionKeys.k_hat", ["ExtendedBaseHash"] = "ElectionKeys.h_e",
            ["Manifest"] = "(parsed from ManifestFile.content, S10a)",
        },
        [typeof(GuardianRecord)] = new()
        {
            ["CryptographicParameters"] = "Parameters", ["GuardianParameters"] = "Parameters.n, Parameters.k", ["ParameterBaseHash"] = "Parameters.h_p", ["ManifestFile"] = "ManifestFile.content",
            ["ElectionBaseHash"] = "ManifestFile.h_b", ["Guardians"] = "GuardianPublicKey", ["ElectionPublicKeys"] = "ElectionKeys.k, ElectionKeys.k_hat",
        },
        [typeof(CryptographicParameters)] = new() { ["Version"] = "Parameters.version", ["P"] = "Parameters.p", ["Q"] = "Parameters.q", ["R"] = "Parameters.r", ["G"] = "Parameters.g" },
        [typeof(GuardianPublicView)] = new()
        {
            ["Index"] = "GuardianPublicKey.index", ["VoteEncryptionCommitments"] = "GuardianPublicKey.vote_commitments", ["OtherBallotDataEncryptionCommitments"] = "GuardianPublicKey.data_commitments",
            ["CommunicationPublicKey"] = "GuardianPublicKey.kappa", ["VoteEncryptionProof"] = "GuardianPublicKey.vote_proof", ["OtherDataEncryptionProof"] = "GuardianPublicKey.data_proof",
        },
        [typeof(EncryptedTally)] = new() { ["Contests"] = "EncryptedTallyContest", ["Manifest"] = "(the setup's manifest)", ["BallotsCast"] = "EncryptedTallyHeader.cast_ballot_count", ["TotalCastWeight"] = "EncryptedTallyHeader.total_cast_weight" },
        [typeof(EncryptedTally.EncryptedAggregateContest)] = new() { ["ContestId"] = "EncryptedTallyContest.index", ["Choices"] = "EncryptedTallyContest.fields", ["CastWeight"] = "EncryptedTallyContest.cast_weight" },
        [typeof(EncryptedTally.EncryptedAggregateChoice)] = new() { ["ChoiceId"] = "(its position in EncryptedTallyContest.fields)", ["MaximumCount"] = Computed, ["A"] = "EncryptedTallyContest.fields", ["B"] = "EncryptedTallyContest.fields" },
        [typeof(DecryptedTally)] = new() { ["Contests"] = "DecryptedTallyContest" },
        [typeof(DecryptedTally.DecryptedContest)] = new() { ["ContestIndex"] = "DecryptedTallyContest.index", ["Choices"] = "DecryptedTallyContest.fields" },
        [typeof(DecryptedTally.DecryptedChoice)] = new() { ["ChoiceIndex"] = "DecryptedTallyField.index", ["VoteCount"] = "DecryptedTallyField.tally", ["T"] = "DecryptedTallyField.encoded_tally", ["Challenge"] = "DecryptedTallyField.proof", ["Response"] = "DecryptedTallyField.proof" },
        [typeof(DecryptedContestData)] = new()
        {
            ["BallotId"] = "ContestDataDecryption.ballot", ["ContestId"] = "ContestDataDecryption.contest_index", ["ContestIndex"] = "ContestDataDecryption.contest_index", ["Beta"] = "ContestDataDecryption.beta",
            ["Challenge"] = "ContestDataDecryption.proof", ["Response"] = "ContestDataDecryption.proof", ["Data"] = "ContestDataDecryption.data",
        },
        [typeof(DecryptedChallengedBallot)] = new() { ["BallotId"] = "ChallengedBallotDecryption.ballot", ["Contests"] = "ChallengedBallotDecryption.contests" },
        [typeof(DecryptedChallengedContest)] = new() { ["Index"] = "DecryptedContest.index", ["ContestId"] = "DecryptedContest.label", ["Choices"] = "DecryptedContest.fields", ["SupplementalFields"] = "DecryptedContest.fields", ["ContestData"] = "DecryptedContest.contest_data" },
        [typeof(DecryptedChallengedField)] = new() { ["Index"] = "DecryptedField.index", ["Id"] = "DecryptedField.label", ["Value"] = "DecryptedField.value", ["EncryptionNonce"] = "DecryptedField.nonce" },
        [typeof(DecryptedChallengedContestData)] = new() { ["EncryptionNonce"] = "ReleasedContestData.nonce", ["Data"] = "ReleasedContestData.data" },
        [typeof(DeviceHeader)] = new() { ["Kind"] = "DeviceHeader.kind", ["DeviceId"] = "DeviceHeader.device_id", ["DeviceInformationHash"] = "DeviceHeader.h_di", ["ChainingMode"] = "DeviceHeader.chaining_mode", ["InitialHash"] = "DeviceHeader.initial_hash", ["Key"] = Computed },
        [typeof(DeviceClose)] = new() { ["BallotCount"] = "DeviceClose.ballot_count", ["ClosingChainingField"] = "DeviceClose.closing_chaining_field", ["ClosingHash"] = "DeviceClose.closing_hash", ["ClosedAt"] = "DeviceClose.closed_at" },
        [typeof(ContestDataRequest)] = new() { ["Ballot"] = "ContestDataRequest.ballot", ["IdentifierHash"] = "ContestDataRequest.h_i", ["ContestIndex"] = "ContestDataRequest.contest_index" },
        [typeof(EncryptedTallyHeader)] = new() { ["CastBallotCount"] = "EncryptedTallyHeader.cast_ballot_count", ["TotalCastWeight"] = "EncryptedTallyHeader.total_cast_weight" },
        [typeof(RecordSetup)] = new()
        {
            ["Format"] = "RecordHeader", ["Parameters"] = "Parameters", ["GuardianParameters"] = "Parameters.n, Parameters.k", ["ParameterBaseHash"] = "Parameters.h_p", ["ManifestFile"] = "ManifestFile.content",
            ["ManifestMediaType"] = "ManifestFile.media_type", ["ElectionBaseHash"] = "ManifestFile.h_b", ["Guardians"] = "GuardianPublicKey", ["Keys"] = "ElectionKeys.k, ElectionKeys.k_hat", ["ExtendedBaseHash"] = "ElectionKeys.h_e",
        },
        [typeof(BallotLocator)] = new() { ["Device"] = "BallotLocator.kind, BallotLocator.h_di", ["Position"] = "BallotLocator.position" },
        [typeof(EncryptedValue)] = new() { ["Alpha"] = "(α of a packed vector: SelectedVector.vector, UncastSelection.vector)", ["Beta"] = "(β of a packed vector)", ["EncryptionNonce"] = "(released only through UncastContestNonces.nonces; never on the vector, design §1)" },
        [typeof(SchnorrProof)] = new() { ["Challenge"] = "GuardianPublicKey.vote_proof, GuardianPublicKey.data_proof", ["Responses"] = "GuardianPublicKey.vote_proof, GuardianPublicKey.data_proof" },
        [typeof(GuardianParameters)] = new() { ["N"] = "Parameters.n", ["K"] = "Parameters.k" },
        [typeof(ManifestFile)] = new() { ["Bytes"] = "ManifestFile.content" },
        [typeof(DeviceKey)] = new() { ["Kind"] = "DeviceHeader.kind", ["DeviceInformationHash"] = "DeviceHeader.h_di", ["KindByte"] = Computed },
        [typeof(BallotNonce)] = new(),
    };

    private static IEnumerable<string> PublicMembers(Type type) =>
        type.GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(x => x.GetIndexParameters().Length == 0).Select(x => x.Name)
            .Concat(type.GetFields(BindingFlags.Public | BindingFlags.Instance).Select(x => x.Name));

    [Fact]
    public void EveryPublicMemberOfEveryRecordedType_IsMappedOrExcluded()
    {
        Assert.Equal(43, Mapping.Count);
        var unmapped = new List<string>();
        foreach (var (type, members) in Mapping)
        {
            foreach (var member in PublicMembers(type))
            {
                if (!members.ContainsKey(member))
                {
                    unmapped.Add($"{type.Name}.{member}");
                }
            }

            foreach (var member in members.Keys.Except(PublicMembers(type)))
            {
                unmapped.Add($"{type.Name}.{member} is mapped but is no member");
            }
        }

        Assert.True(unmapped.Count == 0, "Decide where the record keeps each (a schema field, or an exclusion with its reason): " + string.Join(", ", unmapped));
    }

    /// <summary>Every schema field a mapping names exists in the schema.</summary>
    [Fact]
    public void EveryNamedSchemaField_Exists()
    {
        var schema = EgrfSchema.Instance;
        foreach (var target in Mapping.Values.SelectMany(x => x.Values).Where(x => !x.StartsWith('(')))
        {
            foreach (var path in target.Split(", "))
            {
                var parts = path.Split('.');
                var message = schema.Message($"electionguard.egrf.v2.{parts[0]}");
                if (parts.Length == 2)
                {
                    Assert.True(message.Fields.Values.Any(x => x.Name == parts[1]), path);
                }
            }
        }
    }

    /// <summary>
    /// Design §1: no schema field can carry guardian-private data or a cast ballot's nonce. The only
    /// fields named for nonces or keys are the ciphertext of ξ_B, the released openings of
    /// challenged and uncast ballots (final phase), the public keys, and signature metadata.
    /// </summary>
    [Fact]
    public void NoSchemaField_CanHoldASecret()
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "EncryptedBallot.encrypted_ballot_nonce", "PreEncryptedCastBallot.encrypted_ballot_nonce", "PreEncryptedUncastBallot.encrypted_ballot_nonce",
            "PreEncryptedCompactUncastBallot.encrypted_ballot_nonce", "DecryptedField.nonce", "ReleasedContestData.nonce", "UncastContestNonces.nonces",
            "UncastNonceRelease.ballot_nonce", "SignedStatement.key_id", "SignedStatement.signer_key", "SegmentHeader.key", "TocEntry.key",
            "ChainCloseStatement.device_key", "SectionSealStatement.device_key", "PrefixCheckpointStatement.device_key",
        };
        var named = EgrfSchema.Instance.Messages
            .Where(x => x.FullName.StartsWith("electionguard.", StringComparison.Ordinal) && !x.IsRecordItem) // RecordItem's members name item types, not values
            .SelectMany(m => m.Fields.Values.Select(f => $"{m.Name}.{f.Name}"))
            .Where(x => x.Split('.')[1] is var field && (field.Contains("nonce", StringComparison.Ordinal) || field.Contains("secret", StringComparison.Ordinal)
                || field.Contains("share", StringComparison.Ordinal) || field.Contains("key", StringComparison.Ordinal) || field.Contains("private", StringComparison.Ordinal)))
            .ToHashSet();

        Assert.Equal(allowed.Order(), named.Order());

        // The released openings sit only in final-phase items (and the ciphertext C_ξB, never its plaintext, on ballots).
        foreach (var opening in new[] { "DecryptedField", "ReleasedContestData", "UncastContestNonces", "UncastNonceRelease" })
        {
            Assert.DoesNotContain(EgrfSchema.Instance.Messages, m => m.Name is "EncryptedBallot" or "PreEncryptedCastBallot" or "PreEncryptedUncastBallot" or "PreEncryptedCompactUncastBallot"
                && m.Fields.Values.Any(f => f.TypeName.EndsWith(opening, StringComparison.Ordinal)));
        }
    }
}
