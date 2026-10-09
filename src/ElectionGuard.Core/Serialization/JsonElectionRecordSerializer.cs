using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization.Converters;
using ElectionGuard.Core.Tally;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace ElectionGuard.Core.Serialization;

/// <summary>
/// JSON for the election record items Core produces besides ballots (§3.7): the
/// <see cref="EncryptionRecord"/>, the <see cref="GuardianRecord"/>, the <see cref="EncryptedTally"/>,
/// the <see cref="DecryptedTally"/>, decrypted contest data (<see cref="DecryptedContestData"/>) and
/// decrypted challenged ballots (<see cref="DecryptedChallengedBallot"/>). Ballots have their own
/// serializers (<see cref="JsonEncryptedBallotSerializer"/>, <see cref="ProtobufEncryptedBallotSerializer"/>),
/// as do device chains (<see cref="JsonDeviceChainRecordSerializer"/>) and pre-encrypted ballots
/// (<see cref="JsonPreEncryptedBallotSerializer"/>). How the items are bundled into one record is
/// not decided here (S10b).
///
/// <para><b>Encoding.</b> camelCase property names in declaration order, written indented. An element
/// of Z_p is base64 of its 512-byte big-endian form, an element of Z_q of its 32-byte form, a hash
/// (H_P, H_B, H_E) of its 32 bytes, as on ballots; the manifest file is base64 of its exact bytes;
/// the baseline parameters as <see cref="CryptographicParametersJsonConverter"/> describes; a
/// guardian index, a count and an index as JSON numbers.</para>
///
/// <para><b>Decoding is strict.</b> No byte order mark, comment, trailing comma, unknown property,
/// property named twice, property name that is not valid text, missing required property, null
/// value or null list entry (<see cref="JsonException"/>); base64 only in its canonical form
/// (<see cref="StrictBase64"/>), every element of Z_p and Z_q exactly its width and below p or q,
/// every hash exactly 32 bytes, each parameter exactly its width
/// (<see cref="NonCanonicalEncodingException"/>), so the range halves of Verifications 2.A/2.B,
/// 10.x, 12.x and 13.x hold for anything read back. Hash claims are kept as read, never recomputed,
/// so Verifications 1.E, 1.F and 4.A still check them. An encryption record's manifest file must be
/// a manifest in the library's format (<see cref="ManifestSerializer"/>), since the record's
/// <see cref="EncryptionRecord.Manifest"/> is parsed from it (<see cref="InvalidManifestException"/>).</para>
///
/// <para>Each item is read whole into memory. They are small next to the ballots, which stream.</para>
/// </summary>
public class JsonElectionRecordSerializer
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = StrictJson.CreateOptions();
        options.WriteIndented = true;
        options.Converters.Add(new IntegerModPJsonConverter());
        options.Converters.Add(new IntegerModQJsonConverter());
        options.Converters.Add(new HashClaimJsonConverter<ParameterBaseHash>(ParameterBaseHash.FromCanonicalBytes));
        options.Converters.Add(new HashClaimJsonConverter<ElectionBaseHash>(ElectionBaseHash.FromCanonicalBytes));
        options.Converters.Add(new HashClaimJsonConverter<ExtendedBaseHash>(ExtendedBaseHash.FromCanonicalBytes));
        options.Converters.Add(new ManifestFileJsonConverter());
        options.Converters.Add(new GuardianIndexJsonConverter());
        options.Converters.Add(new CryptographicParametersJsonConverter());
        options.Converters.Add(new GuardianParametersJsonConverter());
        options.Converters.Add(new ElectionPublicKeysJsonConverter());

        // The record's parsed manifest is derived from its manifest file: leaving it out of the
        // contract (rather than ignoring it) means it is not written, and a document that carries a
        // "manifest" member is refused as an unknown member.
        options.TypeInfoResolver = new DefaultJsonTypeInfoResolver
        {
            Modifiers =
            {
                static info =>
                {
                    if (info.Type == typeof(EncryptionRecord) && info.Properties.FirstOrDefault(x => x.Name == "manifest") is { } derived)
                    {
                        info.Properties.Remove(derived);
                    }
                },
            },
        };
        return options;
    }

    // --- Encryption record -------------------------------------------------------------------------

    /// <summary>
    /// Writes the record: parameters, H_P, the manifest file, H_B, the guardians' public keys,
    /// commitments and proofs, K and K-hat, and H_E. The parsed manifest is not written; it is the
    /// manifest file's.
    /// </summary>
    public void Serialize(Stream destination, EncryptionRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        JsonSerializer.Serialize(destination, record, Options);
    }

    public EncryptionRecord DeserializeEncryptionRecord(Stream source)
    {
        var record = Read<EncryptionRecord>(source, "encryption record");
        RequireGuardians(record.Guardians);
        return record;
    }

    // --- Guardian record ---------------------------------------------------------------------------

    public void Serialize(Stream destination, GuardianRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        JsonSerializer.Serialize(destination, record, Options);
    }

    public GuardianRecord DeserializeGuardianRecord(Stream source)
    {
        var record = Read<GuardianRecord>(source, "guardian record");
        RequireGuardians(record.Guardians);
        return record;
    }

    // --- Encrypted tally ---------------------------------------------------------------------------

    private sealed class EncryptedTallyDocument
    {
        public required int BallotsCast { get; init; }
        public required Dictionary<string, EncryptedTallyContestDocument> Contests { get; init; }
    }

    private sealed class EncryptedTallyContestDocument
    {
        public required long CastWeight { get; init; }
        public required Dictionary<string, EncryptedTallyChoiceDocument> Choices { get; init; }
    }

    private sealed class EncryptedTallyChoiceDocument
    {
        public required IntegerModP A { get; init; }
        public required IntegerModP B { get; init; }
    }

    /// <summary>
    /// Writes the encrypted tally (§3.7 "the encrypted tally of each option"): per contest its cast
    /// weight (the sum of the weights of the cast ballots that list it; see
    /// <see cref="EncryptedTally.EncryptedAggregateContest.CastWeight"/>) and per option and
    /// supplemental field the aggregate (A, B), plus the number of ballots cast. The cast weight is
    /// not spec-defined; it is what restores each option's decryption bound when the tally is read
    /// back, and Verification 9 checks it.
    /// </summary>
    public void Serialize(Stream destination, EncryptedTally tally)
    {
        ArgumentNullException.ThrowIfNull(tally);
        JsonSerializer.Serialize(destination, new EncryptedTallyDocument
        {
            BallotsCast = tally.BallotsCast,
            Contests = tally.Contests.ToDictionary(
                x => x.Key,
                x => new EncryptedTallyContestDocument
                {
                    CastWeight = x.Value.CastWeight,
                    Choices = x.Value.Choices.ToDictionary(
                        c => c.Key,
                        c => new EncryptedTallyChoiceDocument { A = c.Value.A, B = c.Value.B }),
                }),
        }, Options);
    }

    /// <summary>
    /// Reads an encrypted tally over <paramref name="manifest"/> (the election's, normally
    /// <see cref="EncryptionRecord.Manifest"/>). The contests and options are the document's, so
    /// Verification 9 still reports one the manifest does not list, or one missing; each option's
    /// decryption bound (<see cref="EncryptedTally.EncryptedAggregateChoice.MaximumCount"/>) is its
    /// contest's published cast weight times the option's maximum under the manifest, so the tally
    /// can be decrypted as read. A negative weight or ballot count is refused, as is a weight above
    /// <c>ballotsCast</c> × <see cref="int.MaxValue"/> (a contest's cast weight is a sum of at most
    /// <c>ballotsCast</c> ballot weights, each an <see cref="int"/>); that is only a consistency
    /// check, since <c>ballotsCast</c> is published too.
    /// <para>The cast weights are claims until Verification 9
    /// (<see cref="Verify.Tally.BallotAggregationVerification"/>) has compared them with the cast
    /// ballots ("9.structure"). Run it before decrypting a tally read here
    /// (<see cref="TallyAdmin.Decrypt"/>): a forged weight widens the decryption search, up to the
    /// limit beyond which decryption refuses with <see cref="TallyDecryptionException"/>.</para>
    /// </summary>
    public EncryptedTally DeserializeEncryptedTally(Stream source, Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var document = Read<EncryptedTallyDocument>(source, "encrypted tally");
        if (document.BallotsCast < 0)
        {
            throw new JsonException($"The encrypted tally counts {document.BallotsCast} cast ballots; a count is not negative.");
        }

        foreach (var (contestId, contest) in document.Contests)
        {
            if (contest is null)
            {
                throw new JsonException($"Contest {contestId} of the encrypted tally is null.");
            }

            if (contest.CastWeight < 0)
            {
                throw new JsonException($"Contest {contestId} of the encrypted tally has cast weight {contest.CastWeight}; a weight is not negative.");
            }

            if (contest.CastWeight > (long)document.BallotsCast * int.MaxValue)
            {
                throw new JsonException($"Contest {contestId} of the encrypted tally has cast weight {contest.CastWeight}, more than {document.BallotsCast} cast ballots of weight at most {int.MaxValue} can give.");
            }

            foreach (var (choiceId, choice) in contest.Choices)
            {
                if (choice is null)
                {
                    throw new JsonException($"Option {choiceId} of contest {contestId} of the encrypted tally is null.");
                }
            }
        }

        return EncryptedTally.Restore(
            manifest,
            document.BallotsCast,
            document.Contests.Select(x => (x.Key, x.Value.CastWeight, x.Value.Choices.Select(c => (c.Key, c.Value.A, c.Value.B)))));
    }

    // --- Decrypted tally ---------------------------------------------------------------------------

    /// <summary>
    /// Writes the decrypted tally (§3.7 "full decryptions of each encrypted tally, plaintext
    /// representations of each tally, proofs of correct decryption"): per contest its index, per
    /// option its index, the count t, T and the proof (c, v).
    /// </summary>
    public void Serialize(Stream destination, DecryptedTally tally)
    {
        ArgumentNullException.ThrowIfNull(tally);
        JsonSerializer.Serialize(destination, tally, Options);
    }

    public DecryptedTally DeserializeDecryptedTally(Stream source)
    {
        var tally = Read<DecryptedTally>(source, "decrypted tally");
        foreach (var (contestId, contest) in tally.Contests)
        {
            if (contest is null)
            {
                throw new JsonException($"Contest {contestId} of the decrypted tally is null.");
            }

            foreach (var (choiceId, choice) in contest.Choices)
            {
                if (choice is null)
                {
                    throw new JsonException($"Option {choiceId} of contest {contestId} of the decrypted tally is null.");
                }
            }
        }

        return tally;
    }

    // --- Decrypted contest data --------------------------------------------------------------------

    /// <summary>
    /// Writes decrypted contest data fields (§3.6.6 p.51: β, the proof (c, v) and D, here with the
    /// ballot, contest and contest index they belong to), D as base64 of its 32·b_Λ bytes.
    /// </summary>
    public void Serialize(Stream destination, IReadOnlyList<DecryptedContestData> contestData)
    {
        ArgumentNullException.ThrowIfNull(contestData);
        JsonSerializer.Serialize(destination, contestData, Options);
    }

    public List<DecryptedContestData> DeserializeDecryptedContestData(Stream source)
    {
        var list = Read<List<DecryptedContestData>>(source, "decrypted contest data list");
        RequireNoNullEntry(list, "decrypted contest data list");
        return list;
    }

    // --- Decrypted challenged ballots --------------------------------------------------------------

    /// <summary>
    /// Writes decrypted challenged ballots (§3.6.7, §3.7): per contest the value and encryption
    /// nonce of every option and supplemental field, and the contest data nonce and D where the
    /// contest carries contest data.
    /// </summary>
    public void Serialize(Stream destination, IReadOnlyList<DecryptedChallengedBallot> ballots)
    {
        ArgumentNullException.ThrowIfNull(ballots);
        JsonSerializer.Serialize(destination, ballots, Options);
    }

    public List<DecryptedChallengedBallot> DeserializeDecryptedChallengedBallots(Stream source)
    {
        var list = Read<List<DecryptedChallengedBallot>>(source, "decrypted challenged ballot list");
        RequireNoNullEntry(list, "decrypted challenged ballot list");
        foreach (var ballot in list)
        {
            RequireNoNullEntry(ballot.Contests, $"contest list of challenged ballot {ballot.BallotId}");
            foreach (var contest in ballot.Contests)
            {
                RequireNoNullEntry(contest.Choices, $"option list of contest {contest.ContestId} of challenged ballot {ballot.BallotId}");
                RequireNoNullEntry(contest.SupplementalFields, $"supplemental field list of contest {contest.ContestId} of challenged ballot {ballot.BallotId}");
            }
        }

        return list;
    }

    // --- Helpers -----------------------------------------------------------------------------------

    private static T Read<T>(Stream source, string what) where T : class
    {
        ArgumentNullException.ThrowIfNull(source);
        byte[] bytes;
        using (var buffer = new MemoryStream())
        {
            source.CopyTo(buffer);
            bytes = buffer.ToArray();
        }

        StrictJson.RejectAmbiguity(bytes);
        return JsonSerializer.Deserialize<T>(bytes, Options)
            ?? throw new JsonException($"The {what} is the JSON value null.");
    }

    private static void RequireGuardians(List<GuardianPublicView> guardians)
    {
        RequireNoNullEntry(guardians, "guardian list");
    }

    private static void RequireNoNullEntry<T>(List<T> list, string what) where T : class
    {
        for (int i = 0; i < list.Count; i++)
        {
            if (list[i] is null)
            {
                throw new JsonException($"Entry {i + 1} of the {what} is null.");
            }
        }
    }
}
