using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization.Converters;
using ProtoBuf;
using System.Text.Json;

namespace ElectionGuard.Core.Serialization;

public interface IEncryptedBallotSerializer
{
    void Serialize(Stream destination, EncryptedBallot encryptedBallot);
    EncryptedBallot? Deserialize(Stream source);
}


/// <summary>
/// JSON for encrypted ballots: camelCase properties, written indented; group elements, Z_q values
/// and hashes base64 of their fixed-width big-endian bytes, each decoded strictly (exact width, below
/// p or q; <see cref="NonCanonicalEncodingException"/> otherwise); the optional encryption timestamp
/// as <c>yyyy-MM-ddTHH:mm:ss.fffZ</c>. A decoded ballot whose id, ballot style, H_I, or a contest's,
/// option's or field's label is null is refused (<see cref="NonCanonicalEncodingException"/>); a
/// null list or list entry decodes and is reported by <see cref="Verify.BallotStructure"/>.
/// </summary>
public class JsonEncryptedBallotSerializer : IEncryptedBallotSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters =
        {
            new IntegerModQJsonConverter(),
            new IntegerModPJsonConverter(),
            new ConfirmationCodeJsonConverter(),
            new ContestHashJsonConverter(),
            new SelectionEncryptionIdentifierJsonConverter(),
            new SelectionEncryptionIdentifierHashJsonConverter(),
            new VotingDeviceInformationHashJsonConverter(),
            new ChainingFieldJsonConverter(),
            new SelectionHashJsonConverter(),
            new ShortCodeJsonConverter(),
            new EncryptionTimestampJsonConverter(),
        }
    };

    public void Serialize(Stream destination, EncryptedBallot encryptedBallot)
    {
        JsonSerializer.Serialize(destination, encryptedBallot, Options);
    }

    public EncryptedBallot? Deserialize(Stream source)
    {
        var ballot = JsonSerializer.Deserialize<EncryptedBallot>(source, Options);
        if (ballot is not null)
        {
            EncryptedBallotShape.Require(ballot);
        }

        return ballot;
    }
}

public class ProtobufEncryptedBallotSerializer : IEncryptedBallotSerializer
{
    public void Serialize(Stream destination, EncryptedBallot encryptedBallot)
    {
        var protobufEncryptedBallot = new ProtobufEncryptedBallot
        {
            Id = encryptedBallot.Id,
            SelectionEncryptionIdentifier = encryptedBallot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = encryptedBallot.SelectionEncryptionIdentifierHash,
            BallotStyleId = encryptedBallot.BallotStyleId,
            DeviceId = encryptedBallot.DeviceId,
            Contests = encryptedBallot.Contests.Select(c => new ProtobufEncryptedContest
            {
                Id = c.Id,
                Choices = c.Choices.Select(s => new ProtobufEncryptedSelection
                {
                    ChoiceId = s.ChoiceId,
                    Alpha = s.Alpha,
                    Beta = s.Beta,
                    Proofs = s.Proofs.Select(p => new ProtobufChallengeResponsePair
                    {
                        Challenge = p.Challenge.ToByteArray(),
                        Response = p.Response.ToByteArray()
                    }).ToArray()
                }).ToList(),
                Proofs = c.Proofs.Select(p => new ProtobufChallengeResponsePair
                {
                    Challenge = p.Challenge.ToByteArray(),
                    Response = p.Response.ToByteArray()
                }).ToArray(),
                SupplementalFields = c.SupplementalFields.Select(f => new ProtobufEncryptedSupplementalField
                {
                    FieldId = f.FieldId,
                    Alpha = f.Alpha.ToByteArray(),
                    Beta = f.Beta.ToByteArray(),
                    Proofs = f.Proofs.Select(p => new ProtobufChallengeResponsePair
                    {
                        Challenge = p.Challenge.ToByteArray(),
                        Response = p.Response.ToByteArray()
                    }).ToArray()
                }).ToList(),
                UndervoteDifferenceProof = c.UndervoteDifferenceProof?.Select(p => new ProtobufChallengeResponsePair
                {
                    Challenge = p.Challenge.ToByteArray(),
                    Response = p.Response.ToByteArray()
                }).ToArray(),
                NullVoteProof = c.NullVoteProof?.Select(p => new ProtobufChallengeResponsePair
                {
                    Challenge = p.Challenge.ToByteArray(),
                    Response = p.Response.ToByteArray()
                }).ToArray(),
                ContestData = c.ContestData != null ? new ProtobufEncryptedData
                {
                    C0 = c.ContestData.C0.ToByteArray(),
                    C1 = c.ContestData.C1,
                    Challenge = c.ContestData.Challenge,
                    Response = c.ContestData.Response
                } : null,
                ContestHash = c.ContestHash,
            }).ToList(),
            ConfirmationCode = encryptedBallot.ConfirmationCode,
            ChainingField = encryptedBallot.ChainingField,
            Weight = encryptedBallot.Weight,
            Status = encryptedBallot.Status,
            EncryptedBallotNonce = new ProtobufEncryptedData
            {
                C0 = encryptedBallot.EncryptedBallotNonce.C0.ToByteArray(),
                C1 = encryptedBallot.EncryptedBallotNonce.C1,
                Challenge = encryptedBallot.EncryptedBallotNonce.Challenge,
                Response = encryptedBallot.EncryptedBallotNonce.Response,
            },
            // Only (α, β), short codes and hashes: a combined or derived nonce is never written.
            PreEncryptedContests = encryptedBallot.PreEncryptedContests?.Select(c => new ProtobufPreEncryptedCastContest
            {
                ContestId = c.ContestId,
                SelectionHashes = c.SelectionHashes.Select(h => (byte[])h).ToList(),
                SelectedVectors = c.SelectedVectors.Select(v => new ProtobufPreEncryptedCastSelection
                {
                    Vector = v.Vector.Select(e => new ProtobufCiphertext { Alpha = e.Alpha.ToByteArray(), Beta = e.Beta.ToByteArray() }).ToList(),
                    SelectionHash = v.SelectionHash,
                    ShortCode = v.ShortCode.Value,
                }).ToList(),
            }).ToList(),
            IsPreEncrypted = encryptedBallot.IsPreEncrypted,
            EncryptionTimestamp = encryptedBallot.EncryptionTimestamp?.ToUnixTimeMilliseconds(),
        };

        Serializer.Serialize(destination, protobufEncryptedBallot);
    }

    public EncryptedBallot? Deserialize(Stream source)
    {
        var protobufBallot = Serializer.Deserialize<ProtobufEncryptedBallot>(source);

        // Every group element, Z_q value and id_B is decoded strictly: a non-canonical encoding
        // throws NonCanonicalEncodingException rather than being reduced into range.

        var encryptedBallot = new EncryptedBallot
        {
            Id = protobufBallot.Id,
            SelectionEncryptionIdentifier = SelectionEncryptionIdentifier.FromCanonicalBytes(protobufBallot.SelectionEncryptionIdentifier),
            SelectionEncryptionIdentifierHash = SelectionEncryptionIdentifierHash.FromCanonicalBytes(protobufBallot.SelectionEncryptionIdentifierHash),
            BallotStyleId = protobufBallot.BallotStyleId,
            DeviceId = protobufBallot.DeviceId,
            // A repeated field with no entries is not on the wire, so a missing list reads as
            // empty; BallotStructure then reports the contests or options the ballot lacks.
            Contests = (protobufBallot.Contests ?? []).Select(c => new EncryptedContest
            {
                Id = c.Id,
                Choices = (c.Choices ?? []).Select(s => new EncryptedSelection
                {
                    ChoiceId = s.ChoiceId,
                    Alpha = IntegerModP.FromCanonicalBytes(s.Alpha),
                    Beta = IntegerModP.FromCanonicalBytes(s.Beta),
                    Proofs = (s.Proofs ?? []).Select(p => new ChallengeResponsePair
                    {
                        Challenge = IntegerModQ.FromCanonicalBytes(p.Challenge),
                        Response = IntegerModQ.FromCanonicalBytes(p.Response)
                    }).ToArray()
                }).ToList(),
                Proofs = (c.Proofs ?? []).Select(p => new ChallengeResponsePair
                {
                    Challenge = IntegerModQ.FromCanonicalBytes(p.Challenge),
                    Response = IntegerModQ.FromCanonicalBytes(p.Response)
                }).ToArray(),
                // A contest whose document carries no supplemental fields decodes with none; protobuf
                // writes nothing for an empty list, and BallotStructure rejects a contest that lacks
                // a field its manifest declares.
                SupplementalFields = (c.SupplementalFields ?? []).Select(f => new EncryptedSupplementalField
                {
                    FieldId = f.FieldId,
                    Alpha = IntegerModP.FromCanonicalBytes(f.Alpha),
                    Beta = IntegerModP.FromCanonicalBytes(f.Beta),
                    Proofs = (f.Proofs ?? []).Select(p => new ChallengeResponsePair
                    {
                        Challenge = IntegerModQ.FromCanonicalBytes(p.Challenge),
                        Response = IntegerModQ.FromCanonicalBytes(p.Response)
                    }).ToArray()
                }).ToList(),
                // Protobuf cannot tell an empty repeated field from an absent one, and the encryptor
                // never writes an empty proof, so either decodes as no proof (here and for the
                // null-vote proof below).
                UndervoteDifferenceProof = c.UndervoteDifferenceProof is { Length: > 0 } relationProof
                    ? relationProof.Select(p => new ChallengeResponsePair
                    {
                        Challenge = IntegerModQ.FromCanonicalBytes(p.Challenge),
                        Response = IntegerModQ.FromCanonicalBytes(p.Response)
                    }).ToArray()
                    : null,
                NullVoteProof = c.NullVoteProof is { Length: > 0 } nullVoteProof
                    ? nullVoteProof.Select(p => new ChallengeResponsePair
                    {
                        Challenge = IntegerModQ.FromCanonicalBytes(p.Challenge),
                        Response = IntegerModQ.FromCanonicalBytes(p.Response)
                    }).ToArray()
                    : null,
                ContestData = c.ContestData != null ? new EncryptedContestData
                {
                    C0 = IntegerModP.FromCanonicalBytes(c.ContestData.C0),
                    C1 = ContestDataC1(c.ContestData.C1),
                    Challenge = IntegerModQ.FromCanonicalBytes(c.ContestData.Challenge),
                    Response = IntegerModQ.FromCanonicalBytes(c.ContestData.Response)
                } : null,
                ContestHash = ContestHash.FromCanonicalBytes(c.ContestHash),
            }).ToList(),
            ConfirmationCode = ConfirmationCode.FromCanonicalBytes(protobufBallot.ConfirmationCode),
            ChainingField = ChainingField.FromCanonicalBytes(protobufBallot.ChainingField),
            EncryptedBallotNonce = ReadBallotNonce(protobufBallot.EncryptedBallotNonce),
            Weight = protobufBallot.Weight,
            Status = protobufBallot.Status,
            PreEncryptedContests = ReadPreEncryptedContests(protobufBallot),
            EncryptionTimestamp = ReadEncryptionTimestamp(protobufBallot.EncryptionTimestamp),
        };

        EncryptedBallotShape.Require(encryptedBallot);
        return encryptedBallot;
    }

    /// <summary>
    /// The optional encryption timestamp (field 14, Unix milliseconds, UTC). Absent reads as none;
    /// a value outside the years 0001-9999 is refused.
    /// </summary>
    private static DateTimeOffset? ReadEncryptionTimestamp(long? unixMilliseconds)
    {
        if (unixMilliseconds is not { } milliseconds)
        {
            return null;
        }

        if (milliseconds < MinimumUnixMilliseconds || milliseconds > MaximumUnixMilliseconds)
        {
            throw new NonCanonicalEncodingException($"An encryption timestamp of {milliseconds} Unix milliseconds is outside the years 0001-9999.");
        }

        return DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
    }

    private static readonly long MinimumUnixMilliseconds = DateTimeOffset.MinValue.ToUnixTimeMilliseconds();
    private static readonly long MaximumUnixMilliseconds = DateTimeOffset.MaxValue.ToUnixTimeMilliseconds();

    /// <summary>
    /// A cast pre-encrypted ballot's pre-encryption data (field 12, flagged by field 13, since
    /// protobuf writes nothing for an empty list): each group element canonical, each selection
    /// hash exactly 32 bytes, each short code present. Null for a regular ballot.
    /// </summary>
    private static List<PreEncryption.PreEncryptedCastContest>? ReadPreEncryptedContests(ProtobufEncryptedBallot ballot)
    {
        if (!ballot.IsPreEncrypted)
        {
            if (ballot.PreEncryptedContests is { Count: > 0 })
            {
                throw new NonCanonicalEncodingException("The ballot carries pre-encryption data but is not flagged as a pre-encrypted ballot (field 13).");
            }

            return null;
        }

        return (ballot.PreEncryptedContests ?? []).Select(c => new PreEncryption.PreEncryptedCastContest
        {
            ContestId = c.ContestId,
            SelectionHashes = (c.SelectionHashes ?? []).Select(SelectionHash.FromCanonicalBytes).ToList(),
            SelectedVectors = (c.SelectedVectors ?? []).Select(v => new PreEncryption.PreEncryptedCastSelection
            {
                Vector = (v.Vector ?? []).Select(e => new EncryptedValue
                {
                    Alpha = IntegerModP.FromCanonicalBytes(e.Alpha),
                    Beta = IntegerModP.FromCanonicalBytes(e.Beta),
                }).ToList(),
                SelectionHash = SelectionHash.FromCanonicalBytes(v.SelectionHash),
                ShortCode = new PreEncryption.ShortCode(v.ShortCode ?? throw new NonCanonicalEncodingException("A selected pre-encryption vector has no short code.")),
            }).ToList(),
        }).ToList();
    }

    /// <summary>
    /// The encrypted ballot nonce C_ξB (§3.3.4), which every ballot carries: C_ξB,0 a canonical
    /// element below p, C_ξB,1 exactly 32 bytes (eq. 37), c_B and v_B canonical in Z_q. Whether C_ξB,0
    /// is in Z_p^r is checked where it is used, before any guardian exponentiates with it.
    /// </summary>
    private static EncryptedBallotNonce ReadBallotNonce(ProtobufEncryptedData? nonce)
    {
        if (nonce is null)
        {
            throw new NonCanonicalEncodingException("The ballot has no encrypted ballot nonce C_ξB; every ballot carries one (§3.3.4).");
        }

        if (nonce.C1 is not { Length: BallotNonceEncryption.NonceBytes })
        {
            throw new NonCanonicalEncodingException($"C_ξB,1 of the encrypted ballot nonce is {BallotNonceEncryption.NonceBytes} bytes (eq. 37); got {nonce.C1?.Length ?? 0}.");
        }

        return new EncryptedBallotNonce
        {
            C0 = IntegerModP.FromCanonicalBytes(nonce.C0),
            C1 = nonce.C1,
            Challenge = IntegerModQ.FromCanonicalBytes(nonce.Challenge),
            Response = IntegerModQ.FromCanonicalBytes(nonce.Response),
        };
    }

    /// <summary>
    /// C_1 of a contest data field: a whole, nonzero number of 32-byte blocks (§3.3.10 eq. 68).
    /// Exactly 32·b_Λ depends on the manifest, which the decoder does not see;
    /// <see cref="Verify.BallotStructure"/> checks that.
    /// </summary>
    private static byte[] ContestDataC1(byte[]? c1)
    {
        if (c1 is null || c1.Length == 0 || c1.Length % ContestDataEncryption.BlockBytes != 0)
        {
            throw new NonCanonicalEncodingException($"C_1 of a contest data field is a nonzero whole number of {ContestDataEncryption.BlockBytes}-byte blocks; got {c1?.Length ?? 0} bytes.");
        }

        return c1;
    }

    [ProtoContract]
    public class ProtobufEncryptedBallot
    {
        [ProtoMember(1)]
        public required string Id { get; init; }
        [ProtoMember(2)]
        public required byte[] SelectionEncryptionIdentifier { get; init; }
        [ProtoMember(3)]
        public required byte[] SelectionEncryptionIdentifierHash { get; init; }
        [ProtoMember(4)]
        public required string BallotStyleId { get; init; }
        [ProtoMember(5)]
        public required string DeviceId { get; init; }
        [ProtoMember(6)]
        public required List<ProtobufEncryptedContest> Contests { get; init; }
        [ProtoMember(7)]
        public required byte[] ConfirmationCode { get; init; }
        /// <summary>
        /// Decoded as given. A ballot that leaves it off the wire reads as 0, which tallying and
        /// Verification 9 reject ("9.structure"): eq. (80) weights are positive.
        /// </summary>
        [ProtoMember(8)]
        public required int Weight { get; init; }

        /// <summary>
        /// The recorded <see cref="BallotStatus"/> (§3.7): cast, challenged or spoiled. Not
        /// required: a ballot serialized before its status was recorded has none, and 0
        /// (<see cref="BallotStatus.Unrecorded"/>) is then left off the wire; such a ballot cannot be
        /// tallied ("9.structure").
        /// </summary>
        [ProtoMember(9)]
        public BallotStatus Status { get; init; }

        /// <summary>
        /// <see cref="EncryptedBallot.EncryptedBallotNonce"/> (§3.3.4). Not marked required, so that a
        /// document without it decodes far enough to be refused with a
        /// <see cref="NonCanonicalEncodingException"/>.
        /// </summary>
        [ProtoMember(10)]
        public ProtobufEncryptedData? EncryptedBallotNonce { get; init; }

        /// <summary>
        /// <see cref="EncryptedBallot.ChainingField"/> (§3.4.4), the 36-byte B_C. Not marked required,
        /// so that a document without it decodes far enough to be refused with a
        /// <see cref="NonCanonicalEncodingException"/>.
        /// </summary>
        [ProtoMember(11)]
        public byte[]? ChainingField { get; init; }

        /// <summary>
        /// <see cref="EncryptedBallot.PreEncryptedContests"/> of a cast pre-encrypted ballot (§4.4);
        /// absent on a regular ballot, which therefore encodes as before.
        /// </summary>
        [ProtoMember(12)]
        public List<ProtobufPreEncryptedCastContest>? PreEncryptedContests { get; init; }

        /// <summary>
        /// Whether the ballot is a cast pre-encrypted ballot (<see cref="EncryptedBallot.IsPreEncrypted"/>),
        /// so that a pre-encrypted ballot with no contests is not read as a regular one. False, and
        /// so not written, on a regular ballot.
        /// </summary>
        [ProtoMember(13)]
        public bool IsPreEncrypted { get; init; }

        /// <summary>
        /// <see cref="EncryptedBallot.EncryptionTimestamp"/> (§3.7), Unix milliseconds in UTC. Optional:
        /// null, and so not written, when the ballot records none.
        /// </summary>
        [ProtoMember(14)]
        public long? EncryptionTimestamp { get; init; }
    }

    /// <summary><see cref="PreEncryption.PreEncryptedCastContest"/>.</summary>
    [ProtoContract]
    public class ProtobufPreEncryptedCastContest
    {
        [ProtoMember(1)]
        public required string ContestId { get; init; }
        [ProtoMember(2)]
        public List<byte[]>? SelectionHashes { get; init; }
        [ProtoMember(3)]
        public List<ProtobufPreEncryptedCastSelection>? SelectedVectors { get; init; }
    }

    /// <summary><see cref="PreEncryption.PreEncryptedCastSelection"/>: (α, β) per position, ψ and ω.</summary>
    [ProtoContract]
    public class ProtobufPreEncryptedCastSelection
    {
        [ProtoMember(1)]
        public List<ProtobufCiphertext>? Vector { get; init; }
        [ProtoMember(2)]
        public byte[]? SelectionHash { get; init; }
        [ProtoMember(3)]
        public string? ShortCode { get; init; }
    }

    /// <summary>An ElGamal ciphertext (α, β) without proofs or nonce.</summary>
    [ProtoContract]
    public class ProtobufCiphertext
    {
        [ProtoMember(1)]
        public required byte[] Alpha { get; init; }
        [ProtoMember(2)]
        public required byte[] Beta { get; init; }
    }

    [ProtoContract]
    public record ProtobufEncryptedContest
    {
        [ProtoMember(1)]
        public required string Id { get; init; }
        [ProtoMember(2)]
        public required List<ProtobufEncryptedSelection> Choices { get; init; } = new();
        [ProtoMember(3)]
        public required ProtobufChallengeResponsePair[] Proofs { get; init; }
        // Members 4-7 held the four fixed supplemental counters (overvote, null vote, undervote,
        // write-in) before they became manifest-declared fields (S5). They are retired, not reused.
        [ProtoMember(8)]
        public required ProtobufEncryptedData? ContestData { get; init; }
        [ProtoMember(9)]
        public required byte[] ContestHash { get; init; }

        /// <summary>The declared supplemental fields, in manifest order (<see cref="EncryptedContest.SupplementalFields"/>).</summary>
        [ProtoMember(10)]
        public List<ProtobufEncryptedSupplementalField>? SupplementalFields { get; init; }

        /// <summary><see cref="EncryptedContest.UndervoteDifferenceProof"/>; absent when there is none.</summary>
        [ProtoMember(11)]
        public ProtobufChallengeResponsePair[]? UndervoteDifferenceProof { get; init; }

        /// <summary><see cref="EncryptedContest.NullVoteProof"/>; absent when there is none.</summary>
        [ProtoMember(12)]
        public ProtobufChallengeResponsePair[]? NullVoteProof { get; init; }
    }

    /// <summary>A supplemental field's encryption, keyed by its label, as a selection is keyed by its option's.</summary>
    [ProtoContract]
    public record ProtobufEncryptedSupplementalField : ProtobufEncryptedValueWithProofs
    {
        [ProtoMember(4)]
        public required string FieldId { get; init; }
    }

    [ProtoContract]
    public record ProtobufEncryptedSelection : ProtobufEncryptedValueWithProofs
    {
        [ProtoMember(4)]
        public required string ChoiceId { get; init; }
    }

    [ProtoContract]
    public record ProtobufChallengeResponsePair
    {
        [ProtoMember(1)]
        public required byte[] Challenge { get; init; }
        [ProtoMember(2)]
        public required byte[] Response { get; init; }
    }

    [ProtoContract]
    [ProtoInclude(10, typeof(ProtobufEncryptedSelection))]
    [ProtoInclude(11, typeof(ProtobufEncryptedSupplementalField))]
    public record ProtobufEncryptedValueWithProofs
    {
        [ProtoMember(1)]
        public required byte[] Alpha { get; init; }
        [ProtoMember(2)]
        public required byte[] Beta { get; init; }

        // No nonce member, on purpose (S10b-0): an encryption nonce is a secret, and a DTO member
        // holding one is one attribute away from putting it on the wire. The unused
        // ProtobufEncryptedValue struct, which also had one, is gone.

        [ProtoMember(3)]
        public required ProtobufChallengeResponsePair[] Proofs { get; init; }
    }

    /// <summary>
    /// A hashed ElGamal ciphertext (C_0, C_1, C_2 = (c, v)) under K-hat: a contest data field
    /// (§3.3.10) or the encrypted ballot nonce (§3.3.4).
    /// </summary>
    [ProtoContract]
    public class ProtobufEncryptedData
    {
        [ProtoMember(1)]
        public required byte[] C0 { get; init; }
        [ProtoMember(2)]
        public required byte[] C1 { get; init; }
        [ProtoMember(3)]
        public required byte[] Challenge { get; init; }
        [ProtoMember(4)]
        public required byte[] Response { get; init; }
    }
}