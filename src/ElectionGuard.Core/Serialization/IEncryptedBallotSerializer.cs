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


public class JsonEncryptedBallotSerializer : IEncryptedBallotSerializer
{
    public void Serialize(Stream destination, EncryptedBallot encryptedBallot)
    {
        var options = new JsonSerializerOptions
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
            }
        };

        JsonSerializer.Serialize(destination, encryptedBallot, options);
    }

    public EncryptedBallot? Deserialize(Stream source)
    {
        var options = new JsonSerializerOptions
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
            }
        };

        return JsonSerializer.Deserialize<EncryptedBallot>(source, options);
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
                    EncryptionNonce = s.EncryptionNonce,
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
            Weight = encryptedBallot.Weight,
            Status = encryptedBallot.Status,
            EncryptedBallotNonce = new ProtobufEncryptedData
            {
                C0 = encryptedBallot.EncryptedBallotNonce.C0.ToByteArray(),
                C1 = encryptedBallot.EncryptedBallotNonce.C1,
                Challenge = encryptedBallot.EncryptedBallotNonce.Challenge,
                Response = encryptedBallot.EncryptedBallotNonce.Response,
            },
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
            SelectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(protobufBallot.SelectionEncryptionIdentifierHash),
            BallotStyleId = protobufBallot.BallotStyleId,
            DeviceId = protobufBallot.DeviceId,
            Contests = protobufBallot.Contests.Select(c => new EncryptedContest
            {
                Id = c.Id,
                Choices = c.Choices.Select(s => new EncryptedSelection
                {
                    ChoiceId = s.ChoiceId,
                    Alpha = IntegerModP.FromCanonicalBytes(s.Alpha),
                    Beta = IntegerModP.FromCanonicalBytes(s.Beta),
                    Proofs = s.Proofs.Select(p => new ChallengeResponsePair
                    {
                        Challenge = IntegerModQ.FromCanonicalBytes(p.Challenge),
                        Response = IntegerModQ.FromCanonicalBytes(p.Response)
                    }).ToArray()
                }).ToList(),
                Proofs = c.Proofs.Select(p => new ChallengeResponsePair
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
                    Proofs = f.Proofs.Select(p => new ChallengeResponsePair
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
                ContestHash = new ContestHash(c.ContestHash),
            }).ToList(),
            ConfirmationCode = new ConfirmationCode(protobufBallot.ConfirmationCode),
            EncryptedBallotNonce = ReadBallotNonce(protobufBallot.EncryptedBallotNonce),
            Weight = protobufBallot.Weight,
            Status = protobufBallot.Status,
        };

        return encryptedBallot;
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
        /// The recorded <see cref="BallotStatus"/> (§3.7). Not required: a ballot serialized before
        /// it was submitted has none, and 0 (<see cref="BallotStatus.NotSubmitted"/>) is then left
        /// off the wire.
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
        
        public byte[]? EncryptionNonce { get; init; }

        [ProtoMember(3)]
        public required ProtobufChallengeResponsePair[] Proofs { get; init; }

        public ProtobufEncryptedValue ToEncryptedValue()
        {
            return new ProtobufEncryptedValue
            {
                Alpha = Alpha,
                Beta = Beta,
                EncryptionNonce = EncryptionNonce
            };
        }
    }

    [ProtoContract]
    public struct ProtobufEncryptedValue
    {
        [ProtoMember(1)]
        public required byte[] Alpha { get; init; }
        [ProtoMember(2)]
        public required byte[] Beta { get; init; }

        public byte[]? EncryptionNonce { get; init; }
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