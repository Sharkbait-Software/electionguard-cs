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
                    C0 = c.ContestData.C0,
                    C1 = c.ContestData.C1,
                    Challenge = c.ContestData.Challenge,
                    Response = c.ContestData.Response
                } : null,
                ContestHash = c.ContestHash,
            }).ToList(),
            ConfirmationCode = encryptedBallot.ConfirmationCode,
            Weight = encryptedBallot.Weight,
            Status = encryptedBallot.Status,
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
                ContestData = c.ContestData != null ? new EncryptedData
                {
                    C0 = c.ContestData.C0,
                    C1 = c.ContestData.C1,
                    Challenge = IntegerModQ.FromCanonicalBytes(c.ContestData.Challenge),
                    Response = IntegerModQ.FromCanonicalBytes(c.ContestData.Response)
                } : null,
                ContestHash = new ContestHash(c.ContestHash),
            }).ToList(),
            ConfirmationCode = new ConfirmationCode(protobufBallot.ConfirmationCode),
            Weight = protobufBallot.Weight,
            Status = protobufBallot.Status,
        };

        return encryptedBallot;
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