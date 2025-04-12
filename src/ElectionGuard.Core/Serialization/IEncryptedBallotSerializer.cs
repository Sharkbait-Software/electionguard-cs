using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Serialization.Converters;
using ProtoBuf;
using System.Text.Json;

namespace ElectionGuard.Core.Serialization;

public interface IEncryptedBallotSerializer
{
    void Serialize(Stream destination, EncryptedBallot encryptedBallot);
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
                new SelectionEncryptionIdentifierHashJsonConverter(),
                new VotingDeviceInformationHashJsonConverter(),
            }
        };

        JsonSerializer.Serialize(destination, encryptedBallot, options);
    }
}

public class ProtobufEncryptedBallotSerializer : IEncryptedBallotSerializer
{
    public void Serialize(Stream destination, EncryptedBallot encryptedBallot)
    {
        var protobufEncryptedBallot = new ProtobufEncryptedBallot
        {
            Id = encryptedBallot.Id,
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
                OvervoteCount = new ProtobufEncryptedValueWithProofs
                {
                    Alpha = c.OvervoteCount.Alpha.ToByteArray(),
                    Beta = c.OvervoteCount.Beta.ToByteArray(),
                    EncryptionNonce = c.OvervoteCount.EncryptionNonce,
                    Proofs = c.OvervoteCount.Proofs.Select(p => new ProtobufChallengeResponsePair
                    {
                        Challenge = p.Challenge.ToByteArray(),
                        Response = p.Response.ToByteArray()
                    }).ToArray()
                },
                NullvoteCount = new ProtobufEncryptedValueWithProofs
                {
                    Alpha = c.NullvoteCount.Alpha.ToByteArray(),
                    Beta = c.NullvoteCount.Beta.ToByteArray(),
                    EncryptionNonce = c.NullvoteCount.EncryptionNonce,
                    Proofs = c.NullvoteCount.Proofs.Select(p => new ProtobufChallengeResponsePair
                    {
                        Challenge = p.Challenge.ToByteArray(),
                        Response = p.Response.ToByteArray()
                    }).ToArray()
                },
                UndervoteCount = new ProtobufEncryptedValueWithProofs
                {
                    Alpha = c.UndervoteCount.Alpha.ToByteArray(),
                    Beta = c.UndervoteCount.Beta.ToByteArray(),
                    EncryptionNonce = c.UndervoteCount.EncryptionNonce,
                    Proofs = c.UndervoteCount.Proofs.Select(p => new ProtobufChallengeResponsePair
                    {
                        Challenge = p.Challenge.ToByteArray(),
                        Response = p.Response.ToByteArray()
                    }).ToArray()
                },
                WriteInVoteCount = new ProtobufEncryptedValueWithProofs
                {
                    Alpha = c.WriteInVoteCount.Alpha.ToByteArray(),
                    Beta = c.WriteInVoteCount.Beta.ToByteArray(),
                    EncryptionNonce = c.WriteInVoteCount.EncryptionNonce,
                    Proofs = c.WriteInVoteCount.Proofs.Select(p => new ProtobufChallengeResponsePair
                    {
                        Challenge = p.Challenge.ToByteArray(),
                        Response = p.Response.ToByteArray()
                    }).ToArray()
                },
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
        };

        Serializer.Serialize(destination, protobufEncryptedBallot);
    }

    [ProtoContract]
    public class ProtobufEncryptedBallot
    {
        [ProtoMember(1)]
        public required string Id { get; init; }
        [ProtoMember(2)]
        public required byte[] SelectionEncryptionIdentifierHash { get; init; }
        [ProtoMember(3)]
        public required string BallotStyleId { get; init; }
        [ProtoMember(4)]
        public required string DeviceId { get; init; }
        [ProtoMember(5)]
        public required List<ProtobufEncryptedContest> Contests { get; init; }
        [ProtoMember(6)]
        public required byte[] ConfirmationCode { get; init; }
        [ProtoMember(7)]
        public required int Weight { get; init; }
    }

    [ProtoContract]
    public record ProtobufEncryptedContest
    {
        [ProtoMember(1)]
        public required string Id { get; init; }
        [ProtoMember(2)]
        public required List<ProtobufEncryptedSelection> Choices { get; init; }
        [ProtoMember(3)]
        public required ProtobufChallengeResponsePair[] Proofs { get; init; }
        [ProtoMember(4)]
        public required ProtobufEncryptedValueWithProofs OvervoteCount { get; init; }
        [ProtoMember(5)]
        public required ProtobufEncryptedValueWithProofs NullvoteCount { get; init; }
        [ProtoMember(6)]
        public required ProtobufEncryptedValueWithProofs UndervoteCount { get; init; }
        [ProtoMember(7)]
        public required ProtobufEncryptedValueWithProofs WriteInVoteCount { get; init; }
        [ProtoMember(8)]
        public required ProtobufEncryptedData? ContestData { get; init; }
        [ProtoMember(9)]
        public required byte[] ContestHash { get; init; }
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