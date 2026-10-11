using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Testing.Common;
using System.Text;
using System.Text.Json.Nodes;
using static ElectionGuard.Core.Serialization.ProtobufEncryptedBallotSerializer;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// S10a (the S3 and S5 carry-overs): a ballot document with a missing or null part fails with a
/// typed exception, never a <see cref="NullReferenceException"/>. A missing or null scalar (an id,
/// a label, a hash, an element) is refused at decode time; a missing or null list or list entry
/// decodes and is reported by <see cref="BallotStructure"/> as <c>"N.structure"</c> before
/// Verifications 6-9 look at the ballot; a missing proof list decodes empty and fails the proof
/// count, as a null JSON proof list already did (S5 review).
/// </summary>
public class MalformedBallotDocumentTests
{
    public MalformedBallotDocumentTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private sealed class Fixture
    {
        public required EncryptionRecord Record { get; init; }
        public required VotingDeviceInformationHash DeviceHash { get; init; }
        public required EncryptedBallot Ballot { get; init; }
    }

    private static readonly Lazy<Fixture> Shared = new(() =>
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, "device-1");
        var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(records.EncryptionRecord, "device-1", deviceHash,
            ElectionFixtureBuilder.CreateBallot(manifest, "ballot-1", new Dictionary<string, int> { ["choice-1"] = 1 }, 0, "text"));
        return new Fixture { Record = records.EncryptionRecord, DeviceHash = deviceHash, Ballot = ballot };
    });

    private static void Run(int verification, EncryptedBallot ballot, Fixture fixture)
    {
        switch (verification)
        {
            case 6:
                new SelectionEncryptionsWellFormedVerification().Verify(ballot, fixture.Record);
                break;
            case 7:
                new AdherenceToVoteLimitsVerification().Verify(ballot, fixture.Record);
                break;
            case 8:
                new ConfirmationCodeVerification().Verify(ballot, fixture.DeviceHash, fixture.Record, null);
                break;
            case 9:
                new EncryptedTally(fixture.Record.Manifest).AddBallot(ballot);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(verification));
        }
    }

    // --- JSON ------------------------------------------------------------------------------------------

    private static EncryptedBallot? ReadJson(Action<JsonNode> edit)
    {
        var serializer = new JsonEncryptedBallotSerializer();
        using var encoded = new MemoryStream();
        serializer.Serialize(encoded, Shared.Value.Ballot);
        var document = JsonNode.Parse(encoded.ToArray())!;
        edit(document);
        return serializer.Deserialize(new MemoryStream(Encoding.UTF8.GetBytes(document.ToJsonString())));
    }

    public static TheoryData<string, int> JsonNullLists()
    {
        var data = new TheoryData<string, int>();
        foreach (var shape in new[] { "null contest list", "null contest entry", "null option list", "null option entry", "null supplemental field entry" })
        {
            foreach (int verification in new[] { 6, 7, 8, 9 })
            {
                data.Add(shape, verification);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(JsonNullLists))]
    public void Json_NullListOrEntry_DecodesAndFailsAsStructure(string shape, int verification)
    {
        var ballot = ReadJson(document =>
        {
            var contest = document["contests"]![0]!;
            switch (shape)
            {
                case "null contest list": document["contests"] = null; break;
                case "null contest entry": document["contests"]![0] = null; break;
                case "null option list": contest["choices"] = null; break;
                case "null option entry": contest["choices"]![1] = null; break;
                case "null supplemental field entry": contest["supplementalFields"]![0] = null; break;
                default: throw new ArgumentOutOfRangeException(nameof(shape));
            }
        })!;

        var exception = Assert.Throws<VerificationFailedException>(() => Run(verification, ballot, Shared.Value));

        Assert.Equal($"{verification}.structure", exception.SubSection);
    }

    [Theory]
    [InlineData("null ballot id")]
    [InlineData("null ballot style")]
    [InlineData("null H_I")]
    [InlineData("null contest id")]
    [InlineData("null option id")]
    [InlineData("null supplemental field id")]
    [InlineData("null contest data C1")]
    [InlineData("contest hash of 31 bytes")]
    [InlineData("confirmation code of 33 bytes")]
    [InlineData("H_I of 31 bytes")]
    public void Json_NullOrShortScalar_IsRefusedAtDecode(string shape)
    {
        var exception = Record.Exception(() => ReadJson(document =>
        {
            var contest = document["contests"]![0]!;
            switch (shape)
            {
                case "null ballot id": document["id"] = null; break;
                case "null ballot style": document["ballotStyleId"] = null; break;
                case "null H_I": document["selectionEncryptionIdentifierHash"] = null; break;
                case "null contest id": contest["id"] = null; break;
                case "null option id": contest["choices"]![0]!["choice_id"] = null; break;
                case "null supplemental field id": contest["supplementalFields"]![0]!["field_id"] = null; break;
                case "null contest data C1": contest["contestData"]!["c1"] = null; break;
                case "contest hash of 31 bytes": contest["contestHash"] = Convert.ToBase64String(new byte[31]); break;
                case "confirmation code of 33 bytes": document["confirmationCode"] = Convert.ToBase64String(new byte[33]); break;
                case "H_I of 31 bytes": document["selectionEncryptionIdentifierHash"] = Convert.ToBase64String(new byte[31]); break;
                default: throw new ArgumentOutOfRangeException(nameof(shape));
            }
        }));

        Assert.IsType<NonCanonicalEncodingException>(exception);
    }

    // --- Protobuf --------------------------------------------------------------------------------------

    private static ProtobufEncryptedBallot Dto()
    {
        using var encoded = new MemoryStream();
        new ProtobufEncryptedBallotSerializer().Serialize(encoded, Shared.Value.Ballot);
        encoded.Position = 0;
        return ProtoBuf.Serializer.Deserialize<ProtobufEncryptedBallot>(encoded);
    }

    /// <summary>Sets an init-only member of a protobuf document to <paramref name="value"/> (null leaves it off the wire).</summary>
    private static T With<T>(T dto, string member, object? value) where T : class
    {
        typeof(T).GetProperty(member)!.SetValue(dto, value);
        return dto;
    }

    private static EncryptedBallot? ReadProtobuf(ProtobufEncryptedBallot dto)
    {
        using var encoded = new MemoryStream();
        ProtoBuf.Serializer.Serialize(encoded, dto);
        encoded.Position = 0;
        return new ProtobufEncryptedBallotSerializer().Deserialize(encoded);
    }

    public static TheoryData<string, int> ProtobufMissingLists()
    {
        var data = new TheoryData<string, int>();
        foreach (var shape in new[] { "no contests", "no options" })
        {
            foreach (int verification in new[] { 6, 7, 8, 9 })
            {
                data.Add(shape, verification);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(ProtobufMissingLists))]
    public void Protobuf_MissingList_DecodesEmptyAndFailsAsStructure(string shape, int verification)
    {
        var dto = Dto();
        if (shape == "no contests")
        {
            With(dto, nameof(ProtobufEncryptedBallot.Contests), null);
        }
        else
        {
            With(dto.Contests[0], nameof(ProtobufEncryptedContest.Choices), null);
        }

        var ballot = ReadProtobuf(dto)!;

        var exception = Assert.Throws<VerificationFailedException>(() => Run(verification, ballot, Shared.Value));
        Assert.Equal($"{verification}.structure", exception.SubSection);
    }

    [Theory]
    [InlineData("selection", 6)]
    [InlineData("supplemental field", 6)]
    [InlineData("contest", 7)]
    public void Protobuf_MissingProofList_DecodesEmptyAndFailsTheProofCount(string owner, int verification)
    {
        var dto = Dto();
        switch (owner)
        {
            case "selection": With(dto.Contests[0].Choices[0], nameof(ProtobufEncryptedSelection.Proofs), null); break;
            case "supplemental field": With(dto.Contests[0].SupplementalFields![0], nameof(ProtobufEncryptedSupplementalField.Proofs), null); break;
            case "contest": With(dto.Contests[0], nameof(ProtobufEncryptedContest.Proofs), null); break;
        }

        var ballot = ReadProtobuf(dto)!;

        var exception = Assert.Throws<VerificationFailedException>(() => Run(verification, ballot, Shared.Value));
        Assert.StartsWith($"{verification}", exception.SubSection);
    }

    [Theory]
    [InlineData("ballot id")]
    [InlineData("ballot style")]
    [InlineData("H_I")]
    [InlineData("confirmation code")]
    [InlineData("contest id")]
    [InlineData("contest hash")]
    [InlineData("option id")]
    [InlineData("alpha")]
    [InlineData("proof challenge")]
    [InlineData("supplemental field id")]
    [InlineData("contest data C1")]
    public void Protobuf_MissingScalar_IsRefusedAtDecode(string member)
    {
        var dto = Dto();
        var contest = dto.Contests[0];
        switch (member)
        {
            case "ballot id": With(dto, nameof(ProtobufEncryptedBallot.Id), null); break;
            case "ballot style": With(dto, nameof(ProtobufEncryptedBallot.BallotStyleId), null); break;
            case "H_I": With(dto, nameof(ProtobufEncryptedBallot.SelectionEncryptionIdentifierHash), null); break;
            case "confirmation code": With(dto, nameof(ProtobufEncryptedBallot.ConfirmationCode), null); break;
            case "contest id": With(contest, nameof(ProtobufEncryptedContest.Id), null); break;
            case "contest hash": With(contest, nameof(ProtobufEncryptedContest.ContestHash), null); break;
            case "option id": With(contest.Choices[0], nameof(ProtobufEncryptedSelection.ChoiceId), null); break;
            case "alpha": With<ProtobufEncryptedValueWithProofs>(contest.Choices[0], nameof(ProtobufEncryptedSelection.Alpha), null); break;
            case "proof challenge": With(contest.Proofs[0], nameof(ProtobufChallengeResponsePair.Challenge), null); break;
            case "supplemental field id": With(contest.SupplementalFields![0], nameof(ProtobufEncryptedSupplementalField.FieldId), null); break;
            case "contest data C1": With(contest.ContestData!, nameof(ProtobufEncryptedData.C1), null); break;
        }

        var exception = Record.Exception(() => ReadProtobuf(dto));

        Assert.IsType<NonCanonicalEncodingException>(exception);
    }
}
