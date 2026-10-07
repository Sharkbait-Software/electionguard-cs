using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Testing.Common;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// G19/G37: the chaining field B_C each ballot was hashed with travels with it through both ballot
/// serializers (JSON <c>chainingField</c>, protobuf field 11), and a device's ordered ballot list
/// (<see cref="DeviceChainRecord"/>, §3.7) round-trips through JSON, so that Verification 8 still
/// passes on what was read back. The strict decoding of B_C is in <see cref="StrictDecodingTests"/>.
/// </summary>
public class ChainingSerializationTests
{
    public ChainingSerializationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly Lazy<(EncryptionRecord Record, List<EncryptedBallot> Ballots, DeviceChainRecord Device)> Simple = new(() =>
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: ChainingMode.Simple);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var chain = new DeviceChain(record, "device-1");
        var encryptor = new BallotEncryptor(record, "device-1", chain.DeviceInformationHash);
        var ballots = Enumerable.Range(1, 3)
            .Select(i => encryptor.EncryptNext(ElectionFixtureBuilder.CreateBallot(manifest, ballotId: $"ballot-{i}", selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 }), chain))
            .ToList();
        foreach (var ballot in ballots)
        {
            ballot.RecordStatus(BallotStatus.Cast);
        }

        return (record, ballots, chain.Close());
    });

    public static TheoryData<string> Serializers() => new() { "json", "protobuf" };

    private static IEncryptedBallotSerializer Serializer(string name) =>
        name == "json" ? new JsonEncryptedBallotSerializer() : new ProtobufEncryptedBallotSerializer();

    [Theory]
    [MemberData(nameof(Serializers))]
    public void BallotRoundTrip_PreservesTheChainingField_AndTheDeviceChainStillVerifies(string name)
    {
        var (record, ballots, device) = Simple.Value;
        var serializer = Serializer(name);

        var decoded = ballots.Select(ballot =>
        {
            using var stream = new MemoryStream();
            serializer.Serialize(stream, ballot);
            stream.Position = 0;
            return serializer.Deserialize(stream)!;
        }).ToList();

        Assert.Equal(ballots.Select(x => x.ChainingField), decoded.Select(x => x.ChainingField));
        var verification = new ConfirmationCodeVerification();
        foreach (var ballot in decoded)
        {
            verification.Verify(ballot, record);
        }

        verification.VerifyDevices([device], decoded, record);
    }

    [Fact]
    public void Json_ChainingField_IsRequired_AndNeverNull()
    {
        var (_, ballots, _) = Simple.Value;
        var serializer = new JsonEncryptedBallotSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, ballots[1]);
        var json = JsonNode.Parse(stream.ToArray())!.AsObject();
        Assert.Equal((byte[])ballots[1].ChainingField, Convert.FromBase64String(json["chainingField"]!.GetValue<string>()));

        var withNull = JsonNode.Parse(json.ToJsonString())!.AsObject();
        withNull["chainingField"] = null;
        Assert.Throws<JsonException>(() => serializer.Deserialize(new MemoryStream(Encoding.UTF8.GetBytes(withNull.ToJsonString()))));

        json.Remove("chainingField");
        Assert.Throws<JsonException>(() => serializer.Deserialize(new MemoryStream(Encoding.UTF8.GetBytes(json.ToJsonString()))));
    }

    [Fact]
    public void DeviceChainRecord_JsonRoundTrip_KeepsEveryValue_AndStillVerifies()
    {
        var (record, ballots, device) = Simple.Value;
        var noChaining = new DeviceChainRecord
        {
            DeviceId = "device-2",
            DeviceInformationHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-2"),
            BallotKind = DeviceChainBallotKind.Encrypted,
            ChainingMode = ChainingMode.None,
            ConfirmationCodes = [],
        };
        var serializer = new JsonDeviceChainRecordSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, [device, noChaining]);
        stream.Position = 0;

        var decoded = serializer.Deserialize(stream)!;

        Assert.Equal(2, decoded.Count);
        var simple = decoded[0];
        Assert.Equal(device.DeviceId, simple.DeviceId);
        Assert.Equal(device.DeviceInformationHash, simple.DeviceInformationHash);
        Assert.Equal(device.BallotKind, simple.BallotKind);
        Assert.Equal(device.ChainingMode, simple.ChainingMode);
        Assert.Equal(device.ConfirmationCodes, simple.ConfirmationCodes);
        Assert.Equal(device.InitialHash, simple.InitialHash);
        Assert.Equal(device.ClosingChainingField, simple.ClosingChainingField);
        Assert.Equal(device.ClosingHash, simple.ClosingHash);
        Assert.Null(decoded[1].InitialHash);
        Assert.Null(decoded[1].ClosingChainingField);
        Assert.Null(decoded[1].ClosingHash);
        Assert.Empty(decoded[1].ConfirmationCodes);

        new ConfirmationCodeVerification().VerifyDevice(simple, ballots, record);
    }

    [Fact]
    public void DeviceChainRecord_Json_ClosingFieldOfTheWrongLength_IsRejected()
    {
        var (_, _, device) = Simple.Value;
        var serializer = new JsonDeviceChainRecordSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, [device]);
        var json = JsonNode.Parse(stream.ToArray())!;
        var entry = json[0]!;
        Assert.NotNull(entry["closingChainingField"]);
        entry["closingChainingField"] = Convert.ToBase64String(((byte[])device.ClosingChainingField!.Value)[1..]);

        Assert.Throws<NonCanonicalEncodingException>(() => serializer.Deserialize(new MemoryStream(Encoding.UTF8.GetBytes(json.ToJsonString()))));
    }
}
