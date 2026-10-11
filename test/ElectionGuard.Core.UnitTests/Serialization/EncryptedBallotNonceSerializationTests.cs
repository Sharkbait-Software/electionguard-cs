using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Testing.Common;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// G17: the encrypted ballot nonce C_ξB (§3.3.4) travels with every encrypted ballot, through both
/// serializers, unchanged, and a guardian can still verify its eq. (38) proof after the trip. The
/// strict decoding of its parts is in <see cref="StrictDecodingTests"/>.
/// </summary>
public class EncryptedBallotNonceSerializationTests
{
    public EncryptedBallotNonceSerializationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static readonly Lazy<(EncryptedBallot Ballot, EncryptionRecord Record, VotingDeviceInformationHash DeviceHash)> Shared = new(() =>
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, "device-1");
        var ballot = ElectionFixtureBuilder.CreateBallot(manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });
        return (ElectionFixtureBuilder.CreateEncryptedBallot(records.EncryptionRecord, "device-1", deviceHash, ballot, status: BallotStatus.Challenged), records.EncryptionRecord, deviceHash);
    });

    public static TheoryData<string> Serializers() => new() { "json", "protobuf" };

    private static IEncryptedBallotSerializer Serializer(string name) =>
        name == "json" ? new JsonEncryptedBallotSerializer() : new ProtobufEncryptedBallotSerializer();

    [Theory]
    [MemberData(nameof(Serializers))]
    public void RoundTrip_PreservesTheEncryptedBallotNonce(string name)
    {
        var (original, _, _) = Shared.Value;
        var serializer = Serializer(name);
        using var stream = new MemoryStream();
        serializer.Serialize(stream, original);
        stream.Position = 0;

        var result = serializer.Deserialize(stream)!;

        var expected = original.EncryptedBallotNonce;
        var actual = result.EncryptedBallotNonce;
        Assert.Equal(expected.C0, actual.C0);
        Assert.Equal(expected.C1, actual.C1);
        Assert.Equal(expected.Challenge, actual.Challenge);
        Assert.Equal(expected.Response, actual.Response);
        Assert.Equal(BallotStatus.Challenged, result.Status);
        Assert.True(BallotNonceEncryption.ProofHolds(result.SelectionEncryptionIdentifierHash, actual));
    }

    /// <summary>
    /// The JSON document names the field <c>encryptedBallotNonce</c>; a document without it is
    /// refused at decode time (the property is required), and one that writes null decodes but is
    /// malformed: Verification 6 fails it under "6.structure".
    /// </summary>
    [Fact]
    public void Json_MissingOrNullEncryptedBallotNonce_IsRefused()
    {
        var (original, record, _) = Shared.Value;
        var serializer = new JsonEncryptedBallotSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, original);
        var json = JsonNode.Parse(stream.ToArray())!.AsObject();
        Assert.NotNull(json["encryptedBallotNonce"]);
        Assert.Equal(original.EncryptedBallotNonce.C1, Convert.FromBase64String(json["encryptedBallotNonce"]!["c1"]!.GetValue<string>()));

        var withNull = JsonNode.Parse(json.ToJsonString())!.AsObject();
        withNull["encryptedBallotNonce"] = null;
        var decoded = serializer.Deserialize(new MemoryStream(Encoding.UTF8.GetBytes(withNull.ToJsonString())))!;
        Assert.Null(decoded.EncryptedBallotNonce);
        var exception = Assert.Throws<VerificationFailedException>(() => new SelectionEncryptionsWellFormedVerification().Verify(decoded, record));
        Assert.Equal("6.structure", exception.SubSection);

        json.Remove("encryptedBallotNonce");
        Assert.Throws<JsonException>(() => serializer.Deserialize(new MemoryStream(Encoding.UTF8.GetBytes(json.ToJsonString()))));
    }
}
