using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Perf.Cli.Running;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Perf.UnitTests;

public class SerializationBenchmarkTests
{
    [Fact]
    public void Measure_ReportsThroughputAndSizeForBothSerializers()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, "device");
        var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(
            records.EncryptionRecord,
            "device",
            deviceHash,
            ElectionFixtureBuilder.CreateBallot(
                manifest,
                selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 }));

        var metrics = SerializationBenchmark.Measure(ballot, iterations: 5);

        Assert.True(metrics.Json.Bytes > 0);
        Assert.True(metrics.Protobuf.Bytes > 0);
        Assert.True(metrics.Json.SerializeOpsPerSec > 0);
        Assert.True(metrics.Json.DeserializeOpsPerSec > 0);
        Assert.True(metrics.Protobuf.SerializeOpsPerSec > 0);
        Assert.True(metrics.Protobuf.DeserializeOpsPerSec > 0);

        // JSON writes indented text with hex-encoded big integers; protobuf writes raw bytes.
        Assert.True(metrics.Protobuf.Bytes < metrics.Json.Bytes);

        // The measured ballot's shape is recorded alongside the throughput/size figures -- one
        // contest, two choices, per CreateMinimalManifest -- so a reader of a persisted result can
        // judge how representative the numbers are. Both serializers measured the same ballot.
        Assert.Equal(1, metrics.Json.ContestCount);
        Assert.Equal(2, metrics.Json.SelectionCount);
        Assert.Equal(1, metrics.Protobuf.ContestCount);
        Assert.Equal(2, metrics.Protobuf.SelectionCount);

        // Verify that Deserialize actually reconstructs the ballot correctly.
        // Round-trip through JSON serializer.
        var jsonSerializer = new JsonEncryptedBallotSerializer();
        using (var jsonStream = new MemoryStream())
        {
            jsonSerializer.Serialize(jsonStream, ballot);
            jsonStream.Position = 0;
            var jsonRoundTrip = jsonSerializer.Deserialize(jsonStream);
            Assert.NotNull(jsonRoundTrip);
            Assert.Equal(ballot.Id, jsonRoundTrip.Id);
            Assert.Equal(
                ballot.Contests[0].Choices[0].Alpha,
                jsonRoundTrip.Contests[0].Choices[0].Alpha);
        }

        // Round-trip through Protobuf serializer.
        var protobufSerializer = new ProtobufEncryptedBallotSerializer();
        using (var protobufStream = new MemoryStream())
        {
            protobufSerializer.Serialize(protobufStream, ballot);
            protobufStream.Position = 0;
            var protobufRoundTrip = protobufSerializer.Deserialize(protobufStream);
            Assert.NotNull(protobufRoundTrip);
            Assert.Equal(ballot.Id, protobufRoundTrip.Id);
            Assert.Equal(
                ballot.Contests[0].Choices[0].Alpha,
                protobufRoundTrip.Contests[0].Choices[0].Alpha);
        }
    }
}
