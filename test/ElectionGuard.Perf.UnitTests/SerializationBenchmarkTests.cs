using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Perf.Cli.Running;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Perf.UnitTests;

public class SerializationBenchmarkTests
{
    [Fact]
    public void Measure_ReportsThroughputAndSizeForBothItemEncodings()
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

        var metrics = SerializationBenchmark.Measure(ballot, manifest, iterations: 5);

        Assert.True(metrics.Json.Bytes > 0);
        Assert.True(metrics.Protobuf.Bytes > 0);
        Assert.True(metrics.Json.SerializeOpsPerSec > 0);
        Assert.True(metrics.Json.DeserializeOpsPerSec > 0);
        Assert.True(metrics.Protobuf.SerializeOpsPerSec > 0);
        Assert.True(metrics.Protobuf.DeserializeOpsPerSec > 0);

        // The proto3 JSON line writes every byte string as base64; the item is the raw bytes.
        Assert.True(metrics.Protobuf.Bytes < metrics.Json.Bytes);

        // The measured ballot's shape is recorded alongside the throughput/size figures -- one
        // contest, two choices, per CreateMinimalManifest -- so a reader of a persisted result can
        // judge how representative the numbers are. Both encodings measured the same ballot.
        Assert.Equal(1, metrics.Json.ContestCount);
        Assert.Equal(2, metrics.Json.SelectionCount);
        Assert.Equal(1, metrics.Protobuf.ContestCount);
        Assert.Equal(2, metrics.Protobuf.SelectionCount);

        // What is measured round-trips: the item codec in both encodings gives back the ballot,
        // byte for byte in its canonical item.
        byte[] item = RecordItemCodec.EncodeBallot(ballot, manifest);
        Assert.Equal(item.LongLength, metrics.Protobuf.Bytes);
        var fromItem = RecordItemCodec.DecodeBallot(item, manifest, "device");
        Assert.Equal((byte[])ballot.SelectionEncryptionIdentifierHash, (byte[])fromItem.SelectionEncryptionIdentifierHash);
        Assert.Equal(ballot.Contests[0].Choices[0].Alpha, fromItem.Contests[0].Choices[0].Alpha);
        Assert.Equal(item, RecordItemCodec.EncodeBallot(fromItem, manifest));

        byte[] line = RecordItemCodec.EncodeBallotJson(ballot, manifest);
        Assert.Equal(line.LongLength, metrics.Json.Bytes);
        var fromLine = RecordItemCodec.DecodeBallotJson(line, manifest, "device");
        Assert.Equal(item, RecordItemCodec.EncodeBallot(fromLine, manifest));
    }
}
