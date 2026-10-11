using System.Diagnostics;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Running;

/// <summary>
/// One encrypted ballot through the election record's item codec (<see cref="RecordItemCodec"/>,
/// S10b-15): <c>protobuf</c> is the canonical <c>RecordItem</c> encoding a record stores and a device
/// sends, <c>json</c> its proto3 JSON line (design §5.5). Decoding includes what a reader does with
/// an item: the canonicality check, the parse and the mapping to the domain ballot. Until S10b-15
/// these two keys measured the retired protobuf-net and System.Text.Json serializers, so a record of
/// either era compares only with its own.
/// </summary>
public static class SerializationBenchmark
{
    public static SerializationMetrics Measure(EncryptedBallot ballot, Manifest manifest, int iterations = 100)
    {
        if (iterations < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations), "A positive iteration count is required to avoid NaN/Infinity in throughput calculations");
        }

        int contestCount = ballot.Contests.Count;
        int selectionCount = ballot.Contests.Sum(contest => contest.Choices.Count);
        string deviceId = ballot.DeviceId;

        return new()
        {
            Json = MeasureOne(
                () => RecordItemCodec.EncodeBallotJson(ballot, manifest),
                bytes => RecordItemCodec.DecodeBallotJson(bytes, manifest, deviceId),
                iterations) with
            {
                ContestCount = contestCount,
                SelectionCount = selectionCount,
            },
            Protobuf = MeasureOne(
                () => RecordItemCodec.EncodeBallot(ballot, manifest),
                bytes => RecordItemCodec.DecodeBallot(bytes, manifest, deviceId),
                iterations) with
            {
                ContestCount = contestCount,
                SelectionCount = selectionCount,
            },
        };
    }

    private static SerializerMetrics MeasureOne(Func<byte[]> encode, Func<byte[], EncryptedBallot> decode, int iterations)
    {
        byte[] encoded = encode();

        // Warm the call tree before measuring, for the same tiered-compilation reason the pipeline
        // has a warmup pass.
        decode(encoded);

        var stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            encode();
        }

        stopwatch.Stop();
        double serializeOpsPerSec = iterations / stopwatch.Elapsed.TotalSeconds;

        stopwatch.Restart();
        for (int i = 0; i < iterations; i++)
        {
            decode(encoded);
        }

        stopwatch.Stop();
        double deserializeOpsPerSec = iterations / stopwatch.Elapsed.TotalSeconds;

        return new SerializerMetrics
        {
            SerializeOpsPerSec = serializeOpsPerSec,
            DeserializeOpsPerSec = deserializeOpsPerSec,
            Bytes = encoded.LongLength,
        };
    }
}
