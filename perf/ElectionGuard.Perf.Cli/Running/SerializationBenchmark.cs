using System.Diagnostics;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Perf.Cli.Results;

namespace ElectionGuard.Perf.Cli.Running;

public static class SerializationBenchmark
{
    public static SerializationMetrics Measure(EncryptedBallot ballot, int iterations = 100)
    {
        if (iterations < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations), "A positive iteration count is required to avoid NaN/Infinity in throughput calculations");
        }

        int contestCount = ballot.Contests.Count;
        int selectionCount = ballot.Contests.Sum(contest => contest.Choices.Count);

        return new()
        {
            Json = MeasureOne(new JsonEncryptedBallotSerializer(), ballot, iterations) with
            {
                ContestCount = contestCount,
                SelectionCount = selectionCount,
            },
            Protobuf = MeasureOne(new ProtobufEncryptedBallotSerializer(), ballot, iterations) with
            {
                ContestCount = contestCount,
                SelectionCount = selectionCount,
            },
        };
    }

    private static SerializerMetrics MeasureOne(
        IEncryptedBallotSerializer serializer,
        EncryptedBallot ballot,
        int iterations)
    {
        byte[] encoded = Encode(serializer, ballot);

        // Warm the call tree before measuring, for the same tiered-compilation reason the pipeline
        // has a warmup pass.
        using (var warmup = new MemoryStream(encoded))
        {
            serializer.Deserialize(warmup);
        }

        var stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            // Do not call .ToArray() in the timed loop; it allocates and copies a full buffer.
            // Serialize into a fresh MemoryStream and discard it so serialize and deserialize
            // throughput figures measure comparable amounts of work. Pre-size it to encoded.Length
            // -- the length of a prior real serialization of this same ballot (see Encode below) --
            // so this loop does not pay array-doubling growth that the deserialize loop's
            // `new MemoryStream(encoded)` never pays by wrapping an existing buffer.
            using var destination = new MemoryStream(encoded.Length);
            serializer.Serialize(destination, ballot);
        }

        stopwatch.Stop();
        double serializeOpsPerSec = iterations / stopwatch.Elapsed.TotalSeconds;

        stopwatch.Restart();
        for (int i = 0; i < iterations; i++)
        {
            using var source = new MemoryStream(encoded);
            serializer.Deserialize(source);
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

    private static byte[] Encode(IEncryptedBallotSerializer serializer, EncryptedBallot ballot)
    {
        using var destination = new MemoryStream();
        serializer.Serialize(destination, ballot);
        return destination.ToArray();
    }
}
