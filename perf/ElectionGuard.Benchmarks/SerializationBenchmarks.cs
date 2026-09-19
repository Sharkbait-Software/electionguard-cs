using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Serialization;

namespace ElectionGuard.Benchmarks;

[MemoryDiagnoser]
public class SerializationBenchmarks
{
    private EncryptedBallot _ballot = null!;
    private JsonEncryptedBallotSerializer _json = null!;
    private ProtobufEncryptedBallotSerializer _protobuf = null!;
    private byte[] _jsonBytes = null!;
    private byte[] _protobufBytes = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ballot = BenchmarkElection.Create().EncryptBallot(0);
        _json = new JsonEncryptedBallotSerializer();
        _protobuf = new ProtobufEncryptedBallotSerializer();
        _jsonBytes = Encode(_json);
        _protobufBytes = Encode(_protobuf);
    }

    [Benchmark(Baseline = true)]
    public byte[] JsonSerialize() => Encode(_json);

    [Benchmark]
    public EncryptedBallot? JsonDeserialize()
    {
        using var source = new MemoryStream(_jsonBytes);
        return _json.Deserialize(source);
    }

    [Benchmark]
    public byte[] ProtobufSerialize() => Encode(_protobuf);

    [Benchmark]
    public EncryptedBallot? ProtobufDeserialize()
    {
        using var source = new MemoryStream(_protobufBytes);
        return _protobuf.Deserialize(source);
    }

    private byte[] Encode(IEncryptedBallotSerializer serializer)
    {
        using var destination = new MemoryStream();
        serializer.Serialize(destination, _ballot);
        return destination.ToArray();
    }
}
