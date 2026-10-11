using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// One encrypted ballot through the election record's item codec (<see cref="RecordItemCodec"/>):
/// the canonical protobuf item and its proto3 JSON line. Decoding includes the canonicality check.
/// </summary>
[MemoryDiagnoser]
public class SerializationBenchmarks
{
    private EncryptedBallot _ballot = null!;
    private Manifest _manifest = null!;
    private byte[] _jsonBytes = null!;
    private byte[] _protobufBytes = null!;

    [GlobalSetup]
    public void Setup()
    {
        var election = BenchmarkElection.Create();
        _ballot = election.EncryptBallot(0);
        _manifest = election.Manifest;
        _jsonBytes = RecordItemCodec.EncodeBallotJson(_ballot, _manifest);
        _protobufBytes = RecordItemCodec.EncodeBallot(_ballot, _manifest);
    }

    [Benchmark(Baseline = true)]
    public byte[] JsonSerialize() => RecordItemCodec.EncodeBallotJson(_ballot, _manifest);

    [Benchmark]
    public EncryptedBallot JsonDeserialize() => RecordItemCodec.DecodeBallotJson(_jsonBytes, _manifest, BenchmarkElection.DeviceId);

    [Benchmark]
    public byte[] ProtobufSerialize() => RecordItemCodec.EncodeBallot(_ballot, _manifest);

    [Benchmark]
    public EncryptedBallot ProtobufDeserialize() => RecordItemCodec.DecodeBallot(_protobufBytes, _manifest, BenchmarkElection.DeviceId);
}
