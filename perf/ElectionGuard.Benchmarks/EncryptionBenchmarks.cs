using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Benchmarks;

[MemoryDiagnoser]
public class EncryptionBenchmarks
{
    /// <summary>
    /// [IterationSetup] forces BenchmarkDotNet's InvocationCount and UnrollFactor to 1, so PickNext
    /// runs exactly once per encrypted ballot and every invocation of EncryptBallot below measures
    /// exactly one Encrypt call -- no generation, no BallotGenerator construction (which re-runs a
    /// duplicate-choice-id validation over every contest), inside the timed method.
    ///
    /// 20,000 pre-generated ballots is comfortably more than any BDN job (default/short/medium/long)
    /// invokes for a ~35 ms operation. If a run ever does exhaust the pool, PickNext throws rather
    /// than silently wrapping around: BallotEncryptor mutates an overvoted ballot's selections in
    /// place, so re-encrypting an already-used instance would quietly encrypt a different (already-
    /// zeroed) workload the second time around instead of failing loudly.
    /// </summary>
    private const int PoolSize = 20_000;

    private BallotEncryptor _encryptor = null!;
    private Ballot[] _pool = null!;
    private int _index;
    private Ballot _current = null!;

    [GlobalSetup]
    public void Setup()
    {
        var election = BenchmarkElection.Create();
        _encryptor = election.CreateEncryptor();

        // Generation (untimed here) reproduces BenchmarkElection's manifest, which enables overvotes
        // and undervotes, so the pool is the same mixed workload EncryptBallot always measured --
        // just generated up front instead of inline, and never repeated for the same ballot.
        _pool = new Ballot[PoolSize];
        for (int i = 0; i < PoolSize; i++)
        {
            _pool[i] = election.GenerateBallot(i);
        }
    }

    [IterationSetup]
    public void PickNext()
    {
        if (_index >= _pool.Length)
        {
            throw new InvalidOperationException(
                $"EncryptionBenchmarks exhausted its {PoolSize}-ballot pool. Increase PoolSize -- a " +
                "ballot cannot be reused because BallotEncryptor mutates an overvoted ballot's " +
                "selections in place, so re-encrypting one would silently change the workload.");
        }

        _current = _pool[_index++];
    }

    /// <summary>
    /// Encrypts one pre-generated, never-before-encrypted ballot. Selection is done in
    /// [IterationSetup], not here, so this measures Encrypt alone -- not generation, and not a
    /// mix of two different code paths averaged into one number.
    /// </summary>
    [Benchmark]
    public EncryptedBallot EncryptBallot() => _encryptor.Encrypt(_current, null);
}
