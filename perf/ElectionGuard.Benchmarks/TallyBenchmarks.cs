using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Tally;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// TallyAdmin.Decrypt's discrete-log search is baby-step giant-step over [0, BallotsCast], so its cost
/// grows with the square root of the ballot count; parameterising by ballot count plots that curve
/// directly. The fixed cost per choice (combining partial decryptions) dominates at these sizes.
/// </summary>
[MemoryDiagnoser]
public class TallyBenchmarks
{
    private BenchmarkElection _election = null!;
    private EncryptedBallot _ballot = null!;
    private EncryptedTally _tally = null!;
    private List<PartialTallyDecryption> _partials = null!;

    [Params(10, 100, 1000)]
    public int BallotsCast { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _election = BenchmarkElection.Create();
        _ballot = _election.EncryptBallot(0);

        _tally = new EncryptedTally(_election.Manifest);
        for (int i = 0; i < BallotsCast; i++)
        {
            _tally.AddBallot(_ballot);
        }

        _partials = _election.Guardians.Guardians
            .Take(2)
            .Select(guardian =>
                new TallyGuardian(guardian.Index, _election.Guardians.SecretShares[guardian.Index]).Decrypt(_tally))
            .ToList();
    }

    [Benchmark]
    public DecryptedTally CombineAndRecoverPlaintext() =>
        new TallyAdmin().Decrypt(_partials, _tally, _election.Guardians.ElectionPublicKeys);
}
