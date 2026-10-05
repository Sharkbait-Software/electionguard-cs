using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Tally;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// TallyAdmin.Decrypt: the three-round verifiable decryption of §3.6.5 by k = 2 guardians, the
/// administrator's proof check, and the discrete-log search. The search is baby-step giant-step over
/// [0, the largest option's MaximumCount], which for these weight-1, R = 1 ballots is BallotsCast,
/// so its cost grows with the square root of the ballot count; parameterising by ballot count plots
/// that curve directly. The fixed cost per choice (partial decryptions, commitments, the proof)
/// dominates at these sizes.
/// </summary>
[MemoryDiagnoser]
public class TallyBenchmarks
{
    private BenchmarkElection _election = null!;
    private EncryptedBallot _ballot = null!;
    private EncryptedTally _tally = null!;
    private List<TallyGuardian> _guardians = null!;

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

        _guardians = ElectionFixtureBuilder.TallyGuardians(_election.Guardians, 2);
    }

    [Benchmark]
    public DecryptedTally DecryptWithProof() =>
        new TallyAdmin().Decrypt(_guardians, _tally, _election.EncryptionRecord);
}
