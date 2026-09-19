using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Tally;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// AddBallot and PartialDecrypt, split out of TallyBenchmarks because neither one scales with
/// ballot count: AddBallot's cost is a fixed number of modular multiplications per choice on the
/// Weight==1 path, and TallyGuardian.Decrypt iterates contests/choices, not ballots. No [Params]
/// here on purpose -- there is nothing for a parameter to plot.
/// </summary>
[MemoryDiagnoser]
public class TallyAccumulationBenchmarks
{
    private BenchmarkElection _election = null!;
    private EncryptedBallot _ballot = null!;
    private EncryptedTally _tally = null!;

    [GlobalSetup]
    public void Setup()
    {
        _election = BenchmarkElection.Create();
        _ballot = _election.EncryptBallot(0);

        _tally = new EncryptedTally(_election.Manifest);
        _tally.AddBallot(_ballot);
    }

    /// <summary>
    /// Measures addition on an existing tally instance, not construction. Repeated invocations
    /// grow _tally's accumulated ciphertexts across the run; that is intentional and harmless,
    /// since AddBallot's cost is independent of how many ballots preceded it.
    /// </summary>
    [Benchmark]
    public void AddBallot() => _tally.AddBallot(_ballot);

    [Benchmark]
    public PartialTallyDecryption PartialDecrypt()
    {
        var guardian = _election.Guardians.Guardians[0];
        return new TallyGuardian(guardian.Index, _election.Guardians.SecretShares[guardian.Index]).Decrypt(_tally);
    }
}
