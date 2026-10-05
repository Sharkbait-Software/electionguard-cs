using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Tally;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// AddBallot and PartialDecrypt, split out of TallyBenchmarks because neither one scales with
/// ballot count: AddBallot's cost is a fixed number of modular multiplications per choice on the
/// Weight==1 path, and TallyGuardian.Commit iterates contests/choices, not ballots. No [Params]
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

    /// <summary>
    /// One guardian's first decryption round: M_i, the commitment pair (a_i, b_i) and d_i for every
    /// choice, with guardians 1 and 2 participating.
    /// </summary>
    [Benchmark]
    public PartialTallyDecryption PartialDecrypt()
    {
        var guardians = _election.Guardians.Guardians;
        return new TallyGuardian(guardians[0].Index, _election.Guardians.SecretShares[guardians[0].Index])
            .Commit(_tally, _election.EncryptionRecord, [guardians[0].Index, guardians[1].Index]);
    }
}
