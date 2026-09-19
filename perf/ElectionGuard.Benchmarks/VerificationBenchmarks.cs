using BenchmarkDotNet.Attributes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify.Ballot;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// Verifications 5-8 over a single encrypted ballot. A verifier-only process is essentially these
/// four numbers multiplied by the ballot count, so this is the tier that sizes it.
/// </summary>
[MemoryDiagnoser]
public class VerificationBenchmarks
{
    /// <summary>
    /// SelectionEncryptionIdentifierVerification checks that identifiers are DISTINCT across the
    /// whole list -- a one-element list can never contain a duplicate, so benchmarking it over a
    /// single identifier (as this used to do) measures the cost of a check that never does its
    /// work. ScenarioRunner verifies one CHUNK at a time under streaming (its own comment notes the
    /// same one-element trap), so 500 matches the chunk size smoke.json actually uses in a real run
    /// -- "a few hundred" identifiers, not the whole scenario. The cost is presumed to scale with
    /// this count (HashSet construction is O(n)), so a different chunk size will read differently.
    /// </summary>
    private const int ChunkSize = 500;

    private BenchmarkElection _election = null!;
    private EncryptedBallot _ballot = null!;
    private List<SelectionEncryptionIdentifier> _identifiers = null!;

    [GlobalSetup]
    public void Setup()
    {
        _election = BenchmarkElection.Create();
        _ballot = _election.EncryptBallot(0);

        _identifiers = Enumerable.Range(0, ChunkSize)
            .Select(i => _election.EncryptBallot(i).SelectionEncryptionIdentifier)
            .ToList();
    }

    [Benchmark]
    public void Verification5_SelectionEncryptionIdentifiers_Chunk500() =>
        new SelectionEncryptionIdentifierVerification().Verify(_identifiers);

    [Benchmark]
    public void Verification6_SelectionEncryptionsWellFormed() =>
        new SelectionEncryptionsWellFormedVerification().Verify(_ballot, _election.EncryptionRecord);

    [Benchmark]
    public void Verification7_AdherenceToVoteLimits() =>
        new AdherenceToVoteLimitsVerification().Verify(_ballot, _election.EncryptionRecord);

    [Benchmark]
    public void Verification8_ConfirmationCode() =>
        new ConfirmationCodeVerification().Verify(_ballot, _election.DeviceHash, _election.EncryptionRecord, null);
}
