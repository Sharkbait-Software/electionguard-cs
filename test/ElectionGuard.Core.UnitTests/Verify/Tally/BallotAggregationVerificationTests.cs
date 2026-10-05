using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Testing.Common;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Tally;

namespace ElectionGuard.Core.UnitTests.Verify.Tally;

public class BallotAggregationVerificationTests
{
    private sealed class Scenario
    {
        public required Manifest Manifest { get; init; }
        public required List<EncryptedBallot> Ballots { get; init; }
        public required EncryptedTally Tally { get; init; }
    }

    private static Scenario Build()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());

        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");

        var ballot1 = ElectionFixtureBuilder.CreateBallot(manifest, "ballot-1", new Dictionary<string, int>
        {
            ["choice-1"] = 1,
            ["choice-2"] = 0,
        });
        var ballot2 = ElectionFixtureBuilder.CreateBallot(manifest, "ballot-2", new Dictionary<string, int>
        {
            ["choice-1"] = 0,
            ["choice-2"] = 1,
        });

        var encryptedBallots = new List<EncryptedBallot>
        {
            ElectionFixtureBuilder.CreateEncryptedBallot(encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot1),
            ElectionFixtureBuilder.CreateEncryptedBallot(encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot2),
        };

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, encryptedBallots.ToArray());

        return new Scenario
        {
            Manifest = manifest,
            Ballots = encryptedBallots,
            Tally = tally,
        };
    }

    [Fact]
    public void Verify_ValidTally_DoesNotThrow()
    {
        var scenario = Build();
        var verification = new BallotAggregationVerification();

        var exception = Record.Exception(() => verification.Verify(scenario.Ballots, scenario.Manifest, scenario.Tally));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_TamperedA_Throws_SubSection9A()
    {
        var scenario = Build();
        scenario.Tally.Contests["contest-1"].Choices["choice-1"].A = new IntegerModP(999999);

        var verification = new BallotAggregationVerification();

        // G38: Verification 9 used to throw a plain System.Exception with no sub-section, which a
        // caller catching VerificationFailedException missed. It now reports 9.A like any other
        // verification reports its lettered checks.
        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(scenario.Ballots, scenario.Manifest, scenario.Tally));

        Assert.Equal("9.A", exception.SubSection);
    }

    [Fact]
    public void Verify_TamperedB_Throws_SubSection9B()
    {
        var scenario = Build();
        scenario.Tally.Contests["contest-1"].Choices["choice-2"].B = new IntegerModP(999999);

        var verification = new BallotAggregationVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(scenario.Ballots, scenario.Manifest, scenario.Tally));

        Assert.Equal("9.B", exception.SubSection);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    [InlineData(4)]
    public void Verify_ManyBallots_ValidTallyPassesAndAMissingBallotIsDetected(int maxDegreeOfParallelism)
    {
        // Enough ballots for EncryptedTally.AddBallots to split the recomputation across workers.
        // The scenario's two ballots repeat; aggregation does not care whether ballots are distinct.
        var scenario = Build();
        var ballots = Enumerable.Range(0, 20).SelectMany(_ => scenario.Ballots).ToList();
        var tally = ElectionFixtureBuilder.CreateEncryptedTally(scenario.Manifest, ballots.ToArray());
        var verification = new BallotAggregationVerification();

        Assert.Null(Record.Exception(() => verification.Verify(ballots, scenario.Manifest, tally, maxDegreeOfParallelism)));

        var missingOne = ballots.Skip(1).ToList();
        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(missingOne, scenario.Manifest, tally, maxDegreeOfParallelism));
        Assert.Equal("9.A", exception.SubSection);
    }
}
