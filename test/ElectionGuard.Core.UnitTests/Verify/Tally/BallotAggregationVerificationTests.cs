using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.TestFixtures;
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
    public void Verify_TamperedA_ThrowsPlainException_NotVerificationFailedException()
    {
        var scenario = Build();
        scenario.Tally.Contests["contest-1"].Choices["choice-1"].A = new IntegerModP(999999);

        var verification = new BallotAggregationVerification();

        var exception = Assert.Throws<Exception>(() => verification.Verify(scenario.Ballots, scenario.Manifest, scenario.Tally));

        // Verification 9 is the one Verify class with no SubSection field: it throws plain
        // System.Exception, not VerificationFailedException, unlike Verifications 1-8. Assert the
        // exact type (not just assignability) to pin this down, and don't attempt to assert a
        // SubSection since VerificationFailedException.SubSection doesn't exist on this type.
        Assert.IsType<Exception>(exception);
        Assert.IsNotType<VerificationFailedException>(exception);
    }

    [Fact]
    public void Verify_TamperedB_ThrowsPlainException_NotVerificationFailedException()
    {
        var scenario = Build();
        scenario.Tally.Contests["contest-1"].Choices["choice-2"].B = new IntegerModP(999999);

        var verification = new BallotAggregationVerification();

        var exception = Assert.Throws<Exception>(() => verification.Verify(scenario.Ballots, scenario.Manifest, scenario.Tally));

        Assert.IsType<Exception>(exception);
        Assert.IsNotType<VerificationFailedException>(exception);
    }
}
