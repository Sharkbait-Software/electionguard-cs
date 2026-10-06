using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Tally;

/// <summary>
/// Stage S5 (G29, G16/G10): every supplemental field a contest declares is aggregated like an
/// option, decrypted with its own proof under its own option index, and covered by Verifications 9,
/// 10 and 11; each has its own decryption bound.
/// </summary>
public class SupplementalFieldTallyTests
{
    private const string DeviceId = "device-1";

    public SupplementalFieldTallyTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private sealed record Election(
        Manifest Manifest,
        EncryptionRecord Record,
        VotingDeviceInformationHash DeviceHash,
        ElectionFixtureBuilder.GuardianSetResult GuardianSet);

    private static Election Build(int selectionLimit, int optionSelectionLimit, int writeInFields = 2)
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(
            optionSelectionLimit: optionSelectionLimit,
            selectionLimit: selectionLimit,
            supplementalFields: ElectionFixtureBuilder.AllSupplementalFields,
            writeInFieldCount: writeInFields);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        return new Election(manifest, records.EncryptionRecord, new VotingDeviceInformationHash(records.ExtendedBaseHash, DeviceId), guardianSet);
    }

    private static Ballot Plaintext(Election election, string id, int choice1, int choice2, int writeIns = 0) =>
        ElectionFixtureBuilder.CreateBallot(
            election.Manifest,
            ballotId: id,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = choice1, ["choice-2"] = choice2 },
            numWriteinsSelected: writeIns);

    /// <summary>
    /// Encrypts the ballots, accumulating the expected tally from each BEFORE it is encrypted (the
    /// encryptor zeroes an overvoted contest in place), and tallies them.
    /// </summary>
    private static (List<EncryptedBallot> Ballots, EncryptedTally Tally, ExpectedTally Expected) EncryptAndTally(Election election, params Ballot[] plaintexts)
    {
        var accumulator = new ExpectedTallyAccumulator(election.Manifest);
        var ballots = new List<EncryptedBallot>();
        foreach (var plaintext in plaintexts)
        {
            accumulator.Add(plaintext);
            ballots.Add(ElectionFixtureBuilder.CreateEncryptedBallot(election.Record, DeviceId, election.DeviceHash, plaintext));
        }

        return (ballots, ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, [.. ballots]), accumulator.Build());
    }

    [Fact]
    public void Decrypt_EverySupplementalFieldTotal_MatchesTheIndependentlyAccumulatedTally_AndVerifies()
    {
        // L = 2, R = 2, two write-in fields (which count toward the limit, user decision Q13).
        var election = Build(selectionLimit: 2, optionSelectionLimit: 2);
        var (ballots, tally, expected) = EncryptAndTally(election,
            Plaintext(election, "full", 1, 1),
            Plaintext(election, "null", 0, 0),
            Plaintext(election, "sum-over", 2, 1),          // 3 > L: overvote
            Plaintext(election, "option-over", 3, 0),       // 3 > R: overvote
            Plaintext(election, "write-in-full", 1, 0, 1),  // 1 + 1 = L
            Plaintext(election, "write-in-only", 0, 0, 1),  // 1 < L: an undervote, not a null vote
            Plaintext(election, "write-in-over", 1, 0, 2)); // 1 + 2 > L: overvote

        var decrypted = ElectionFixtureBuilder.DecryptTally(election.GuardianSet, tally, election.Record);
        var contest = decrypted.Contests["contest-1"];
        var counters = expected.GetCounters("contest-1");

        Assert.Equal(expected.GetVotes("contest-1", "choice-1"), contest.Choices["choice-1"].VoteCount);
        Assert.Equal(expected.GetVotes("contest-1", "choice-2"), contest.Choices["choice-2"].VoteCount);
        foreach (var field in election.Manifest.Contests[0].SupplementalFields)
        {
            Assert.Equal(counters.Get(field.Kind), contest.Choices[field.Id].VoteCount);
            Assert.Equal(field.Index, contest.Choices[field.Id].ChoiceIndex);
        }

        // Hand-checked against §3.3.9 and user decisions Q11-Q15: 3 overvotes; 1 null vote;
        // undervotes on null and write-in-only (an overvote is not an undervote, Q11); difference
        // 2 + 1 (0 on each overvote, since s + w + L*overvote + u = L); write-ins 1 + 1 (0 on an
        // overvote, Q12).
        Assert.Equal([3, 1, 2, 3, 2], new[]
        {
            counters.Overvotes, counters.Nullvotes, counters.Undervotes, counters.UndervoteDifference, counters.WriteIns,
        });
        Assert.Equal(1 + 0 + 1, contest.Choices["choice-1"].VoteCount);

        new BallotAggregationVerification().Verify(ballots, election.Manifest, tally);
        new TallyDecryptionVerification().Verify(election.Record, tally, decrypted);
        new TallyContentsVerification().Verify(election.Manifest, decrypted, ballots);
    }

    [Fact]
    public void Decrypt_LOneROne_TwoIsAnOvervote_AndTheOptionBoundIsOne()
    {
        // The S4-noted G16/G10 interaction: with L = 1 and R = 2 a 2 is now an overvote (sum > L),
        // so no valid ballot gives an option more than min(R, L) = 1, and decryption searches [0, 1]
        // per ballot. Before S5, L * R = 2 let the 2 through with an invalid contest proof.
        var election = Build(selectionLimit: 1, optionSelectionLimit: 2);
        var (_, tally, _) = EncryptAndTally(election,
            Plaintext(election, "two", 2, 0),
            Plaintext(election, "one", 1, 0));

        Assert.Equal(2, tally.Contests["contest-1"].Choices["choice-1"].MaximumCount);
        var decrypted = ElectionFixtureBuilder.DecryptTally(election.GuardianSet, tally, election.Record);

        Assert.Equal(1, decrypted.Contests["contest-1"].Choices["choice-1"].VoteCount);
        Assert.Equal(1, decrypted.Contests["contest-1"].Choices["overvotes"].VoteCount);
    }

    [Theory]
    [InlineData(1, 1, 3)]
    [InlineData(3, 2, 1)]
    [InlineData(2, 3, 4)]
    public void MaximumCount_IsEachFieldsOwnRangeBound(int selectionLimit, int optionSelectionLimit, int writeInFields)
    {
        // The S4 hook EncryptedTally.MaximumOptionValue, per field: an indicator adds at most 1 per
        // ballot, the undervote difference count L, the write-in count the number of write-in fields,
        // an option min(R, L).
        var election = Build(selectionLimit, optionSelectionLimit, writeInFields: writeInFields);
        var (_, tally, _) = EncryptAndTally(election,
            Plaintext(election, "a", 0, 0),
            Plaintext(election, "b", 0, 0));
        var choices = tally.Contests["contest-1"].Choices;

        Assert.Equal(2 * Math.Min(selectionLimit, optionSelectionLimit), choices["choice-1"].MaximumCount);
        Assert.Equal(2, choices["overvotes"].MaximumCount);
        Assert.Equal(2, choices["null-votes"].MaximumCount);
        Assert.Equal(2, choices["undervotes"].MaximumCount);
        Assert.Equal(2 * selectionLimit, choices["undervote-difference"].MaximumCount);
        Assert.Equal(2 * writeInFields, choices["write-ins"].MaximumCount);
    }

    /// <summary>
    /// S5 review: Verification 9 compares every field's aggregate, not only the options'. Each
    /// claimed tally here is honest except for one supplemental field's A or B, so only the
    /// comparison over the fields can reject it (the key check passes: every label is present).
    /// </summary>
    [Theory]
    [InlineData("null-votes", true, "9.A")]
    [InlineData("undervote-difference", false, "9.B")]
    [InlineData("write-ins", true, "9.A")]
    [InlineData("overvotes", false, "9.B")]
    public void Verification9_TamperedSupplementalFieldAggregate_Fails(string fieldId, bool tamperA, string subSection)
    {
        var election = Build(selectionLimit: 2, optionSelectionLimit: 1);
        var (ballots, _, _) = EncryptAndTally(election, Plaintext(election, "a", 1, 0, 1), Plaintext(election, "b", 0, 0));

        var honest = ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, [.. ballots]);
        new BallotAggregationVerification().Verify(ballots, election.Manifest, honest);

        var claimed = ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, [.. ballots]);
        var aggregate = claimed.Contests["contest-1"].Choices[fieldId];
        if (tamperA)
        {
            aggregate.A = new IntegerModP(999999);
        }
        else
        {
            aggregate.B = new IntegerModP(999999);
        }

        var exception = Assert.Throws<VerificationFailedException>(() => new BallotAggregationVerification().Verify(ballots, election.Manifest, claimed));

        Assert.Equal(subSection, exception.SubSection);
        Assert.Contains($"choice {fieldId}", exception.Message);
    }

    [Fact]
    public void Verifications9To11_RejectATallyThatLeavesOutOrMislabelsAField()
    {
        var election = Build(selectionLimit: 1, optionSelectionLimit: 1);
        var (ballots, tally, _) = EncryptAndTally(election, Plaintext(election, "a", 1, 0), Plaintext(election, "b", 0, 0));
        var decrypted = ElectionFixtureBuilder.DecryptTally(election.GuardianSet, tally, election.Record);

        // V9: a claimed tally without the null-vote aggregate.
        var claimed = ElectionFixtureBuilder.CreateEncryptedTally(election.Manifest, [.. ballots]);
        claimed.Contests["contest-1"].Choices.Remove("null-votes");
        var v9 = Assert.Throws<VerificationFailedException>(() => new BallotAggregationVerification().Verify(ballots, election.Manifest, claimed));
        Assert.Equal("9.structure", v9.SubSection);

        // V10: a field published under another option index.
        var original = decrypted.Contests["contest-1"].Choices["write-ins"];
        decrypted.Contests["contest-1"].Choices["write-ins"] = new DecryptedTally.DecryptedChoice
        {
            ChoiceIndex = original.ChoiceIndex + 1,
            VoteCount = original.VoteCount,
            T = original.T,
            Challenge = original.Challenge,
            Response = original.Response,
        };
        var v10 = Assert.Throws<VerificationFailedException>(() => new TallyDecryptionVerification().Verify(election.Record, tally, decrypted));
        Assert.Equal("10.structure", v10.SubSection);
        decrypted.Contests["contest-1"].Choices["write-ins"] = original;

        // V11: a decrypted tally without a declared field (11.C), or with a field no one declared (11.B).
        var undervotes = decrypted.Contests["contest-1"].Choices["undervotes"];
        decrypted.Contests["contest-1"].Choices.Remove("undervotes");
        var v11C = Assert.Throws<VerificationFailedException>(() => new TallyContentsVerification().Verify(election.Manifest, decrypted, ballots));
        Assert.Equal("11.C", v11C.SubSection);

        decrypted.Contests["contest-1"].Choices["undervotes"] = undervotes;
        decrypted.Contests["contest-1"].Choices["overvote-difference"] = undervotes;
        var v11B = Assert.Throws<VerificationFailedException>(() => new TallyContentsVerification().Verify(election.Manifest, decrypted, ballots));
        Assert.Equal("11.B", v11B.SubSection);
    }
}
