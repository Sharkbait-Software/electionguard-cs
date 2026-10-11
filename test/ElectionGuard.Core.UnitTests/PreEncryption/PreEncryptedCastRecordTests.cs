using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.PreEncryption;

/// <summary>
/// The published records of pre-encrypted ballots (§4.3, §4.4), as the test-only
/// <see cref="PreEncryptedBallotFixtures"/> builds them from the library's primitives (the library has
/// no recording tool, user decision Q35): cast records that verify and tally with regular ballots, and
/// uncast records that open. Also pins the known exposure of a printed ballot not yet recorded on the
/// challenged-ballot nonce path (S9b-1).
/// </summary>
public class PreEncryptedCastRecordTests
{
    public PreEncryptedCastRecordTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static PreEncryptedElection Election => PreEncryptedElection.Get();

    /// <summary>The plaintext σ of each component of a cast ballot's combined vector, from its summed nonce.</summary>
    private static int[] Plaintexts(EncryptedContest contest, EncryptionRecord record) => contest.Choices
        .Select(x =>
        {
            var gToNonce = MontgomeryModP.PowModP(record.ElectionPublicKeys.VoteEncryptionKey, x.EncryptionNonce!.Value);
            Assert.Equal(MontgomeryModP.PowModP(EGParameters.G, x.EncryptionNonce!.Value), x.Alpha);
            return x.Beta == gToNonce ? 0 : x.Beta == gToNonce * record.ElectionPublicKeys.VoteEncryptionKey ? 1 : -1;
        })
        .ToArray();

    [Fact]
    public void RecordCast_CombinesTheSelectedVectors_AndEveryBallotVerificationAccepts()
    {
        var election = Election;
        var (preEncrypted, cast) = election.Cast("cast-1", [2], [1, 4]);

        Assert.True(cast.IsPreEncrypted);
        Assert.Equal(BallotStatus.Cast, cast.Status);
        Assert.Equal(1, cast.Weight);
        Assert.Equal(preEncrypted.ConfirmationCode, cast.ConfirmationCode);
        Assert.Equal(preEncrypted.ChainingField, cast.ChainingField);
        Assert.Equal(preEncrypted.Contests.Select(x => x.ContestHash), cast.Contests.Select(x => x.ContestHash));
        Assert.Equal([0, 1, 0], Plaintexts(cast.Contests[0], election.Record));
        Assert.Equal([1, 0, 0, 1], Plaintexts(cast.Contests[1], election.Record));

        new SelectionEncryptionIdentifierVerification().Verify(cast.SelectionEncryptionIdentifier, cast.SelectionEncryptionIdentifierHash, election.Record.ExtendedBaseHash);
        new SelectionEncryptionsWellFormedVerification().Verify(cast, election.Record);
        new AdherenceToVoteLimitsVerification().Verify(cast, election.Record);
        new SelectionVectorAccumulationVerification().Verify(cast, election.Record);
        new PreEncryptedConfirmationCodeVerification().Verify(cast, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(cast, election.Record);
    }

    [Fact]
    public void RecordCast_PublishesEverySelectionHash_TheSelectedVectorsAndTheirShortCodes_AndNoOptionLabel()
    {
        var election = Election;
        var (preEncrypted, cast) = election.Cast("cast-1", [3], [2, 3]);

        for (int i = 0; i < cast.Contests.Count; i++)
        {
            var record = cast.PreEncryptedContests![i];
            var contest = preEncrypted.Contests[i];
            Assert.Equal(contest.ContestId, record.ContestId);

            // §4.4: every selection hash, null vectors included, sorted numerically.
            Assert.Equal(contest.Selections.Select(x => x.SelectionHash).Order(), record.SelectionHashes);

            // The selected vectors, sorted by hash, with their published (α, β) and short codes,
            // and no nonce.
            Assert.Equal(record.SelectedVectors.Select(x => x.SelectionHash).Order(), record.SelectedVectors.Select(x => x.SelectionHash));
            foreach (var selected in record.SelectedVectors)
            {
                var source = contest.Selections.Single(x => x.SelectionHash == selected.SelectionHash);
                Assert.NotNull(source.ChoiceId);
                Assert.Equal(source.ShortCode, selected.ShortCode);
                Assert.Equal(source.Vector.Select(x => (x.Alpha, x.Beta)), selected.Vector.Select(x => (x.Alpha, x.Beta)));
                Assert.All(selected.Vector, x => Assert.Null(x.EncryptionNonce));
            }
        }

        // The selected vectors are the voter's: option 3 of contest-1, options 2 and 3 of contest-2.
        Assert.Equal(["contest-1-option-3"], SelectedLabels(preEncrypted, cast, 0));
        Assert.Equal(["contest-2-option-2", "contest-2-option-3"], SelectedLabels(preEncrypted, cast, 1));
    }

    private static string[] SelectedLabels(PreEncryptedBallot preEncrypted, EncryptedBallot cast, int contest) =>
        cast.PreEncryptedContests![contest].SelectedVectors
            .Select(v => preEncrypted.Contests[contest].Selections.Single(x => x.SelectionHash == v.SelectionHash).ChoiceId!)
            .Order()
            .ToArray();

    /// <summary>
    /// An undervote is padded with the contest's first null vectors, so the record always shows L
    /// short codes (§4.1.5: "the use of null short codes allows the election record to not reveal
    /// undervotes"); the combined vector still encrypts only the voter's selections.
    /// </summary>
    [Theory]
    [InlineData(new int[0], new int[0])]
    [InlineData(new[] { 1 }, new[] { 4 })]
    public void RecordCast_Undervote_IsPaddedWithTheFirstNullVectors(int[] contest1, int[] contest2)
    {
        var election = Election;
        var (preEncrypted, cast) = election.Cast("undervote", contest1, contest2);

        for (int i = 0; i < 2; i++)
        {
            var contest = preEncrypted.Contests[i];
            int limit = election.Manifest.Contests[i].SelectionLimit;
            int selections = i == 0 ? contest1.Length : contest2.Length;
            var selected = cast.PreEncryptedContests![i].SelectedVectors
                .Select(v => contest.Selections.Single(x => x.SelectionHash == v.SelectionHash))
                .ToList();

            Assert.Equal(limit, selected.Count);
            Assert.Equal(
                contest.Selections.Where(x => x.IsNullVote).Take(limit - selections).Select(x => x.SelectionIndex).Order(),
                selected.Where(x => x.IsNullVote).Select(x => x.SelectionIndex).Order());
        }

        Assert.Equal(Enumerable.Range(1, 3).Select(j => contest1.Contains(j) ? 1 : 0), Plaintexts(cast.Contests[0], election.Record));
        Assert.Equal(Enumerable.Range(1, 4).Select(j => contest2.Contains(j) ? 1 : 0), Plaintexts(cast.Contests[1], election.Record));
        new AdherenceToVoteLimitsVerification().Verify(cast, election.Record);
        new SelectionVectorAccumulationVerification().Verify(cast, election.Record);
        new PreEncryptedConfirmationCodeVerification().Verify(cast, election.DeviceHash, election.Record, null);
    }

    /// <summary>
    /// p.64: "Verification 8 is only used for regular ElectionGuard ballots". A cast pre-encrypted
    /// ballot is refused, not reported as a wrong hash.
    /// </summary>
    [Fact]
    public void Verification8_CastPreEncryptedBallot_IsRefused()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1]);

        var exception = Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(cast, election.Record));

        Assert.Equal("8.structure", exception.SubSection);
    }

    /// <summary>
    /// "Ordinary and pre-encrypted ballots can be tallied together" (§4): regular and cast
    /// pre-encrypted ballots aggregate into one tally that Verifications 9, 10 and 11 accept and that
    /// decrypts to the sum of both kinds' selections. An uncast pre-encrypted ballot is not tallied.
    /// </summary>
    [Fact]
    public void Tally_MixedRegularAndPreEncryptedBallots_DecryptsToTheSumOfTheirSelections()
    {
        var election = Election;
        var record = election.Record;
        var regularDeviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "regular-device");
        var regular = new[]
        {
            ElectionFixtureBuilder.CreateEncryptedBallot(record, "regular-device", regularDeviceHash, election.Selections("regular-1", [1], [1, 2])),
            ElectionFixtureBuilder.CreateEncryptedBallot(record, "regular-device", regularDeviceHash, election.Selections("regular-2", [2], [])),
        };
        var cast = new[]
        {
            election.Cast("pre-1", [1], [2, 3]).Cast,
            election.Cast("pre-2", [3], [4]).Cast,
            election.Cast("pre-3", [], []).Cast,
        };
        var ballots = regular.Concat(cast).ToList();

        var tally = new EncryptedTally(election.Manifest);
        tally.AddBallots(ballots);
        new BallotAggregationVerification().Verify(ballots, election.Manifest, tally);
        var decrypted = new TallyAdmin().Decrypt(election.Guardians, tally, record);
        new TallyDecryptionVerification().Verify(record, tally, decrypted);
        new TallyContentsVerification().Verify(election.Manifest, decrypted, ballots);

        Assert.Equal(5, tally.BallotsCast);
        Assert.Equal([2, 1, 1], Enumerable.Range(1, 3).Select(j => decrypted.Contests["contest-1"].Choices[$"contest-1-option-{j}"].VoteCount));
        Assert.Equal([1, 2, 1, 1], Enumerable.Range(1, 4).Select(j => decrypted.Contests["contest-2"].Choices[$"contest-2-option-{j}"].VoteCount));
    }

    [Fact]
    public void RecordUncast_ReleasesEveryEncryptionNonce_AndVerifications16To19Accept()
    {
        var election = Election;
        var uncast = election.Uncast("uncast-1");

        Assert.Null(uncast.BallotNonce);
        Assert.Equal(uncast.Ballot.Contests.Select(x => x.ContestId), uncast.Contests.Select(x => x.ContestId));
        for (int i = 0; i < uncast.Contests.Count; i++)
        {
            var contest = uncast.Ballot.Contests[i];
            Assert.Equal(contest.Selections.Select(x => x.SelectionIndex), uncast.Contests[i].Selections.Select(x => x.SelectionIndex));
            for (int j = 0; j < contest.Selections.Count; j++)
            {
                var nonces = uncast.Contests[i].Selections[j].Nonces;
                Assert.Equal(contest.Selections[j].Vector.Select(x => x.Alpha), nonces.Select(x => MontgomeryModP.PowModP(EGParameters.G, x)));
            }
        }

        new PreEncryptedConfirmationCodeVerification().Verify(uncast.Ballot, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(uncast.Ballot, election.Record);
        new UncastBallotEncryptionVerification().Verify(uncast, election.Record);
        new UncastBallotContentVerification().Verify(election.Manifest, uncast);
    }

    [Fact]
    public void RecordUncast_ReleasingTheBallotNonce_PublishesTheDecryptedBallotNonce()
    {
        var election = Election;
        var ballot = election.PreEncrypt("uncast-1");
        var ballotNonce = election.BallotNonceOf(ballot);

        var uncast = PreEncryptedBallotFixtures.RecordUncast(election.Record, ballot, ballotNonce, releaseBallotNonce: true);

        Assert.Equal(ballotNonce.ToByteArray(), uncast.BallotNonce!.Value.ToByteArray());
        new UncastBallotEncryptionVerification().Verify(uncast, election.Record);
    }

    /// <summary>
    /// KNOWN EXPOSURE (S9b-1, open by design since S9c; user decisions Q33 and Q35, sign-off asked as
    /// S9c-R1 in the tracker): a printed pre-encrypted ballot that is not yet recorded is in no
    /// cast-ballot view, and its id_B, H_I and C_ξB are built as a regular ballot's (§4.2, "as shown
    /// in Section 3.3.4"). Wrapped in a made-up regular ballot marked challenged, they pass every
    /// guardian check on the challenged path (status, structure, H_I, eq. 38, the Q31 record check),
    /// and k shares give the printed ballot's ξ_B ahead of its voter. The administrator's
    /// <see cref="TallyAdmin.CombineChallengedBallot"/> publishes nothing (the wrapper's contests are
    /// not encrypted under that ξ_B), but whoever holds the shares does not need it. The guardians
    /// know nothing of pre-encrypted ballots before they are recorded, so keeping such requests from
    /// them is the deployment's job. If a later stage closes this, flip the test to assert the refusal.
    /// </summary>
    [Fact]
    public void DecryptBallotNonce_UnrecordedPreEncryptedBallotWrappedAsChallenged_OpensIt_KnownExposure_S9b_1()
    {
        var election = Election;
        var printed = election.PreEncrypt("printed");
        var deviceHash = new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "regular-device");
        var regular = ElectionFixtureBuilder.CreateEncryptedBallot(election.Record, "regular-device", deviceHash, election.Selections("regular-1", [2], [1, 4]));
        var wrapper = new EncryptedBallot
        {
            Id = printed.Id,
            BallotStyleId = regular.BallotStyleId,
            DeviceId = regular.DeviceId,
            SelectionEncryptionIdentifier = printed.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = printed.SelectionEncryptionIdentifierHash,
            Contests = regular.Contests,
            ConfirmationCode = regular.ConfirmationCode,
            ChainingField = regular.ChainingField,
            EncryptedBallotNonce = printed.EncryptedBallotNonce,
            Weight = regular.Weight,
            Status = BallotStatus.Challenged,
        };

        // Any 2 of the 3 guardians answer; nothing in the request or the record lets them refuse.
        var shares = election.Guardians.Take(2).Select(x => x.DecryptBallotNonce(wrapper, election.Record, election.NoCastBallots)).ToList();

        // β_B = ∏ m_j^{w_j} (eq. 108) and ξ_B = C_ξB,1 ⊕ k_1 (eqs. 35-37), from the public pieces.
        var participants = shares.Select(x => x.GuardianIndex).ToList();
        IntegerModP betaB = 1;
        foreach (var share in shares)
        {
            betaB *= MontgomeryModP.PowModP(share.Mi, TallyDecryptionHashes.LagrangeCoefficient(share.GuardianIndex, participants));
        }

        var recovered = BallotNonceEncryption.Decrypt(printed.SelectionEncryptionIdentifierHash, printed.EncryptedBallotNonce, betaB);

        Assert.Equal(election.BallotNonceOf(printed).ToByteArray(), recovered.ToByteArray());
        var regenerated = PreEncryptedBallotFixtures.PreEncrypt(election.Record, PreEncryptedElection.DeviceId, printed.Id, printed.BallotStyleId, printed.SelectionEncryptionIdentifier, recovered, null);
        Assert.Equal(printed.ConfirmationCode, regenerated.ConfirmationCode);
        Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().CombineChallengedBallot(wrapper, election.Record, shares));
    }
}
