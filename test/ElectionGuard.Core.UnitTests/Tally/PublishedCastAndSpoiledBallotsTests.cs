using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.PreEncryption;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Tally;

/// <summary>
/// A guardian's view of the published record's cast and spoiled ballots (user decision Q31, S9b;
/// spoiled ballots added by "Refuse spoiled too", 2026-10-09): what it holds, what it refuses to
/// hold, and how a request's values match it, per status.
/// </summary>
public class PublishedCastAndSpoiledBallotsTests
{
    public PublishedCastAndSpoiledBallotsTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static PreEncryptedElection Election => PreEncryptedElection.Get();

    private static EncryptedBallot Regular(string id, BallotStatus status = BallotStatus.Cast)
    {
        var election = Election;
        var deviceHash = new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "regular-device");
        var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(election.Record, "regular-device", deviceHash, election.Selections(id, [1], [2]));
        return status == BallotStatus.Cast ? ballot : Relabel(ballot, status);
    }

    private static EncryptedBallot Relabel(EncryptedBallot ballot, BallotStatus status, SelectionEncryptionIdentifierHash? selectionHash = null) => new()
    {
        Id = ballot.Id,
        BallotStyleId = ballot.BallotStyleId,
        DeviceId = ballot.DeviceId,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = selectionHash ?? ballot.SelectionEncryptionIdentifierHash,
        Contests = ballot.Contests,
        ConfirmationCode = ballot.ConfirmationCode,
        ChainingField = ballot.ChainingField,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        Weight = ballot.Weight,
        PreEncryptedContests = ballot.PreEncryptedContests,
        Status = status,
    };

    private static PublishedBallotMatch MatchOf(IPublishedCastAndSpoiledBallots view, EncryptedBallot ballot) =>
        view.Match(ballot.SelectionEncryptionIdentifier, ballot.SelectionEncryptionIdentifierHash, ballot.EncryptedBallotNonce.C0);

    private const BallotValueMatch All = BallotValueMatch.SelectionEncryptionIdentifier | BallotValueMatch.SelectionEncryptionIdentifierHash | BallotValueMatch.EncryptedBallotNonce;

    [Fact]
    public void FromRecord_HoldsCastAndSpoiledBallots_RegularAndPreEncrypted_NotChallengedOnes()
    {
        var election = Election;
        var cast = Regular("r-1");
        var challenged = Regular("r-2", BallotStatus.Challenged);
        var spoiled = Regular("r-3", BallotStatus.Spoiled);
        var (_, preEncrypted) = election.Cast("p-1", [2], [1]);

        var view = PublishedCastAndSpoiledBallots.FromRecord(election.Record.ExtendedBaseHash, [cast, challenged, spoiled, preEncrypted]);

        Assert.Equal((2, 1), (view.CastCount, view.SpoiledCount));
        Assert.Equal(new PublishedBallotMatch(All, BallotValueMatch.None), MatchOf(view, preEncrypted));
        Assert.Equal(new PublishedBallotMatch(All, BallotValueMatch.None), MatchOf(view, cast));
        Assert.Equal(new PublishedBallotMatch(BallotValueMatch.None, All), MatchOf(view, spoiled));
        Assert.True(MatchOf(view, challenged).IsNone);
        Assert.Equal(PublishedBallotMatch.None, MatchOf(view, challenged));
    }

    /// <summary>
    /// A ballot of a published record always has a recorded status. One without (or with a value that
    /// is not a status) is refused rather than skipped, since skipping would leave it unprotected.
    /// </summary>
    [Theory]
    [InlineData(BallotStatus.Unrecorded)]
    [InlineData((BallotStatus)7)]
    public void FromRecord_BallotWithoutARecordedStatus_Throws(BallotStatus status)
    {
        var election = Election;
        Assert.Contains("no recorded status", Assert.Throws<ArgumentException>(
            () => PublishedCastAndSpoiledBallots.FromRecord(election.Record.ExtendedBaseHash, [Regular("r-1"), Relabel(Regular("r-2"), status)])).Message);
    }

    /// <summary>Each value is matched on its own, by content (copies of the bytes, not the same arrays), under the status it was added with.</summary>
    [Theory]
    [InlineData(BallotStatus.Cast)]
    [InlineData(BallotStatus.Spoiled)]
    public void Match_ReportsEachMatchingValue_ByContent_UnderItsStatus(BallotStatus status)
    {
        var held = Regular("r-1", status);
        var other = Regular("r-2");
        var view = new PublishedCastAndSpoiledBallots(Election.Record.ExtendedBaseHash);
        view.Add(held);
        PublishedBallotMatch Expect(BallotValueMatch values) => status == BallotStatus.Cast ? new(values, BallotValueMatch.None) : new(BallotValueMatch.None, values);

        var identifier = new SelectionEncryptionIdentifier(((byte[])held.SelectionEncryptionIdentifier).ToArray());
        var identifierHash = new SelectionEncryptionIdentifierHash(((byte[])held.SelectionEncryptionIdentifierHash).ToArray());
        Assert.Equal(Expect(BallotValueMatch.SelectionEncryptionIdentifier), view.Match(identifier, other.SelectionEncryptionIdentifierHash, other.EncryptedBallotNonce.C0));
        Assert.Equal(Expect(BallotValueMatch.SelectionEncryptionIdentifierHash), view.Match(other.SelectionEncryptionIdentifier, identifierHash, other.EncryptedBallotNonce.C0));
        Assert.Equal(Expect(BallotValueMatch.EncryptedBallotNonce), view.Match(other.SelectionEncryptionIdentifier, other.SelectionEncryptionIdentifierHash, new IntegerModP(held.EncryptedBallotNonce.C0.ToByteArray())));
        Assert.Equal(PublishedBallotMatch.None, view.Match(other.SelectionEncryptionIdentifier, other.SelectionEncryptionIdentifierHash, other.EncryptedBallotNonce.C0));

        // Missing or wrong-length values match nothing (the structure check refuses them afterwards).
        Assert.Equal(PublishedBallotMatch.None, view.Match(default, null, null));
        Assert.Equal(PublishedBallotMatch.None, view.Match(new SelectionEncryptionIdentifier(new byte[31]), new SelectionEncryptionIdentifierHash(new byte[33]), null));
    }

    [Fact]
    public void Add_BallotNotRecordedAsCastOrSpoiled_OrNotOfThisElection_Throws()
    {
        var election = Election;
        var view = new PublishedCastAndSpoiledBallots(election.Record.ExtendedBaseHash);
        var cast = Regular("r-1");

        Assert.Contains("not as cast or spoiled", Assert.Throws<ArgumentException>(() => view.Add(Regular("r-2", BallotStatus.Challenged))).Message);
        Assert.Contains("not as cast or spoiled", Assert.Throws<ArgumentException>(() => view.Add(Relabel(cast, BallotStatus.Unrecorded))).Message);
        Assert.Contains("H_I", Assert.Throws<ArgumentException>(() => view.Add(Relabel(cast, BallotStatus.Cast, new SelectionEncryptionIdentifierHash(new byte[32])))).Message);
        Assert.Contains("H_I", Assert.Throws<ArgumentException>(() => view.Add(Relabel(cast, BallotStatus.Spoiled, new SelectionEncryptionIdentifierHash(new byte[32])))).Message);
        Assert.Contains("H_I", Assert.Throws<ArgumentException>(() => new PublishedCastAndSpoiledBallots(PreEncryptedElection.Get(ChainingMode.Simple).Record.ExtendedBaseHash).Add(cast)).Message);
        Assert.Equal((0, 0), (view.CastCount, view.SpoiledCount));

        view.Add(cast);
        view.Add(cast);
        view.Add(Regular("r-3", BallotStatus.Spoiled));
        Assert.Equal((1, 1), (view.CastCount, view.SpoiledCount));
    }

    /// <summary>
    /// The record verifier fills the view from a sealed record's parsed items, whatever their
    /// verification findings (an item with a value out of range has no domain ballot, design §4.8):
    /// the raw id_B, H_I and C_ξB,0 bytes are held exactly as <see cref="PublishedCastAndSpoiledBallots.Add(EncryptedBallot)"/>
    /// holds the domain values, so a challenged copy of such a ballot is refused all the same.
    /// </summary>
    [Fact]
    public void Add_RawValues_MatchAsTheDomainBallotDoes()
    {
        var election = Election;
        var cast = Regular("r-raw-1");
        var spoiled = Regular("r-raw-2", BallotStatus.Spoiled);
        var view = new PublishedCastAndSpoiledBallots(election.Record.ExtendedBaseHash);

        view.Add(BallotStatus.Cast, (byte[])cast.SelectionEncryptionIdentifier, (byte[])cast.SelectionEncryptionIdentifierHash, cast.EncryptedBallotNonce.C0.ToByteArray());
        view.Add(BallotStatus.Spoiled, (byte[])spoiled.SelectionEncryptionIdentifier, (byte[])spoiled.SelectionEncryptionIdentifierHash, spoiled.EncryptedBallotNonce.C0.ToByteArray());

        Assert.Equal(new PublishedBallotMatch(All, BallotValueMatch.None), MatchOf(view, cast));
        Assert.Equal(new PublishedBallotMatch(BallotValueMatch.None, All), MatchOf(view, spoiled));
        Assert.Equal((1, 1), (view.CastCount, view.SpoiledCount));

        // A request for the cast ballot's nonce under its own values, relabelled challenged, is refused.
        var copy = Relabel(cast, BallotStatus.Challenged);
        Assert.Equal(BallotValueMatch.EncryptedBallotNonce, MatchOf(view, copy).Cast & BallotValueMatch.EncryptedBallotNonce);
    }

    /// <summary>
    /// Raw values are held as stored: an item without C_ξB still holds its id_B and H_I, and an H_I
    /// that is not H(H_E; 0x20, id_B) is held too (holding more only refuses more). Other statuses
    /// and widths are refused.
    /// </summary>
    [Fact]
    public void Add_RawValues_HeldAsStored_OtherStatusesAndWidthsRefused()
    {
        var election = Election;
        var cast = Regular("r-raw-3");
        byte[] identifier = cast.SelectionEncryptionIdentifier;
        byte[] identifierHash = cast.SelectionEncryptionIdentifierHash;
        var view = new PublishedCastAndSpoiledBallots(election.Record.ExtendedBaseHash);

        view.Add(BallotStatus.Cast, identifier, identifierHash, []);
        Assert.Equal(BallotValueMatch.SelectionEncryptionIdentifier | BallotValueMatch.SelectionEncryptionIdentifierHash, MatchOf(view, cast).Cast);

        byte[] unbound = new byte[32];
        view.Add(BallotStatus.Spoiled, new byte[32], unbound, new byte[512]);
        Assert.Equal(BallotValueMatch.SelectionEncryptionIdentifierHash, view.Match(new SelectionEncryptionIdentifier(new byte[31].Append((byte)1).ToArray()), new SelectionEncryptionIdentifierHash(unbound), null).Spoiled);

        Assert.Throws<ArgumentException>(() => view.Add(BallotStatus.Challenged, identifier, identifierHash, []));
        Assert.Throws<ArgumentException>(() => view.Add(BallotStatus.Unrecorded, identifier, identifierHash, []));
        Assert.Throws<ArgumentException>(() => view.Add(BallotStatus.Cast, identifier[..31], identifierHash, []));
        Assert.Throws<ArgumentException>(() => view.Add(BallotStatus.Cast, identifier, identifierHash, new byte[511]));
    }
}
