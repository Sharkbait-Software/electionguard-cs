using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.PreEncryption;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Tally;

/// <summary>
/// A guardian's view of the published record's cast ballots (user decision Q31, S9b): what it
/// holds, what it refuses to hold, and how a request's values match it.
/// </summary>
public class PublishedCastBallotsTests
{
    public PublishedCastBallotsTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static PreEncryptedElection Election => PreEncryptedElection.Get();

    private static EncryptedBallot Regular(string id, bool cast = true)
    {
        var election = Election;
        var deviceHash = new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "regular-device");
        var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(election.Record, "regular-device", deviceHash, election.Selections(id, [1], [2]));
        return cast ? ballot : Relabel(ballot, BallotStatus.Challenged);
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

    [Fact]
    public void FromRecord_HoldsCastBallotsOnly_RegularAndPreEncrypted()
    {
        var election = Election;
        var cast = Regular("r-1");
        var challenged = Regular("r-2", cast: false);
        var (_, preEncrypted) = election.Cast("p-1", [2], [1]);

        var view = PublishedCastBallots.FromRecord(election.Record.ExtendedBaseHash, [cast, challenged, preEncrypted]);

        Assert.Equal(2, view.Count);
        Assert.Equal(CastBallotMatch.SelectionEncryptionIdentifier | CastBallotMatch.SelectionEncryptionIdentifierHash | CastBallotMatch.EncryptedBallotNonce,
            view.Match(preEncrypted.SelectionEncryptionIdentifier, preEncrypted.SelectionEncryptionIdentifierHash, preEncrypted.EncryptedBallotNonce.C0));
        Assert.Equal(CastBallotMatch.None,
            view.Match(challenged.SelectionEncryptionIdentifier, challenged.SelectionEncryptionIdentifierHash, challenged.EncryptedBallotNonce.C0));
    }

    /// <summary>Each value is matched on its own, by content (copies of the bytes, not the same arrays).</summary>
    [Fact]
    public void Match_ReportsEachMatchingValue_ByContent()
    {
        var cast = Regular("r-1");
        var other = Regular("r-2");
        var view = new PublishedCastBallots(Election.Record.ExtendedBaseHash);
        view.Add(cast);

        var identifier = new SelectionEncryptionIdentifier(((byte[])cast.SelectionEncryptionIdentifier).ToArray());
        var identifierHash = new SelectionEncryptionIdentifierHash(((byte[])cast.SelectionEncryptionIdentifierHash).ToArray());
        Assert.Equal(CastBallotMatch.SelectionEncryptionIdentifier, view.Match(identifier, other.SelectionEncryptionIdentifierHash, other.EncryptedBallotNonce.C0));
        Assert.Equal(CastBallotMatch.SelectionEncryptionIdentifierHash, view.Match(other.SelectionEncryptionIdentifier, identifierHash, other.EncryptedBallotNonce.C0));
        Assert.Equal(CastBallotMatch.EncryptedBallotNonce, view.Match(other.SelectionEncryptionIdentifier, other.SelectionEncryptionIdentifierHash, new IntegerModP(cast.EncryptedBallotNonce.C0.ToByteArray())));
        Assert.Equal(CastBallotMatch.None, view.Match(other.SelectionEncryptionIdentifier, other.SelectionEncryptionIdentifierHash, other.EncryptedBallotNonce.C0));

        // Missing or wrong-length values match nothing (the structure check refuses them afterwards).
        Assert.Equal(CastBallotMatch.None, view.Match(default, null, null));
        Assert.Equal(CastBallotMatch.None, view.Match(new SelectionEncryptionIdentifier(new byte[31]), new SelectionEncryptionIdentifierHash(new byte[33]), null));
    }

    [Fact]
    public void Add_BallotNotRecordedAsCast_OrNotOfThisElection_Throws()
    {
        var election = Election;
        var view = new PublishedCastBallots(election.Record.ExtendedBaseHash);
        var cast = Regular("r-1");

        Assert.Contains("not as cast", Assert.Throws<ArgumentException>(() => view.Add(Regular("r-2", cast: false))).Message);
        Assert.Contains("not as cast", Assert.Throws<ArgumentException>(() => view.Add(Relabel(cast, BallotStatus.Unrecorded))).Message);
        Assert.Contains("not as cast", Assert.Throws<ArgumentException>(() => view.Add(Relabel(cast, BallotStatus.Spoiled))).Message);
        Assert.Contains("H_I", Assert.Throws<ArgumentException>(() => view.Add(Relabel(cast, BallotStatus.Cast, new SelectionEncryptionIdentifierHash(new byte[32])))).Message);
        Assert.Contains("H_I", Assert.Throws<ArgumentException>(() => new PublishedCastBallots(PreEncryptedElection.Get(ChainingMode.Simple).Record.ExtendedBaseHash).Add(cast)).Message);
        Assert.Equal(0, view.Count);

        view.Add(cast);
        view.Add(cast);
        Assert.Equal(1, view.Count);
    }
}
