using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Tally;
using ElectionGuard.Testing.Common;
using System.Collections.Concurrent;
using System.Text.Json;

namespace ElectionGuard.Core.UnitTests.PreEncryption;

/// <summary>
/// A small election that uses pre-encrypted ballots (§4), shared by the pre-encrypted record and
/// Verification 15-19 tests: contest-1 with three options and L = 1, contest-2 with four options and
/// L = 2, one ballot style listing both, Ω2 (four hex characters, so short codes practically never
/// collide), and a 3-of-2 guardian set. Ballots are made and recorded by the test-only
/// <see cref="PreEncryptedBallotFixtures"/> (the library has no encrypting or recording tool, user
/// decision Q35), which remembers each ballot's ξ_B here. Built once per chaining mode; the tests
/// only read it.
/// </summary>
public sealed class PreEncryptedElection
{
    public const string DeviceId = "pre-encrypted-device-1";
    public const string BallotStyleId = "style-1";

    private static readonly Lazy<PreEncryptedElection> NoChaining = new(() => new PreEncryptedElection(ChainingMode.None));
    private static readonly Lazy<PreEncryptedElection> SimpleChaining = new(() => new PreEncryptedElection(ChainingMode.Simple));

    public static PreEncryptedElection Get(ChainingMode chainingMode = ChainingMode.None) =>
        chainingMode == ChainingMode.None ? NoChaining.Value : SimpleChaining.Value;

    private PreEncryptedElection(ChainingMode chainingMode)
    {
        Manifest = CreateManifest(chainingMode);
        var manifestFile = ManifestSerializer.ToManifestFile(Manifest);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        Record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, Manifest, manifestFile).EncryptionRecord;
        _guardianSet = guardianSet;
        DeviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(Record.ExtendedBaseHash, DeviceId);
    }

    public Manifest Manifest { get; }
    public EncryptionRecord Record { get; }
    private readonly ElectionFixtureBuilder.GuardianSetResult _guardianSet;

    /// <summary>ξ_B of every ballot this election pre-encrypted, by id_B (hex).</summary>
    private readonly ConcurrentDictionary<string, BallotNonce> _ballotNonces = new(StringComparer.Ordinal);

    /// <summary>The decryption handles of the 3-of-2 guardian set.</summary>
    public List<TallyGuardian> Guardians => _guardianSet.Guardians
        .Select(x => new TallyGuardian(x.Index, _guardianSet.SecretShares[x.Index]))
        .ToList();

    /// <summary>A view of the published record with no cast ballot (user decision Q31).</summary>
    public PublishedCastBallots NoCastBallots => new(Record.ExtendedBaseHash);

    /// <summary>H_DI of <see cref="DeviceId"/> for pre-encrypted ballots (eq. 119).</summary>
    public VotingDeviceInformationHash DeviceHash { get; }

    public static Manifest CreateManifest(ChainingMode chainingMode) => new()
    {
        ElectionId = "pre-encrypted-election",
        Contests =
        [
            new Contest
            {
                Id = "contest-1",
                Name = "Contest 1",
                SelectionLimit = 1,
                OptionSelectionLimit = 1,
                Index = 1,
                Choices = Enumerable.Range(1, 3).Select(j => new Choice { Id = $"contest-1-option-{j}", Name = $"Option {j}", Index = j }).ToList(),
            },
            new Contest
            {
                Id = "contest-2",
                Name = "Contest 2",
                SelectionLimit = 2,
                OptionSelectionLimit = 1,
                Index = 2,
                Choices = Enumerable.Range(1, 4).Select(j => new Choice { Id = $"contest-2-option-{j}", Name = $"Option {j}", Index = j }).ToList(),
            },
        ],
        BallotStyles = [new BallotStyle { Id = BallotStyleId, Name = "Style 1", ContestIds = ["contest-1", "contest-2"] }],
        ChainingMode = chainingMode,
        HashTrimmingFunction = HashTrimmingFunction.FourHex,
    };

    /// <summary>A fresh pre-encrypted ballot of <see cref="DeviceId"/> with unique short codes; its ξ_B is remembered.</summary>
    public PreEncryptedBallot PreEncrypt(string ballotId, ConfirmationCode? previousConfirmationCode = null)
    {
        var (ballot, ballotNonce) = PreEncryptedBallotFixtures.PreEncrypt(Record, DeviceId, ballotId, BallotStyleId, previousConfirmationCode);
        _ballotNonces[Convert.ToHexString(ballot.SelectionEncryptionIdentifier)] = ballotNonce;
        return ballot;
    }

    /// <summary>
    /// ξ_B of <paramref name="ballot"/>, which this election pre-encrypted (looked up by id_B, so a
    /// copy or a deserialized ballot works too). It stands in for the ξ_B a recording tool obtains
    /// (§4.3.1), which is outside this library.
    /// </summary>
    public BallotNonce BallotNonceOf(PreEncryptedBallot ballot) => _ballotNonces[Convert.ToHexString(ballot.SelectionEncryptionIdentifier)];

    /// <summary>
    /// The voter's selections as a plaintext ballot: the options of contest-1 and contest-2 given
    /// (by option number) are selected, every other option is not.
    /// </summary>
    public Ballot Selections(string ballotId, int[] contest1, int[] contest2) => new()
    {
        Id = ballotId,
        BallotStyleId = BallotStyleId,
        Contests =
        [
            new BallotContest
            {
                Id = "contest-1",
                Choices = Enumerable.Range(1, 3).Select(j => new BallotChoice { Id = $"contest-1-option-{j}", SelectionValue = contest1.Contains(j) ? 1 : 0 }).ToList(),
            },
            new BallotContest
            {
                Id = "contest-2",
                Choices = Enumerable.Range(1, 4).Select(j => new BallotChoice { Id = $"contest-2-option-{j}", SelectionValue = contest2.Contains(j) ? 1 : 0 }).ToList(),
            },
        ],
    };

    /// <summary>Pre-encrypts a ballot and records it as cast with the given selections.</summary>
    public (PreEncryptedBallot PreEncrypted, EncryptedBallot Cast) Cast(string ballotId, int[] contest1, int[] contest2, ConfirmationCode? previousConfirmationCode = null)
    {
        var ballot = PreEncrypt(ballotId, previousConfirmationCode);
        var cast = PreEncryptedBallotFixtures.RecordCast(Record, ballot, BallotNonceOf(ballot), Selections(ballotId, contest1, contest2));
        return (ballot, cast);
    }

    /// <summary>Pre-encrypts a ballot and records it as uncast.</summary>
    public PreEncryptedUncastBallot Uncast(string ballotId, bool releaseBallotNonce = false, ConfirmationCode? previousConfirmationCode = null)
    {
        var ballot = PreEncrypt(ballotId, previousConfirmationCode);
        return PreEncryptedBallotFixtures.RecordUncast(Record, ballot, BallotNonceOf(ballot), releaseBallotNonce);
    }
}
