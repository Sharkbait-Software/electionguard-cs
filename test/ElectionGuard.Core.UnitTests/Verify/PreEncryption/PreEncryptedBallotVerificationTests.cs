using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Verify.PreEncryption;

/// <summary>
/// Verification 16 (confirmation codes of pre-encrypted ballots) and Verification 17 (short codes).
/// Each failing case tampers one published value and asserts the lettered sub-check that catches it.
/// </summary>
public class PreEncryptedBallotVerificationTests
{
    private const string DeviceId = "device-1";
    private const string BallotStyleId = "ballot-style-1";

    public PreEncryptedBallotVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static EncryptionRecord CreateEncryptionRecord(ChainingMode chainingMode = ChainingMode.None, int selectionLimit = 1)
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(
            chainingMode: chainingMode,
            selectionLimit: selectionLimit,
            hashTrimmingFunction: HashTrimmingFunction.LetterDigit);
        return ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
    }

    /// <summary>A pre-encrypted ballot of <see cref="DeviceId"/>, made by the test-only fixture (the library has no encrypting tool, user decision Q35).</summary>
    private static PreEncryptedBallot PreEncrypt(EncryptionRecord record, string ballotId, ConfirmationCode? previousConfirmationCode) =>
        PreEncryptedBallotFixtures.PreEncrypt(record, DeviceId, ballotId, BallotStyleId, previousConfirmationCode).Ballot;

    private static VotingDeviceInformationHash DeviceHash(EncryptionRecord record)
    {
        return VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, DeviceId);
    }

    private static PreEncryptedBallot ReplaceSelection(PreEncryptedBallot ballot, int index, Func<PreEncryptedSelection, PreEncryptedSelection> change)
    {
        var contest = ballot.Contests[0];
        var selections = contest.Selections.ToList();
        selections[index] = change(selections[index]);
        return ballot with { Contests = [contest with { Selections = selections }] };
    }

    // Verification 16

    [Fact]
    public void ConfirmationCode_ValidBallot_NoChaining_DoesNotThrow()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var ballot = PreEncrypt(record, "ballot-1", null);

        var exception = Record.Exception(() => new PreEncryptedConfirmationCodeVerification().Verify(ballot, DeviceHash(record), record, null));

        Assert.Null(exception);
    }

    [Fact]
    public void ConfirmationCode_ValidBallots_SimpleChaining_DoNotThrow()
    {
        var record = CreateEncryptionRecord(ChainingMode.Simple);
        var first = PreEncrypt(record, "ballot-1", null);
        var second = PreEncrypt(record, "ballot-2", first.ConfirmationCode);
        var verification = new PreEncryptedConfirmationCodeVerification();

        Assert.Null(Record.Exception(() => verification.Verify(first, DeviceHash(record), record, null)));
        Assert.Null(Record.Exception(() => verification.Verify(second, DeviceHash(record), record, first.ConfirmationCode)));
    }

    [Fact]
    public void ConfirmationCode_TamperedEncryption_Fails16A()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var tampered = ReplaceSelection(ballot, 1, s =>
        {
            var vector = s.Vector.ToList();
            vector[0] = vector[0] with { Alpha = vector[0].Alpha * new IntegerModP(EGParameters.G) };
            return s with { Vector = vector };
        });

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(tampered, DeviceHash(record), record, null));

        Assert.Equal("16.A", exception.SubSection);
    }

    [Fact]
    public void ConfirmationCode_TamperedSelectionHashMatchingItsVector_Fails16B()
    {
        // A selection hash recomputed from a different vector is self-consistent (16.A passes) but
        // no longer the hash the contest hash was computed from.
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var tampered = ReplaceSelection(ballot, 0, s =>
        {
            var vector = s.Vector.Reverse().ToList();
            return s with { Vector = vector, SelectionHash = new SelectionHash(ballot.SelectionEncryptionIdentifierHash, vector) };
        });

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(tampered, DeviceHash(record), record, null));

        Assert.Equal("16.B", exception.SubSection);
    }

    [Fact]
    public void ConfirmationCode_TamperedContestHash_Fails16B()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var tampered = ballot with { Contests = [ballot.Contests[0] with { ContestHash = new ContestHash(new byte[32]) }] };

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(tampered, DeviceHash(record), record, null));

        Assert.Equal("16.B", exception.SubSection);
    }

    [Fact]
    public void ConfirmationCode_TamperedConfirmationCode_Fails16C()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var tampered = ballot with { ConfirmationCode = new ConfirmationCode(new byte[32]) };

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(tampered, DeviceHash(record), record, null));

        Assert.Equal("16.C", exception.SubSection);
    }

    [Fact]
    public void ConfirmationCode_WrongPreviousConfirmationCode_Fails16F()
    {
        // The published chaining field and confirmation code are consistent (16.C), but not with the
        // predecessor the verifier knows for this device.
        var record = CreateEncryptionRecord(ChainingMode.Simple);
        var first = PreEncrypt(record, "ballot-1", null);
        var second = PreEncrypt(record, "ballot-2", first.ConfirmationCode);

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(second, DeviceHash(record), record, new ConfirmationCode(new byte[32])));

        Assert.Equal("16.F", exception.SubSection);
    }

    [Fact]
    public void ConfirmationCode_DeviceHashForAnotherDevice_Fails16D()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var otherDevice = VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, "device-2");
        // Recompute the published chaining-dependent values for the other device so 16.C passes.
        var chainingField = ChainingField.ForPreEncryptedBallots(ChainingMode.None, otherDevice, record.ExtendedBaseHash, null);
        var tampered = ballot with
        {
            ChainingField = chainingField,
            ConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(ballot.SelectionEncryptionIdentifierHash, ballot.Contests.Select(c => c.ContestHash), chainingField),
        };

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(tampered, otherDevice, record, null));

        Assert.Equal("16.D", exception.SubSection);
    }

    [Fact]
    public void ConfirmationCode_PublishedChainingFieldDiffers_NoChaining_Fails16E()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var simpleField = ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, DeviceHash(record), record.ExtendedBaseHash, null);
        var tampered = ballot with
        {
            ChainingField = simpleField,
            ConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(ballot.SelectionEncryptionIdentifierHash, ballot.Contests.Select(c => c.ContestHash), simpleField),
        };

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(tampered, DeviceHash(record), record, null));

        Assert.Equal("16.E", exception.SubSection);
    }

    [Fact]
    public void ConfirmationCode_PublishedChainingFieldDiffers_SimpleChaining_Fails16F()
    {
        var record = CreateEncryptionRecord(ChainingMode.Simple);
        var first = PreEncrypt(record, "ballot-1", null);
        var second = PreEncrypt(record, "ballot-2", first.ConfirmationCode);
        // Published as if it were the device's first ballot, though the verifier knows its predecessor.
        var firstBallotField = ChainingField.ForPreEncryptedBallots(ChainingMode.Simple, DeviceHash(record), record.ExtendedBaseHash, null);
        var tampered = second with
        {
            ChainingField = firstBallotField,
            ConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(second.SelectionEncryptionIdentifierHash, second.Contests.Select(c => c.ContestHash), firstBallotField),
        };

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(tampered, DeviceHash(record), record, first.ConfirmationCode));

        Assert.Equal("16.F", exception.SubSection);
    }

    // Verification 16 structure (G24): eqs. (113)-(115) give each contest with m options and
    // selection limit L exactly m option vectors, one per option, and L null vectors, each of m
    // encryptions; the ballot lists exactly its ballot style's contests (eq. 116). The fixture has
    // m = 2 and L = 2.

    private static PreEncryptedContest Contest(PreEncryptedBallot ballot) => ballot.Contests[0];

    private static PreEncryptedBallot WithSelections(PreEncryptedBallot ballot, Func<List<PreEncryptedSelection>, List<PreEncryptedSelection>> change) =>
        ballot with { Contests = [Contest(ballot) with { Selections = change(Contest(ballot).Selections.ToList()) }] };

    private static readonly Dictionary<string, Func<PreEncryptedBallot, PreEncryptedBallot>> PreEncryptedShapes = new()
    {
        ["missing null vector"] = b => WithSelections(b, s => s.Take(s.Count - 1).ToList()),
        ["extra null vector"] = b => WithSelections(b, s => [.. s, s[^1]]),
        ["option vector in place of a null vector"] = b => WithSelections(b, s => [s[0], s[1], s[2], s[0]]),
        ["null vector in place of an option vector"] = b => WithSelections(b, s => [s[2], s[1], s[2], s[3]]),
        ["option vector twice, one option missing"] = b => WithSelections(b, s => [s[0], s[0], s[2], s[3]]),
        ["vector for an option not in the manifest"] = b => WithSelections(b, s => [s[0] with { ChoiceId = "not-an-option" }, s[1], s[2], s[3]]),
        ["short vector"] = b => WithSelections(b, s => [s[0] with { Vector = s[0].Vector.Take(1).ToList() }, s[1], s[2], s[3]]),
        ["long vector"] = b => WithSelections(b, s => [s[0] with { Vector = [.. s[0].Vector, s[0].Vector[0]] }, s[1], s[2], s[3]]),
        ["duplicated contest"] = b => b with { Contests = [Contest(b), Contest(b)] },
        ["missing contest"] = b => b with { Contests = [] },
        ["contest not in the manifest"] = b => b with { Contests = [Contest(b) with { ContestId = "not-a-contest" }] },
        ["wrong contest index"] = b => b with { Contests = [Contest(b) with { ContestIndex = 2 }] },
        ["unknown ballot style"] = b => b with { BallotStyleId = "not-a-style" },
        // S9 review round 3: 16.D hashes S_device (eq. 119); without one it would throw
        // ArgumentNullException rather than report the ballot.
        ["null device id"] = b => b with { DeviceId = null! },
    };

    public static TheoryData<string> PreEncryptedShapeNames()
    {
        var data = new TheoryData<string>();
        foreach (var shape in PreEncryptedShapes.Keys)
        {
            data.Add(shape);
        }

        return data;
    }

    /// <summary>
    /// Every selection hash, contest hash and the confirmation code recomputed over the reshaped
    /// ballot, so that 16.A-16.C would all hold: only the structural check can reject it.
    /// </summary>
    private static PreEncryptedBallot Rehashed(PreEncryptedBallot ballot)
    {
        var hashI = ballot.SelectionEncryptionIdentifierHash;
        var contests = ballot.Contests
            .Select(contest =>
            {
                var selections = contest.Selections
                    .Select(s => s with { SelectionHash = new SelectionHash(hashI, s.Vector) })
                    .ToList();
                return contest with
                {
                    Selections = selections,
                    ContestHash = ContestHash.ForPreEncryptedContest(hashI, contest.ContestIndex, selections.Select(s => s.SelectionHash)),
                };
            })
            .ToList();
        return ballot with
        {
            Contests = contests,
            ConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(hashI, contests.Select(c => c.ContestHash), ballot.ChainingField),
        };
    }

    [Fact]
    public void ConfirmationCode_Rehashed_ValidBallot_StillPasses()
    {
        // Rehashed reproduces the generator's own hashes, so a shape it leaves alone passes.
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var ballot = PreEncrypt(record, "ballot-1", null);
        Assert.Equal(4, Contest(ballot).Selections.Count);

        var rehashed = Rehashed(ballot);

        Assert.Equal(ballot.ConfirmationCode, rehashed.ConfirmationCode);
        Assert.Null(Record.Exception(() => new PreEncryptedConfirmationCodeVerification().Verify(rehashed, DeviceHash(record), record, null)));
    }

    [Theory]
    [MemberData(nameof(PreEncryptedShapeNames))]
    public void ConfirmationCode_MalformedButSelfConsistentBallot_Fails16Structure(string shape)
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var ballot = PreEncrypt(record, "ballot-1", null);
        var malformed = Rehashed(PreEncryptedShapes[shape](ballot));

        var exception = Assert.Throws<VerificationFailedException>(() =>
            new PreEncryptedConfirmationCodeVerification().Verify(malformed, DeviceHash(record), record, null));

        Assert.Equal("16.structure", exception.SubSection);
    }

    // Verification 17

    [Fact]
    public void ShortCodes_ValidBallot_DoesNotThrow()
    {
        var record = CreateEncryptionRecord(selectionLimit: 2);
        var ballot = PreEncrypt(record, "ballot-1", null);

        Assert.Null(Record.Exception(() => new ShortCodeVerification().Verify(ballot, record)));
    }

    [Fact]
    public void ShortCodes_TamperedShortCode_Fails17A()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var tampered = ReplaceSelection(ballot, 1, s => s with { ShortCode = new ShortCode(s.ShortCode.Value == "A0" ? "A1" : "A0") });

        var exception = Assert.Throws<VerificationFailedException>(() => new ShortCodeVerification().Verify(tampered, record));

        Assert.Equal("17.A", exception.SubSection);
    }

    [Fact]
    public void ShortCodes_TamperedNullVoteShortCode_Fails17A()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        int nullVector = ballot.Contests[0].Selections.FindIndex(s => s.IsNullVote);
        var tampered = ReplaceSelection(ballot, nullVector, s => s with { ShortCode = new ShortCode("??") });

        var exception = Assert.Throws<VerificationFailedException>(() => new ShortCodeVerification().Verify(tampered, record));

        Assert.Equal("17.A", exception.SubSection);
    }

    [Fact]
    public void ShortCodes_CodesFromADifferentTrimmingFunction_Fails17A()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var contest = ballot.Contests[0];
        var retrimmed = contest.Selections.Select(s => s with { ShortCode = HashTrimming.Trim(HashTrimmingFunction.TwoHex, s.SelectionHash) }).ToList();
        var tampered = ballot with { Contests = [contest with { Selections = retrimmed }] };

        var exception = Assert.Throws<VerificationFailedException>(() => new ShortCodeVerification().Verify(tampered, record));

        Assert.Equal("17.A", exception.SubSection);
    }

    [Fact]
    public void ShortCodes_ManifestWithoutHashTrimmingFunction_Fails17A()
    {
        var record = CreateEncryptionRecord();
        var ballot = PreEncrypt(record, "ballot-1", null);
        var withoutOmega = new EncryptionRecord
        {
            CryptographicParameters = record.CryptographicParameters,
            GuardianParameters = record.GuardianParameters,
            ParameterBaseHash = record.ParameterBaseHash,
            ManifestFile = ManifestSerializer.ToManifestFile(record.Manifest with { HashTrimmingFunction = null }),
            ElectionBaseHash = record.ElectionBaseHash,
            Guardians = record.Guardians,
            ElectionPublicKeys = record.ElectionPublicKeys,
            ExtendedBaseHash = record.ExtendedBaseHash,
        };

        var exception = Assert.Throws<VerificationFailedException>(() => new ShortCodeVerification().Verify(ballot, withoutOmega));

        Assert.Equal("17.A", exception.SubSection);
    }
}
