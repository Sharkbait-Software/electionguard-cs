using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
using System.Text;

namespace ElectionGuard.Core.UnitTests.BallotEncryption;

/// <summary>
/// §3.3.10 contest data on the encryption side (G11, user decision Q7): the manifest's per-contest
/// b_Λ, the encryptor's refusals, the fixed-length field on every ballot, and the library's string
/// encoding. The known-answer tests pin the bytes.
/// </summary>
public class ContestDataEncryptionTests
{
    public ContestDataEncryptionTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private sealed record Election(Manifest Manifest, EncryptionRecord Record, VotingDeviceInformationHash DeviceHash);

    private static readonly Lazy<Election> WithContestData = new(() => Build(includeWriteIns: true));
    private static readonly Lazy<Election> WithoutContestData = new(() => Build(includeWriteIns: false));

    private static Election Build(bool includeWriteIns)
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: includeWriteIns);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        return new Election(manifest, record.EncryptionRecord, new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1"));
    }

    private static EncryptedBallot Encrypt(Election election, byte[]? contestData)
    {
        var ballot = ElectionFixtureBuilder.CreateBallot(election.Manifest);
        ballot = ballot with { Contests = [ballot.Contests[0] with { ContestData = contestData }] };
        return new BallotEncryptor(election.Record, "device-1", election.DeviceHash).Encrypt(ballot, null);
    }

    /// <summary>
    /// C_1 is 32·b_Λ bytes whatever the text's length, including none at all: the field's presence
    /// and length reveal nothing about what was written.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("A")]
    [InlineData("A write-in long enough to need the second block.")]
    public void Encrypt_ContestDeclaringContestData_AlwaysCarriesAFieldOfExactly32TimesBBytes(string? text)
    {
        var election = WithContestData.Value;
        int blocks = election.Manifest.Contests[0].ContestDataBlocks;
        Assert.Equal(ElectionFixtureBuilder.DefaultContestDataBlocks, blocks);

        var encrypted = Encrypt(election, text is null ? null : ContestDataEncoding.Encode(text, blocks));

        var data = Assert.IsType<EncryptedContestData>(encrypted.Contests[0].ContestData);
        Assert.Equal(32 * blocks, data.C1.Length);
        Assert.True(ContestDataEncryption.ProofHolds(encrypted.SelectionEncryptionIdentifierHash, 1, data));
    }

    [Fact]
    public void Encrypt_ContestDeclaringNoContestData_CarriesNoneAndRefusesSome()
    {
        var election = WithoutContestData.Value;
        Assert.Equal(0, election.Manifest.Contests[0].ContestDataBlocks);

        Assert.Null(Encrypt(election, null).Contests[0].ContestData);
        Assert.Throws<InvalidBallotException>(() => Encrypt(election, new byte[32]));
    }

    /// <summary>The library takes exactly 32·b_Λ raw bytes (Q7): it neither pads nor truncates.</summary>
    [Theory]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(65)]
    [InlineData(96)]
    public void Encrypt_ContestDataOfAnotherLength_IsRefused(int length)
    {
        Assert.Throws<InvalidBallotException>(() => Encrypt(WithContestData.Value, new byte[length]));
    }

    /// <summary>
    /// Eq. (64) derives ξ from ξ_B and the contest index, so the same ballot nonce gives the same
    /// C_0 and C_1, and C_1 decrypts under β = K-hat^ξ.
    /// </summary>
    [Fact]
    public void Encrypt_FieldDecryptsUnderTheBallotNoncesKey()
    {
        var election = WithContestData.Value;
        var data = ContestDataEncoding.Encode("Write-in: Grace Hopper", 2);
        var ballot = ElectionFixtureBuilder.CreateBallot(election.Manifest);
        ballot = ballot with { Contests = [ballot.Contests[0] with { ContestData = data }] };
        var identifier = new SelectionEncryptionIdentifier(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
        var nonce = new BallotNonce(Enumerable.Range(100, 32).Select(i => (byte)i).ToArray());

        var first = new BallotEncryptor(election.Record, "device-1", election.DeviceHash).Encrypt(ballot, null, identifier, nonce).Contests[0].ContestData!;
        var second = new BallotEncryptor(election.Record, "device-1", election.DeviceHash).Encrypt(ballot, null, identifier, nonce).Contests[0].ContestData!;

        Assert.Equal(first.C0, second.C0);
        Assert.Equal(first.C1, second.C1);

        // u of eq. (69) is fresh and random, never derived from ξ_B or ξ: two proofs sharing u under
        // the same ξ would reveal ξ = (v' - v)/(c - c') and so the data.
        Assert.NotEqual(first.Challenge, second.Challenge);
        Assert.NotEqual(first.Response, second.Response);
        var proofHash = new SelectionEncryptionIdentifierHash(election.Record.ExtendedBaseHash, identifier);
        Assert.True(ContestDataEncryption.ProofHolds(proofHash, 1, first));
        Assert.True(ContestDataEncryption.ProofHolds(proofHash, 1, second));
        var selectionHash = new SelectionEncryptionIdentifierHash(election.Record.ExtendedBaseHash, identifier);
        var xi = ContestDataEncryption.Nonce(selectionHash, 1, nonce);
        var beta = ElectionGuard.Core.Crypto.MontgomeryModP.PowModP(election.Record.ElectionPublicKeys.OtherBallotDataEncryptionKey, xi);
        Assert.Equal(data, ContestDataEncryption.Decrypt(selectionHash, 1, 2, first, beta));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(Contest.ContestDataBlocksLimit)]
    public void ManifestValidate_ContestDataBlocksOutOfRange_Throws(int blocks)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(contestDataBlocks: blocks);

        Assert.Throws<InvalidManifestException>(manifest.Validate);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(Contest.ContestDataBlocksLimit - 1)]
    public void ManifestValidate_ContestDataBlocksInRange_DoesNotThrow(int blocks)
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(contestDataBlocks: blocks);

        manifest.Validate();
    }

    // The Q7 string encoding (not spec).

    [Theory]
    [InlineData("", 1)]
    [InlineData("Write-in: Ada Lovelace", 1)]
    [InlineData("Ends in NUL\0\0", 1)]
    [InlineData("Wahl Zürich – Gerät №7 🗳", 2)]
    public void Encoding_RoundTrips(string text, int blocks)
    {
        var data = ContestDataEncoding.Encode(text, blocks);

        Assert.Equal(32 * blocks, data.Length);
        Assert.Equal(Encoding.UTF8.GetByteCount(text), System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(data));
        Assert.Equal(text, ContestDataEncoding.Decode(data));
    }

    [Fact]
    public void Encoding_ExactlyFull_FitsAndOneByteMore_IsRejected()
    {
        Assert.Equal(28, ContestDataEncoding.Capacity(1));
        Assert.Equal(ContestDataEncoding.Capacity(1) + 4, ContestDataEncoding.Encode(new string('x', 28), 1).Length);
        Assert.Throws<ArgumentException>(() => ContestDataEncoding.Encode(new string('x', 29), 1));
        Assert.Throws<ArgumentException>(() => ContestDataEncoding.Encode("x\uD800", 2));
        Assert.Throws<ArgumentOutOfRangeException>(() => ContestDataEncoding.Encode("x", 0));
    }

    public static TheoryData<string> Undecodable() => new() { "length beyond the field", "nonzero padding", "invalid UTF-8", "not whole blocks" };

    [Theory]
    [MemberData(nameof(Undecodable))]
    public void Decoding_AnAmbiguousOrMalformedField_Throws(string defect)
    {
        var data = ContestDataEncoding.Encode("abc", 1);
        switch (defect)
        {
            case "length beyond the field":
                data[3] = 29;
                break;
            case "nonzero padding":
                data[^1] = 1;
                break;
            case "invalid UTF-8":
                data[4] = 0xFF;
                break;
            case "not whole blocks":
                data = data[..31];
                break;
        }

        Assert.Throws<FormatException>(() => ContestDataEncoding.Decode(data));
    }
}
