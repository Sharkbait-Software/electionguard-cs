using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Serialization;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ElectionGuard.Core.UnitTests.PreEncryption;

/// <summary>
/// The printer-committed list of issued pre-encrypted ballots (user decision Q31, S9b): its
/// canonical encoding and commitment (a library format, not the spec's), and its strict reader.
/// </summary>
public class IssuedPreEncryptedBallotsTests
{
    public IssuedPreEncryptedBallotsTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static PreEncryptedElection Election => PreEncryptedElection.Get();

    private const int Header = 48 + 32 + 4;
    private const int EntryLength = 32 + 512;

    private static IssuedPreEncryptedBallot Entry(byte first, IntegerModP? c0 = null)
    {
        var identifier = new byte[32];
        identifier[0] = first;
        identifier[31] = (byte)~first;
        return new IssuedPreEncryptedBallot(new SelectionEncryptionIdentifier(identifier), c0 ?? new IntegerModP(1000 + first));
    }

    [Fact]
    public void CanonicalBytes_FollowTheDocumentedLayout_AndTheCommitmentIsTheirSha256()
    {
        var hash = Election.Record.ExtendedBaseHash;
        var list = new IssuedPreEncryptedBallots(hash, [Entry(9), Entry(3), Entry(200)]);

        var bytes = list.ToCanonicalBytes();

        Assert.Equal(48, Encoding.ASCII.GetByteCount(IssuedPreEncryptedBallots.FormatTag));
        Assert.Equal(Header + 3 * EntryLength, bytes.Length);
        Assert.Equal(Encoding.ASCII.GetBytes("electionguard-cs:issued-pre-encrypted-ballots:v1"), bytes[..48]);
        Assert.Equal((byte[])hash, bytes[48..80]);
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(80, 4)));
        Assert.Equal(new byte[] { 3, 9, 200 }, Enumerable.Range(0, 3).Select(i => bytes[Header + i * EntryLength]));
        Assert.Equal(new IntegerModP(1009).ToByteArray(), bytes[(Header + EntryLength + 32)..(Header + 2 * EntryLength)]);
        Assert.Equal(SHA256.HashData(bytes), list.Commitment);
        Assert.Equal(new byte[] { 3, 9, 200 }, list.Ballots.Select(x => ((byte[])x.SelectionEncryptionIdentifier)[0]));
    }

    /// <summary>Guardians compare commitments: the same ballots in any order commit identically; any change shows.</summary>
    [Fact]
    public void Commitment_IndependentOfInputOrder_AndChangesWithAnyEntry()
    {
        var hash = Election.Record.ExtendedBaseHash;
        var reference = new IssuedPreEncryptedBallots(hash, [Entry(1), Entry(2), Entry(3)]).Commitment;

        Assert.Equal(reference, new IssuedPreEncryptedBallots(hash, [Entry(3), Entry(1), Entry(2)]).Commitment);
        Assert.NotEqual(reference, new IssuedPreEncryptedBallots(hash, [Entry(1), Entry(2)]).Commitment);
        Assert.NotEqual(reference, new IssuedPreEncryptedBallots(hash, [Entry(1), Entry(2), Entry(3, 7)]).Commitment);
        Assert.NotEqual(reference, new IssuedPreEncryptedBallots(PreEncryptedElection.Get(ChainingMode.Simple).Record.ExtendedBaseHash, [Entry(1), Entry(2), Entry(3)]).Commitment);
    }

    [Fact]
    public void FromPrintedBallots_ListsEachBallotsIdentifierAndEncryptedNonce_AndRoundTrips()
    {
        var election = Election;
        var printed = new[] { election.PreEncrypt("a"), election.PreEncrypt("b") };
        var list = IssuedPreEncryptedBallots.FromPrintedBallots(election.Record.ExtendedBaseHash, printed);

        foreach (var ballot in printed)
        {
            Assert.True(list.TryGet(ballot.SelectionEncryptionIdentifier, out var issued));
            Assert.Equal(ballot.EncryptedBallotNonce.C0, issued.EncryptedBallotNonceC0);
        }

        Assert.False(list.TryGet(election.PreEncrypt("c").SelectionEncryptionIdentifier, out _));
        Assert.True(list.IsFor(election.Record.ExtendedBaseHash));
        Assert.False(list.IsFor(PreEncryptedElection.Get(ChainingMode.Simple).Record.ExtendedBaseHash));

        var read = IssuedPreEncryptedBallots.FromCanonicalBytes(list.ToCanonicalBytes(), election.Record.ExtendedBaseHash);
        Assert.Equal(list.Commitment, read.Commitment);
        Assert.Equal(2, read.Count);
    }

    /// <summary>
    /// The list holds its own copies: changing an input id_B's array after construction, or an array
    /// read back out of it, moves neither a look-up nor the commitment the guardians compare.
    /// </summary>
    [Fact]
    public void List_HoldsItsOwnCopies_OfTheIdentifiersAndCommitment()
    {
        var hash = Election.Record.ExtendedBaseHash;
        var input = Entry(7);
        var list = new IssuedPreEncryptedBallots(hash, [input, Entry(8)]);
        var commitment = list.Commitment;
        var lookUp = SelectionEncryptionIdentifier.FromCanonicalBytes((byte[])input.SelectionEncryptionIdentifier);

        ((byte[])input.SelectionEncryptionIdentifier)[0] ^= 0xFF;
        ((byte[])list.Ballots[0].SelectionEncryptionIdentifier)[0] ^= 0xFF;
        Assert.True(list.TryGet(lookUp, out var issued));
        ((byte[])issued.SelectionEncryptionIdentifier)[0] ^= 0xFF;
        list.Commitment[0] ^= 0xFF;

        Assert.True(list.TryGet(lookUp, out _));
        Assert.False(list.TryGet(input.SelectionEncryptionIdentifier, out _));
        Assert.Equal(commitment, list.Commitment);
        Assert.Equal(SHA256.HashData(list.ToCanonicalBytes()), list.Commitment);
        Assert.Equal(new byte[] { 7, 8 }, list.Ballots.Select(x => ((byte[])x.SelectionEncryptionIdentifier)[0]));
    }

    [Fact]
    public void Constructor_DuplicateOrMalformedIdentifier_Throws()
    {
        var hash = Election.Record.ExtendedBaseHash;
        Assert.Contains("twice", Assert.Throws<ArgumentException>(() => new IssuedPreEncryptedBallots(hash, [Entry(1), Entry(1, 5)])).Message);
        Assert.Throws<ArgumentException>(() => new IssuedPreEncryptedBallots(hash, [new IssuedPreEncryptedBallot(new SelectionEncryptionIdentifier(new byte[31]), 5)]));
    }

    public static TheoryData<string, Func<byte[], byte[]>> MalformedEncodings => new()
    {
        { "wrong tag", b => { b[0] ^= 1; return b; } },
        { "another election", b => { b[48] ^= 1; return b; } },
        { "count too high", b => { BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(80), 3); return b; } },
        { "truncated", b => b[..^1] },
        { "out of order", b => { (b[Header], b[Header + EntryLength]) = (b[Header + EntryLength], b[Header]); return b; } },
        { "C0 = p", b => { EGParameters.P.ToByteArray(isUnsigned: true, isBigEndian: true).CopyTo(b, Header + 32); return b; } },
        { "empty", _ => [] },
    };

    [Theory]
    [MemberData(nameof(MalformedEncodings))]
    public void FromCanonicalBytes_Malformed_IsRefused(string description, Func<byte[], byte[]> tamper)
    {
        var hash = Election.Record.ExtendedBaseHash;
        var bytes = new IssuedPreEncryptedBallots(hash, [Entry(1), Entry(2)]).ToCanonicalBytes();

        Assert.NotNull(description);
        Assert.Throws<NonCanonicalEncodingException>(() => IssuedPreEncryptedBallots.FromCanonicalBytes(tamper(bytes), hash));
    }
}
