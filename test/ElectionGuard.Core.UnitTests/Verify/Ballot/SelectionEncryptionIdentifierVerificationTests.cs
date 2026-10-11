using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;

namespace ElectionGuard.Core.UnitTests.Verify.Ballot;

public class SelectionEncryptionIdentifierVerificationTests
{
    public SelectionEncryptionIdentifierVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    [Fact]
    public void Verify_UniqueIdentifiers_DoesNotThrow()
    {
        var identifiers = new List<SelectionEncryptionIdentifier>
        {
            new SelectionEncryptionIdentifier(new byte[] { 1, 2, 3 }),
            new SelectionEncryptionIdentifier(new byte[] { 4, 5, 6 }),
        };

        var verification = new SelectionEncryptionIdentifierVerification();

        var exception = Record.Exception(() => verification.Verify(identifiers));

        Assert.Null(exception);
    }

    [Fact]
    public void Verify_DuplicateIdentifiers_Throws_SubSection5A()
    {
        // The same identifier value appearing twice in the list is exactly the duplicate
        // condition Verification 5.A detects.
        var identifier = new SelectionEncryptionIdentifier(new byte[] { 9, 9, 9 });
        var identifiers = new List<SelectionEncryptionIdentifier> { identifier, identifier };

        var verification = new SelectionEncryptionIdentifierVerification();

        var exception = Assert.Throws<VerificationFailedException>(() => verification.Verify(identifiers));
        Assert.Equal("5.A", exception.SubSection);
    }

    /// <summary>
    /// G13: two ballots read separately carry their identifiers in separate arrays. Equality used to
    /// be the struct default, which compared the arrays by reference, so 5.A never saw these as equal.
    /// </summary>
    [Fact]
    public void Verify_EqualIdentifiersInSeparateArrays_Throws_SubSection5A()
    {
        byte[] bytes = Enumerable.Range(0, 32).Select(i => (byte)(7 * i)).ToArray();
        var first = new SelectionEncryptionIdentifier(bytes);
        var second = new SelectionEncryptionIdentifier((byte[])bytes.Clone());
        Assert.NotSame((byte[])first, (byte[])second);

        var exception = Assert.Throws<VerificationFailedException>(
            () => new SelectionEncryptionIdentifierVerification().Verify([first, second]));

        Assert.Equal("5.A", exception.SubSection);
    }

    [Fact]
    public void Identifier_EqualityAndHashCode_AreByContent()
    {
        byte[] bytes = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var first = new SelectionEncryptionIdentifier(bytes);
        var second = new SelectionEncryptionIdentifier((byte[])bytes.Clone());
        byte[] changed = (byte[])bytes.Clone();
        changed[31] ^= 1;
        var third = new SelectionEncryptionIdentifier(changed);

        Assert.True(first.Equals(second));
        Assert.True(first == second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
        Assert.False(first.Equals(third));
        Assert.True(first != third);
        Assert.Single(new HashSet<SelectionEncryptionIdentifier> { first, second });
    }

    /// <summary>
    /// 5.A is over every submitted ballot, so a caller that sees the ballots in chunks (the perf
    /// harness) or from several sources keeps one set across all of them.
    /// </summary>
    [Fact]
    public void IdentifierSet_DuplicateInALaterBatch_Throws_SubSection5A()
    {
        var set = new SelectionEncryptionIdentifierSet();
        var batch1 = Enumerable.Range(0, 3).Select(i => new SelectionEncryptionIdentifier(Enumerable.Repeat((byte)i, 32).ToArray())).ToList();
        var batch2 = new List<SelectionEncryptionIdentifier>
        {
            new(Enumerable.Repeat((byte)10, 32).ToArray()),
            new(Enumerable.Repeat((byte)1, 32).ToArray()), // equal to batch1[1], in its own array
        };

        foreach (var identifier in batch1)
        {
            set.Add(identifier);
        }

        set.Add(batch2[0]);
        var exception = Assert.Throws<VerificationFailedException>(() => set.Add(batch2[1]));

        Assert.Equal("5.A", exception.SubSection);
        Assert.Equal(4, set.Count);
    }

    [Fact]
    public void Verify_ValidHash_DoesNotThrow()
    {
        // SelectionEncryptionIdentifierVerification.Verify(identifier, hash, extendedBaseHash) now
        // compares hash bytes by content (SequenceEqual) instead of byte[] reference equality, so a
        // correctly-derived hash passes.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (_, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, guardianSet.ElectionPublicKeys);

        var identifier = new SelectionEncryptionIdentifier(new byte[] { 1, 2, 3 });
        var hash = new SelectionEncryptionIdentifierHash(extendedBaseHash, identifier);

        var verification = new SelectionEncryptionIdentifierVerification();

        var exception = Record.Exception(() => verification.Verify(identifier, hash, extendedBaseHash));
        Assert.Null(exception);
    }

    [Fact]
    public void Verify_TamperedHash_Throws_SubSection5B()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (_, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, guardianSet.ElectionPublicKeys);

        var identifier = new SelectionEncryptionIdentifier(new byte[] { 1, 2, 3 });

        // Hash was derived from a different identifier than the one being verified, so it will
        // not match the recomputed hash for `identifier`.
        var otherIdentifier = new SelectionEncryptionIdentifier(new byte[] { 9, 9, 9 });
        var wrongHash = new SelectionEncryptionIdentifierHash(extendedBaseHash, otherIdentifier);

        var verification = new SelectionEncryptionIdentifierVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(identifier, wrongHash, extendedBaseHash));
        Assert.Equal("5.B", exception.SubSection);
    }
}
