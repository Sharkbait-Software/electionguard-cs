using ElectionGuard.Core.Models;
using ElectionGuard.Core.UnitTests.TestFixtures;
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

    [Fact]
    public void Verify_ValidHash_AlwaysThrows_SubSection5B_DueToByteArrayReferenceComparisonBug()
    {
        // Pinning a genuine production bug (per CLAUDE.md: pin observed behavior, don't "fix" it
        // in a test). SelectionEncryptionIdentifierVerification.Verify(identifier, hash,
        // extendedBaseHash) (line 28) compares `expected != (byte[])selectionEncryptionIdentifierHash`.
        // `byte[]` has no `!=` operator overload, so this is a *reference* comparison between two
        // freshly-allocated arrays -- it is never true equality, even when the hash was correctly
        // derived from the same identifier/extendedBaseHash. As a result this overload throws
        // VerificationFailedException("5.B", ...) unconditionally, for both matching and
        // mismatching hashes. This test documents that even a correctly-computed hash throws.
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (_, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, guardianSet.ElectionPublicKeys);

        var identifier = new SelectionEncryptionIdentifier(new byte[] { 1, 2, 3 });
        var hash = new SelectionEncryptionIdentifierHash(extendedBaseHash, identifier);

        var verification = new SelectionEncryptionIdentifierVerification();

        var exception = Assert.Throws<VerificationFailedException>(
            () => verification.Verify(identifier, hash, extendedBaseHash));
        Assert.Equal("5.B", exception.SubSection);
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
