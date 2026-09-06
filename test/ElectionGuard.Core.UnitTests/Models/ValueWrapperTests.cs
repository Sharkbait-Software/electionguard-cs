using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.Models;

public class ValueWrapperTests
{
    [Fact]
    public void SelectionEncryptionIdentifier_Constructor_RoundTripsBytes()
    {
        var bytes = new byte[] { 0x01, 0x02, 0x03 };

        var identifier = new SelectionEncryptionIdentifier(bytes);

        Assert.Equal(bytes, (byte[])identifier);
    }

    [Fact]
    public void BallotNonce_Constructor_RoundTripsBytes()
    {
        var bytes = new byte[] { 0x04, 0x05, 0x06 };

        var nonce = new BallotNonce(bytes);

        Assert.Equal(bytes, (byte[])nonce);
    }

    [Fact]
    public void BallotNonce_ToByteArray_ReturnsOriginalBytes()
    {
        var bytes = new byte[] { 0x07, 0x08 };

        var nonce = new BallotNonce(bytes);

        Assert.Equal(bytes, nonce.ToByteArray());
    }

    [Fact]
    public void ManifestFile_Bytes_RoundTrips()
    {
        var bytes = new byte[] { 0x09, 0x0A };

        var manifestFile = new ManifestFile { Bytes = bytes };

        Assert.Equal(bytes, manifestFile.Bytes);
    }

    // Assertion-quality strengthening: the round-trip tests above only assert structural equality
    // (Assert.Equal does an element-wise byte comparison), so none of them would catch a change
    // that defensively copies the input array before storing/returning it. These tests add that
    // secondary observable -- reference identity -- pinning that these thin value wrappers store
    // (and expose) the exact array instance passed in, with no defensive copy.
    [Fact]
    public void SelectionEncryptionIdentifier_ImplicitConversion_ReturnsSameArrayInstance()
    {
        var bytes = new byte[] { 0x01, 0x02, 0x03 };

        var identifier = new SelectionEncryptionIdentifier(bytes);

        Assert.Same(bytes, (byte[])identifier);
    }

    [Fact]
    public void BallotNonce_ImplicitConversion_ReturnsSameArrayInstance()
    {
        var bytes = new byte[] { 0x04, 0x05, 0x06 };

        var nonce = new BallotNonce(bytes);

        Assert.Same(bytes, (byte[])nonce);
    }

    [Fact]
    public void ManifestFile_Bytes_ReturnsSameArrayInstance()
    {
        var bytes = new byte[] { 0x09, 0x0A };

        var manifestFile = new ManifestFile { Bytes = bytes };

        Assert.Same(bytes, manifestFile.Bytes);
    }
}
