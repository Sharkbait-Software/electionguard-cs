using System.Numerics;

namespace ElectionGuard.Core.UnitTests;

public class CryptographicParameterTests
{
    [Fact]
    public void CryptographicParameters_R_IsCorrect()
    {
        var cryptographicParameters = new CryptographicParameters();

        // The following equation must hold.
        // r = (p - 1)/q
        var expected = cryptographicParameters.R;

        var actual = (cryptographicParameters.P - 1) / cryptographicParameters.Q;

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CryptographicParameters_G_IsCorrect()
    {
        var cryptographicParameters = new CryptographicParameters();

        // g is calculated by the following equation
        // g = 2^r mod p
        var expected = cryptographicParameters.G;

        var actual = BigInteger.ModPow(2, cryptographicParameters.R, cryptographicParameters.P);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CryptographicParameters_Version_IsCorrect()
    {
        var cryptographicParameters = new CryptographicParameters();

        var expected = Convert.FromHexString("000000000000000000000000000000000000000000000000000076322E312E30");
        byte[] actual = cryptographicParameters.Version;

        Assert.Equal(32, expected.Length);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Guardian_EncryptedShares_Valid()
    {
        var cryptographicParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        EGParameters.Init(cryptographicParameters, guardianParameters);

        var guardian1 = new Guardian(new GuardianIndex(1));
        var guardian2 = new Guardian(new GuardianIndex(2));
        var guardian3 = new Guardian(new GuardianIndex(3));

        var guardian1Keys = guardian1.GenerateKeys();
        var guardian2Keys = guardian2.GenerateKeys();
        var guardian3Keys = guardian3.GenerateKeys();

        var encryptedShares1 = guardian1.EncryptShares(new List<GuardianPublicView> { guardian2Keys.ToPublicView(), guardian3Keys.ToPublicView() });
        var encryptedShares2 = guardian2.EncryptShares(new List<GuardianPublicView> { guardian1Keys.ToPublicView(), guardian3Keys.ToPublicView() });
        var encryptedShares3 = guardian3.EncryptShares(new List<GuardianPublicView> { guardian1Keys.ToPublicView(), guardian2Keys.ToPublicView() });
        var allShares = encryptedShares1.Concat(encryptedShares2).Concat(encryptedShares3);

        guardian1.DecryptShares(allShares.Where(x => x.DestinationIndex == guardian1.Index).ToList());
        guardian2.DecryptShares(allShares.Where(x => x.DestinationIndex == guardian2.Index).ToList());
        guardian3.DecryptShares(allShares.Where(x => x.DestinationIndex == guardian3.Index).ToList());
    }
}
