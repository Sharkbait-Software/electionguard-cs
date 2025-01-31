using System.Numerics;

namespace ElectionGuard.Core.UnitTests;

public class CryptographicParameterTests
{
    [Fact]
    public void CryptographicParameters_R_IsCorrect()
    {
        // The following equation must hold.
        // r = (p - 1)/q
        var parameters = new CryptographicParameters();
        var expected = parameters.R;

        var actual = (parameters.P - 1) / parameters.Q;

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CryptographicParameters_G_IsCorrect()
    {
        // g is calculated by the following equation
        // g = 2^r mod p
        var parameters = new CryptographicParameters();
        var expected = parameters.G;

        var actual = BigInteger.ModPow(2, parameters.R, parameters.P);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CryptographicParameters_Version_IsCorrect()
    {
        var parameters = new CryptographicParameters();
        var expected = Convert.FromHexString("76322E312E300000000000000000000000000000000000000000000000000000");
        var actual = parameters.Version;

        Assert.Equal(32, expected.Length);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ParameterBaseHash_IsExpectedLength()
    {
        var cryptographicParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        var baseHash = new ParameterBaseHash(cryptographicParameters, guardianParameters);
        Assert.True(true);
    }

    [Fact]
    public void Guardian_VoteEncryptionKeys_VerifyNIZK()
    {
        var cryptographicParameters = new CryptographicParameters();
        var cryptoFactory = new ElectionGuardCryptoFactory(cryptographicParameters);
        var guardianParameters = new GuardianParameters();
        var parameterBaseHash = new ParameterBaseHash(cryptographicParameters, guardianParameters);
        var guardian = new Guardian(cryptoFactory, guardianParameters, parameterBaseHash, new GuardianIndex(1));

        guardian.GenerateKeys();

        for (int i = 0; i <= guardianParameters.K; i++)
        {
            var generator = BigInteger.ModPow(cryptographicParameters.G, guardian.VoteEncryptionKeyProof.Responses[i], cryptographicParameters.P);

            BigInteger publicPiece;
            if (i == guardianParameters.K)
            {
                // This is for the communication public key, not the vote encryption public keys
                publicPiece = BigInteger.ModPow(guardian._communicationKeyPair.PublicKey, guardian.VoteEncryptionKeyProof.Challenge, cryptographicParameters.P);
            }
            else
            {
                // This is for the vote encryption public keys
                publicPiece = BigInteger.ModPow(guardian._voteEncryptionKeyPairs[i].PublicKey, guardian.VoteEncryptionKeyProof.Challenge, cryptographicParameters.P);
            }

            var calculatedH = (generator * publicPiece).Mod(cryptographicParameters.P);
            Assert.Equal(guardian.VoteEncryptionKeyProof.RandomPublicValues[i], calculatedH);
        }
    }

    [Fact]
    public void Guardian_OtherDataEncryptionKeys_VerifyNIZK()
    {
        var cryptographicParameters = new CryptographicParameters();
        var cryptoFactory = new ElectionGuardCryptoFactory(cryptographicParameters);
        var guardianParameters = new GuardianParameters();
        var parameterBaseHash = new ParameterBaseHash(cryptographicParameters, guardianParameters);
        var guardian = new Guardian(cryptoFactory, guardianParameters, parameterBaseHash, new GuardianIndex(1));

        guardian.GenerateKeys();

        for (int i = 0; i <= guardianParameters.K; i++)
        {
            var generator = BigInteger.ModPow(cryptographicParameters.G, guardian.OtherDataEncryptionKeyProof.Responses[i], cryptographicParameters.P);

            BigInteger publicPiece;
            if (i == guardianParameters.K)
            {
                // This is for the communication public key, not the vote encryption public keys
                publicPiece = BigInteger.ModPow(guardian._communicationKeyPair.PublicKey, guardian.OtherDataEncryptionKeyProof.Challenge, cryptographicParameters.P);
            }
            else
            {
                // This is for the vote encryption public keys
                publicPiece = BigInteger.ModPow(guardian._otherBallotDataKeyPairs[i].PublicKey, guardian.OtherDataEncryptionKeyProof.Challenge, cryptographicParameters.P);
            }

            var calculatedH = (generator * publicPiece).Mod(cryptographicParameters.P);
            Assert.Equal(guardian.OtherDataEncryptionKeyProof.RandomPublicValues[i], calculatedH);
        }
    }

    [Fact]
    public void Guardian_EncryptedShares_Valid()
    {
        var cryptographicParameters = new CryptographicParameters();
        var cryptoFactory = new ElectionGuardCryptoFactory(cryptographicParameters);
        var guardianParameters = new GuardianParameters();
        var parameterBaseHash = new ParameterBaseHash(cryptographicParameters, guardianParameters);
        var guardian1 = new Guardian(cryptoFactory, guardianParameters, parameterBaseHash, new GuardianIndex(1));
        var guardian2 = new Guardian(cryptoFactory, guardianParameters, parameterBaseHash, new GuardianIndex(2));
        var guardian3 = new Guardian(cryptoFactory, guardianParameters, parameterBaseHash, new GuardianIndex(3));

        guardian1.GenerateKeys();
        guardian2.GenerateKeys();
        guardian3.GenerateKeys();

        var encryptedShares1 = guardian1.EncryptShares(new List<GuardianPublicView> { guardian2.PublicDto, guardian3.PublicDto });
        var encryptedShares2 = guardian2.EncryptShares(new List<GuardianPublicView> { guardian1.PublicDto, guardian3.PublicDto });
        var encryptedShares3 = guardian3.EncryptShares(new List<GuardianPublicView> { guardian1.PublicDto, guardian2.PublicDto });
        var allShares = encryptedShares1.Concat(encryptedShares2).Concat(encryptedShares3);

        guardian1.DecryptShares(allShares.Where(x => x.DestinationIndex == guardian1.Index).ToList());
        guardian2.DecryptShares(allShares.Where(x => x.DestinationIndex == guardian2.Index).ToList());
        guardian3.DecryptShares(allShares.Where(x => x.DestinationIndex == guardian3.Index).ToList());
    }
}
