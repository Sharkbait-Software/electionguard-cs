using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests;

public class BallotTests
{
    [Fact]
    public void CanEncryptAndDecryptASelection()
    {
        var cryptographicParameters = new CryptographicParameters();
        var guardianParameters = new GuardianParameters();
        EGParameters.Init(cryptographicParameters, guardianParameters);

        var randomElectionPrivateKey = ElectionGuardRandom.GetIntegerModQ();
        var randomElectionPublicKey = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, randomElectionPrivateKey);

        var ballot = new Ballot(randomElectionPublicKey);
        var selectionNonce = ElectionGuardRandom.GetIntegerModQ();

        var encryptedSelection = ballot.EncryptSelection(0, selectionNonce);
        int decrypted = ballot.DecryptSelection(encryptedSelection, selectionNonce, 1);

        Assert.Equal(0, decrypted);

        encryptedSelection = ballot.EncryptSelection(1, selectionNonce);
        decrypted = ballot.DecryptSelection(encryptedSelection, selectionNonce, 1);

        Assert.Equal(1, decrypted);
    }
}
