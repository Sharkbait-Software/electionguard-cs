using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Text;

namespace ElectionGuard.Core.BallotEncryption;

/// <summary>
/// §3.3.4 encryption of the ballot nonce to the other-ballot-data encryption key K-hat. Shared by
/// <see cref="BallotEncryptor"/> and the pre-encrypted ballot encrypting tool (§4.2).
/// </summary>
internal static class BallotNonceEncryption
{
    public static EncryptedData Encrypt(BallotNonce ballotNonce, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, IntegerModP otherBallotDataEncryptionKey)
    {
        var keyPair = KeyPair.GenerateRandom();
        IntegerModQ epsilon = keyPair.SecretKey;
        IntegerModP alpha = keyPair.PublicKey;
        IntegerModP beta = MontgomeryModP.PowModP(otherBallotDataEncryptionKey, epsilon);
        var symmetricKey = EGHash.Hash(selectionEncryptionIdentifierHash,
            [0x22],
            alpha,
            beta);
        var k1 = ComputeBallotNonceEncryptionKey(symmetricKey);

        var c0 = alpha;
        var c1 = ballotNonce.ToByteArray().XOR(k1);

        var proof = KeyPair.GenerateRandom();
        var u = proof.SecretKey;
        var commitment = proof.PublicKey;
        var challenge = EGHash.HashModQ(selectionEncryptionIdentifierHash,
            [0x23],
            commitment,
            c0,
            c1);
        var response = u - challenge * epsilon;

        return new EncryptedData
        {
            C0 = c0,
            C1 = c1,
            Challenge = challenge,
            Response = response,
        };
    }

    private static byte[] ComputeBallotNonceEncryptionKey(byte[] symmetricKey)
    {
        byte[] key = EGHash.Hash(symmetricKey,
            [0x01],
            Encoding.UTF8.GetBytes("ballot_nonce"),
            [0x00],
            Encoding.UTF8.GetBytes("ballot_nonce_encrypt"),
            [0x01, 0x00]);
        return key;
    }
}
