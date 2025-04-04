using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Text;

namespace ElectionGuard.Core.BallotEncryption;

public class BallotEncryptor
{
    public BallotEncryptor(EncryptionRecord encryptionRecord)
    {
        _encryptionRecord = encryptionRecord;
    }

    private readonly EncryptionRecord _encryptionRecord;

    public void Encrypt()
    {
        var selectionEncryptionIdentifier = new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32));
        var selectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(_encryptionRecord.ExtendedBaseHash, selectionEncryptionIdentifier);

        var ballotNonce = new BallotNonce(ElectionGuardRandom.GetBytes(32));
        var encryptedBallotNonce = EncryptBallotNonce(ballotNonce, selectionEncryptionIdentifierHash);
    }

    private EncryptedBallotNonce EncryptBallotNonce(BallotNonce ballotNonce, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash)
    {
        // 3.3.4
        var keyPair = KeyPair.GenerateRandom();
        IntegerModQ epsilon = keyPair.SecretKey;
        IntegerModP alpha = keyPair.PublicKey;
        IntegerModP beta = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey, epsilon);
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

        return new EncryptedBallotNonce
        {
            C0 = c0,
            C1 = c1,
            Challenge = challenge,
            Response = response,
        };
    }

    private byte[] ComputeBallotNonceEncryptionKey(byte[] symmetricKey)
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

public class EncryptedBallotNonce
{
    public required byte[] C0 { get; init; }
    public required byte[] C1 { get; init; }
    public required IntegerModQ Challenge { get; init; }
    public required IntegerModQ Response { get; init; }
}