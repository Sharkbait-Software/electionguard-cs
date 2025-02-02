using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core;

public class Guardian
{
    public Guardian(GuardianIndex index)
    {
        if (index < 0 || index > EGParameters.GuardianParameters.N)
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"Guardian index must be between 0 and N ({EGParameters.GuardianParameters.N}).");
        }

        Index = index;
    }

    public GuardianIndex Index { get; }

    private GuardianKeys? _keys = null;

    public GuardianKeys GenerateKeys()
    {
        // The first coefficient/committment is our private / secret key for the guardian.
        List<KeyPair> voteEncryptionKeyPairs = new List<KeyPair>();
        for (int i = 0; i < EGParameters.GuardianParameters.K; i++)
        {
            var keyPair = GenerateKeyPair();
            voteEncryptionKeyPairs.Add(keyPair);
        }

        List<KeyPair> otherBallotDataEncryptionKeyPairs = new List<KeyPair>();
        for (int i = 0; i < EGParameters.GuardianParameters.K; i++)
        {
            var keyPair = GenerateKeyPair();
            otherBallotDataEncryptionKeyPairs.Add(keyPair);
        }

        var communicationKeyPair = GenerateKeyPair();

        // Generate a NIZK proof for voteEncryptionKeys
        var voteEncryptionKeyProof = GenerateKeyProof(voteEncryptionKeyPairs, communicationKeyPair, "pk_vote");
        var otherBallotDataEncryptionKeyProof = GenerateKeyProof(otherBallotDataEncryptionKeyPairs, communicationKeyPair, "pk_data");

        _keys = new GuardianKeys
        {
            Index = Index,
            VoteEncryptionKeyPairs = voteEncryptionKeyPairs,
            OtherBallotDataEncryptionKeyPairs = otherBallotDataEncryptionKeyPairs,
            CommunicationKeyPair = communicationKeyPair,
            VoteEncryptionKeyProof = voteEncryptionKeyProof,
            OtherBallotDataEncryptionKeyProof = otherBallotDataEncryptionKeyProof,
        };

        return _keys;
    }

    public List<GuardianEncryptedShare> EncryptShares(List<GuardianPublicView> guardians)
    {
        if (_keys == null)
        {
            throw new Exception("Keys not generated.");
        }

        List<GuardianEncryptedShare> encryptedShares = new List<GuardianEncryptedShare>();

        foreach (var guardian in guardians)
        {
            var keyPair = GenerateKeyPair();
            IntegerModQ epsilon = keyPair.SecretKey;
            IntegerModP alpha = keyPair.PublicKey;

            IntegerModP beta = IntegerModP.PowModP(guardian.CommunicationPublicKey, epsilon);
            var symmetricKey = EGHash.Hash(EGParameters.ParameterBaseHash,
                [0x11],
                Index,
                guardian.Index,
                guardian.CommunicationPublicKey,
                alpha,
                beta
                );

            (byte[] k1, byte[] k2) = ComputeShareEncryptionKeys(symmetricKey, Index, guardian.Index);

            IntegerModP c0 = alpha;
            var c1a = ComputePolynomial(_keys.VoteEncryptionKeyPairs, guardian.Index).ToByteArray().XOR(k1);
            var c1b = ComputePolynomial(_keys.OtherBallotDataEncryptionKeyPairs, guardian.Index).ToByteArray().XOR(k2);
            var c1 = ByteArrayExtensions.Concat(c1a, c1b);

            var proof = GenerateKeyPair();
            var uBar = proof.SecretKey;
            var gamma = proof.PublicKey;
            var cBar = EGHash.HashModQ(EGParameters.ParameterBaseHash,
                [0x12],
                Index,
                guardian.Index,
                gamma,
                c0,
                c1
                );
            var vBar = uBar - cBar * epsilon;

            var encryptedShareDto = new GuardianEncryptedShare
            {
                SourceIndex = Index,
                DestinationIndex = guardian.Index,
                C0 = c0,
                C1 = c1,
                Challenge = cBar,
                Response = vBar,
            };
            encryptedShares.Add(encryptedShareDto);
        }

        return encryptedShares;
    }

    public KeyPair GenerateKeyPair()
    {
        IntegerModQ secretKey = ElectionGuardRandom.GetIntegerModQ();

        // Public key is g^secretKey mod p
        IntegerModP publicKey = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, secretKey);

        return new KeyPair(secretKey, publicKey);
    }

    private IntegerModQ ComputePolynomial(List<KeyPair> keyPairs, int destinationGuardianIndex)
    {
        IntegerModQ sum = new IntegerModQ(0);
        for (int j = 0; j < keyPairs.Count; j++)
        {
            sum += keyPairs[j].SecretKey * IntegerModQ.PowModQ(destinationGuardianIndex, j);
        }

        return sum;
    }

    private (byte[] k1, byte[] k2) ComputeShareEncryptionKeys(byte[] symmetricKey, GuardianIndex sourceIndex, GuardianIndex destinationIndex)
    {
        byte[] k1 = EGHash.Hash(symmetricKey,
            [0x01],
            System.Text.Encoding.UTF8.GetBytes("share_enc_keys"),
            [0x00],
            System.Text.Encoding.UTF8.GetBytes("share_encrypt"),
            sourceIndex,
            destinationIndex,
            [0x02, 0x00]
            );
        byte[] k2 = EGHash.Hash(symmetricKey,
            [0x02],
            System.Text.Encoding.UTF8.GetBytes("share_enc_keys"),
            [0x00],
            System.Text.Encoding.UTF8.GetBytes("share_encrypt"),
            sourceIndex,
            destinationIndex,
            [0x02, 0x00]
            );

        return (k1, k2);
    }

    public void DecryptShares(List<GuardianEncryptedShare> encryptedShares)
    {
        if (_keys == null)
        {
            throw new Exception("Keys not generated.");
        }

        List<IntegerModQ> voteEncryptionPolynomials = new List<IntegerModQ>();
        List<IntegerModQ> otherDataEncryptionPolynomials = new List<IntegerModQ>();

        foreach (var encryptedShare in encryptedShares)
        {
            var gamma = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, encryptedShare.Response) * IntegerModP.PowModP(new IntegerModP(encryptedShare.C0), encryptedShare.Challenge);
            var cBar = EGHash.HashModQ(EGParameters.ParameterBaseHash,
                [0x12],
                encryptedShare.SourceIndex,
                Index,
                gamma,
                encryptedShare.C0,
                encryptedShare.C1
                );

            if (cBar != encryptedShare.Challenge)
            {
                throw new InvalidOperationException($"Could not decrypt guardian {encryptedShare.SourceIndex} shares.");
            }

            var k = EGHash.HashModQ(EGParameters.ParameterBaseHash,
                EGParameters.CryptographicParameters.Q.ToByteArray(true, true),
                [0x11],
                encryptedShare.SourceIndex,
                encryptedShare.DestinationIndex,
                gamma,
                encryptedShare.C0,
                encryptedShare.C1
                ).ToByteArray();

            (byte[] k1, byte[] k2) = ComputeShareEncryptionKeys(k, encryptedShare.SourceIndex, encryptedShare.DestinationIndex);
            byte[] pphPolynomials = encryptedShare.C1.XOR(k1.Concat(k2).ToArray());
            IntegerModQ p = new IntegerModQ(pphPolynomials[..32]);
            IntegerModQ pHat = new IntegerModQ(pphPolynomials[32..]);

            voteEncryptionPolynomials.Add(p);
            otherDataEncryptionPolynomials.Add(pHat);
        }

        voteEncryptionPolynomials.Add(ComputePolynomial(_keys.VoteEncryptionKeyPairs, Index));
        otherDataEncryptionPolynomials.Add(ComputePolynomial(_keys.OtherBallotDataEncryptionKeyPairs, Index));


    }

    private Proof GenerateKeyProof(List<KeyPair> keyPairs, KeyPair communicationKeyPair, string encryptionKeyType)
    {
        List<KeyPair> randomKeyPairs = new List<KeyPair>();
        for (int i = 0; i <= EGParameters.GuardianParameters.K; i++)
        {
            var random = GenerateKeyPair();
            randomKeyPairs.Add(random);
        }

        List<byte[]> bytesToHash = [
            [0x10],
            System.Text.Encoding.UTF8.GetBytes(encryptionKeyType),
            Index,
            // Public keys,
            // communication public key,
            // random public keys
        ];
        bytesToHash.AddRange(keyPairs.Select(x => x.PublicKey.ToByteArray()));
        bytesToHash.Add(communicationKeyPair.PublicKey.ToByteArray());
        bytesToHash.AddRange(randomKeyPairs.Select(x => x.PublicKey.ToByteArray()));

        byte[] challengeHash = EGHash.Hash(EGParameters.ParameterBaseHash, bytesToHash.ToArray());
        IntegerModQ challengeValue = new IntegerModQ(challengeHash);

        List<IntegerModQ> responseValues = new List<IntegerModQ>();
        for (int i = 0; i < EGParameters.GuardianParameters.K; i++)
        {
            var responseValue = randomKeyPairs[i].SecretKey - challengeValue * keyPairs[i].SecretKey;
            responseValues.Add(responseValue);
        }

        var communicationResponseValue = randomKeyPairs[EGParameters.GuardianParameters.K].SecretKey - challengeValue * communicationKeyPair.SecretKey;
        responseValues.Add(communicationResponseValue);

        var proof = new Proof
        {
            Challenge = challengeValue,
            Responses = responseValues.ToArray(),
        };

        return proof;
    }
}

public record Proof
{
    public required IntegerModQ Challenge { get; init; }
    public required IntegerModQ[] Responses { get; init; }
}