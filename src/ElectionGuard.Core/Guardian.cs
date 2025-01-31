using System.Numerics;
using System.Security.Cryptography;

namespace ElectionGuard.Core;

public class Guardian
{
    public Guardian(ElectionGuardCryptoFactory cryptoFactory, GuardianParameters guardianParameters, ParameterBaseHash parameterBaseHash, GuardianIndex index)
    {
        _cryptoFactory = cryptoFactory;
        _guardianParameters = guardianParameters;
        _parameterBaseHash = parameterBaseHash;

        if (index < 0 || index > guardianParameters.N)
        {
            throw new ArgumentOutOfRangeException(nameof(index), $"Guardian index must be between 0 and N ({guardianParameters.N}).");
        }

        Index = index;
    }

    public GuardianIndex Index { get; }

    private ElectionGuardCryptoFactory _cryptoFactory;
    private GuardianParameters _guardianParameters;
    private ParameterBaseHash _parameterBaseHash;

    public List<KeyPair> _voteEncryptionKeyPairs = new List<KeyPair>();
    public List<KeyPair> _otherBallotDataKeyPairs = new List<KeyPair>();
    public KeyPair _communicationKeyPair;

    public Proof VoteEncryptionKeyProof { get; private set; }
    public Proof OtherDataEncryptionKeyProof { get; private set; }

    public GuardianPublicView PublicDto
    {
        get
        {
            return new GuardianPublicView
            {
                Index = Index,
                VoteEncryptionPublicKey = _voteEncryptionKeyPairs[0].PublicKey,
                OtherDataEncryptionPublicKey = _otherBallotDataKeyPairs[0].PublicKey,
                CommunicationPublicKey = _communicationKeyPair.PublicKey,
                VoteEncryptionProof = VoteEncryptionKeyProof,
                OtherDataEncryptionProof = OtherDataEncryptionKeyProof,
            };
        }
    }

    public void GenerateKeys()
    {
        // The first coefficient/committment is our private / secret key for the guardian.
        for (int i = 0; i < _guardianParameters.K; i++)
        {
            var keyPair = _cryptoFactory.GenerateKeyPair();
            this._voteEncryptionKeyPairs.Add(keyPair);
        }

        for (int i = 0; i < _guardianParameters.K; i++)
        {
            var keyPair = _cryptoFactory.GenerateKeyPair();
            this._otherBallotDataKeyPairs.Add(keyPair);
        }

        this._communicationKeyPair = _cryptoFactory.GenerateKeyPair();

        // Generate a NIZK proof for voteEncryptionKeys
        VoteEncryptionKeyProof = GenerateKeyProof(_voteEncryptionKeyPairs, _communicationKeyPair, "pk_vote");
        OtherDataEncryptionKeyProof = GenerateKeyProof(_otherBallotDataKeyPairs, _communicationKeyPair, "pk_data");
    }

    public List<GuardianEncryptedShare> EncryptShares(List<GuardianPublicView> guardians)
    {
        List<GuardianEncryptedShare> encryptedShares = new List<GuardianEncryptedShare>();

        foreach (var guardian in guardians)
        {
            var keyPair = _cryptoFactory.GenerateKeyPair();
            IntegerModQ nonce = keyPair.SecretKey;
            IntegerModP alpha = keyPair.PublicKey;

            IntegerModP beta = IntegerModP.PowModP(guardian.CommunicationPublicKey, nonce);
            var symmetricKey = EGHash.Hash(_parameterBaseHash,
                [0x11],
                Index,
                guardian.Index,
                guardian.CommunicationPublicKey,
                alpha,
                beta
                );

            (byte[] k1, byte[] k2) = ComputeShareEncryptionKeys(symmetricKey, Index, guardian.Index);

            IntegerModP c0 = alpha;
            var c1a = ComputePolynomial(_voteEncryptionKeyPairs, guardian.Index).ToByteArray().XOR(k1);
            var c1b = ComputePolynomial(_otherBallotDataKeyPairs, guardian.Index).ToByteArray().XOR(k2);
            var c1 = new byte[c1a.Length + c1b.Length];
            Buffer.BlockCopy(c1a, 0, c1, 0, c1a.Length);
            Buffer.BlockCopy(c1b, 0, c1, c1a.Length, c1b.Length);

            var proof = _cryptoFactory.GenerateKeyPair();
            var uBar = proof.SecretKey;
            var gamma = proof.PublicKey;
            var challengeValue = EGHash.Hash(_parameterBaseHash,
                [0x12],
                Index,
                guardian.Index,
                gamma,
                c0,
                c1
                );
            var cBar = new IntegerModQ(challengeValue, _cryptoFactory.Q);
            var vBar = uBar - (cBar * nonce);

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

    private IntegerModQ ComputePolynomial(List<KeyPair> keyPairs, int destinationGuardianIndex)
    {
        IntegerModQ sum = new IntegerModQ(0, _cryptoFactory.Q);
        for (int i = 0; i < keyPairs.Count; i++)
        {
            sum += keyPairs[i].SecretKey * IntegerModQ.Pow(destinationGuardianIndex, i, _cryptoFactory.Q);
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
        List<IntegerModQ> voteEncryptionPolynomials = new List<IntegerModQ>();
        List<IntegerModQ> otherDataEncryptionPolynomials = new List<IntegerModQ>();

        foreach (var encryptedShare in encryptedShares)
        {
            var gamma = IntegerModP.PowModP(_cryptoFactory.G, encryptedShare.Response) * IntegerModP.PowModP(new IntegerModP(encryptedShare.C0.AsBigInteger(), _cryptoFactory.P), encryptedShare.Challenge);
            var challengeValue = EGHash.Hash(_parameterBaseHash,
                [0x12],
                encryptedShare.SourceIndex,
                Index,
                gamma,
                encryptedShare.C0,
                encryptedShare.C1
                );
            var cBar = new BigInteger(challengeValue, true, true).Mod(_cryptoFactory.Q);

            if (cBar != encryptedShare.Challenge)
            {
                throw new InvalidOperationException($"Could not decrypt guardian {encryptedShare.SourceIndex} shares.");
            }

            var k = EGHash.HashMod(_parameterBaseHash,
                _cryptoFactory.Q,
                [0x11],
                encryptedShare.SourceIndex,
                encryptedShare.DestinationIndex,
                gamma,
                encryptedShare.C0,
                encryptedShare.C1
                ).ToByteArray(true, true);

            (byte[] k1, byte[] k2) = ComputeShareEncryptionKeys(k, encryptedShare.SourceIndex, encryptedShare.DestinationIndex);
            byte[] pphPolynomials = encryptedShare.C1.XOR(k1.Concat(k2).ToArray());
            IntegerModQ p = new IntegerModQ(pphPolynomials[..32], _cryptoFactory.Q);
            IntegerModQ pHat = new IntegerModQ(pphPolynomials[32..], _cryptoFactory.Q);

            voteEncryptionPolynomials.Add(p);
            otherDataEncryptionPolynomials.Add(pHat);
        }

        voteEncryptionPolynomials.Add(ComputePolynomial(_voteEncryptionKeyPairs, Index));
        otherDataEncryptionPolynomials.Add(ComputePolynomial(_otherBallotDataKeyPairs, Index));


    }

    private Proof GenerateKeyProof(List<KeyPair> keyPairs, KeyPair communicationKeyPair, string encryptionKeyType)
    {
        List<KeyPair> randomKeyPairs = new List<KeyPair>();
        for (int i = 0; i <= _guardianParameters.K; i++)
        {
            var random = _cryptoFactory.GenerateKeyPair();
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

        byte[] challengeHash = EGHash.Hash(_parameterBaseHash, bytesToHash.ToArray());
        BigInteger challengeValue = new BigInteger(challengeHash, true, true).Mod(_cryptoFactory.Q);

        List<BigInteger> responseValues = new List<BigInteger>();
        for (int i = 0; i < _guardianParameters.K; i++)
        {
            var responseValue = (randomKeyPairs[i].SecretKey - (challengeValue * keyPairs[i].SecretKey).Mod(_cryptoFactory.Q)).Mod(_cryptoFactory.Q);
            responseValues.Add(responseValue);
        }

        var communicationResponseValue = (randomKeyPairs[_guardianParameters.K].SecretKey - (challengeValue * communicationKeyPair.SecretKey).Mod(_cryptoFactory.Q)).Mod(_cryptoFactory.Q);
        responseValues.Add(communicationResponseValue);

        var proof = new Proof
        {
            Challenge = challengeValue,
            Responses = responseValues.ToArray(),
            RandomPublicValues = randomKeyPairs.Select(x => (BigInteger)x.PublicKey).ToArray(),
        };

        return proof;
    }
}

public record Proof
{
    public required BigInteger Challenge { get; init; }
    public required BigInteger[] Responses { get; init; }
    public required BigInteger[] RandomPublicValues { get; init; }
}

public static class BigIntegerRandomNumberGenerator
{
    public static BigInteger GetUnsigned(this BigInteger max)
    {
        // Naive implementation for now. Generate a random bigint with the correct number of bytes, 
        // and return it if it is within our requested bounds.
        // A better implementation would probably carry over insignificant 0 bits at least.
        while (true)
        {
            var randomBytes = RandomNumberGenerator.GetBytes(max.GetByteCount(true));
            var b = new BigInteger(randomBytes, true, true);
            if (b < max)
            {
                return b;
            }
        }
    }
}