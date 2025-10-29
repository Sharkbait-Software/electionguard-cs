using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.KeyGeneration;
using System.Numerics;

namespace ElectionGuard.Core.KeyGeneration;

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

    private List<GuardianPublicView>? _guardians = null;
    private List<SharePolynomial>? _voteEncryptionSharePolynomials = null;
    private List<SharePolynomial>? _otherBallotDataEncryptionSharePolynomials = null;

    public GuardianKeys GenerateKeys()
    {
        // The first coefficient/committment is our private / secret key for the guardian.
        List<KeyPair> voteEncryptionKeyPairs = new List<KeyPair>();
        for (int i = 0; i < EGParameters.GuardianParameters.K; i++)
        {
            var keyPair = KeyPair.GenerateRandom();
            voteEncryptionKeyPairs.Add(keyPair);
        }

        List<KeyPair> otherBallotDataEncryptionKeyPairs = new List<KeyPair>();
        for (int i = 0; i < EGParameters.GuardianParameters.K; i++)
        {
            var keyPair = KeyPair.GenerateRandom();
            otherBallotDataEncryptionKeyPairs.Add(keyPair);
        }

        var communicationKeyPair = KeyPair.GenerateRandom();

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

        _guardians = guardians;

        List<GuardianEncryptedShare> encryptedShares = new List<GuardianEncryptedShare>();

        foreach (var guardian in guardians)
        {
            var keyPair = KeyPair.GenerateRandom();
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

            var proof = KeyPair.GenerateRandom();
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

        _guardians.Add(_keys.ToPublicView());

        return encryptedShares;
    }

    public GuardianSecretShares DecryptShares(List<GuardianEncryptedShare> encryptedShares)
    {
        if (_keys == null)
        {
            throw new Exception("Keys not generated.");
        }

        _voteEncryptionSharePolynomials = new List<SharePolynomial>();
        _otherBallotDataEncryptionSharePolynomials = new List<SharePolynomial>();

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

            var alpha = new IntegerModP(encryptedShare.C0);
            var beta = IntegerModP.PowModP(alpha, _keys.CommunicationKeyPair.SecretKey);

            var k = EGHash.HashModQ(EGParameters.ParameterBaseHash,
                [0x11],
                encryptedShare.SourceIndex,
                encryptedShare.DestinationIndex,
                _keys.CommunicationKeyPair.PublicKey,
                alpha,
                beta
                ).ToByteArray();

            (byte[] k1, byte[] k2) = ComputeShareEncryptionKeys(k, encryptedShare.SourceIndex, encryptedShare.DestinationIndex);
            byte[] pphPolynomials = encryptedShare.C1.XOR(k1.Concat(k2).ToArray());
            IntegerModQ p = new IntegerModQ(pphPolynomials[..32]);
            IntegerModQ pHat = new IntegerModQ(pphPolynomials[32..]);

            _voteEncryptionSharePolynomials.Add(new SharePolynomial { SourceIndex = encryptedShare.SourceIndex, Value = p });
            _otherBallotDataEncryptionSharePolynomials.Add(new SharePolynomial { SourceIndex = encryptedShare.SourceIndex, Value = pHat });
        }

        _voteEncryptionSharePolynomials.Add(new SharePolynomial { SourceIndex = Index, Value = ComputePolynomial(_keys.VoteEncryptionKeyPairs, Index) });
        _otherBallotDataEncryptionSharePolynomials.Add(new SharePolynomial { SourceIndex = Index, Value = ComputePolynomial(_keys.OtherBallotDataEncryptionKeyPairs, Index) });

        IntegerModQ zi = _voteEncryptionSharePolynomials.Select(x => x.Value).Sum();
        IntegerModQ ẑi = _otherBallotDataEncryptionSharePolynomials.Select(x => x.Value).Sum();

        return new GuardianSecretShares
        {
            VoteEncryptionKeyShare = zi,
            OtherBallotDataEncryptionKeyShare = ẑi,
        };
    }

    public void Verify(GuardianRecord record)
    {
        if (_guardians == null || _voteEncryptionSharePolynomials == null || _otherBallotDataEncryptionSharePolynomials == null)
        {
            throw new Exception("Don't have original guardian data to compare against the guardian record.");
        }

        // 1. Verify that the guardian record matches original data we received.
        var originalGuardianViews = _guardians.OrderBy(x => (int)x.Index);
        var originalElectionPublicKeys = new ElectionPublicKeys(originalGuardianViews.SelectMany(x => x.VoteEncryptionCommitments), originalGuardianViews.SelectMany(x => x.OtherBallotDataEncryptionCommitments));
        List<byte[]> originalValuesToHash = [
            [0x13],
            originalElectionPublicKeys.VoteEncryptionKey,
            originalElectionPublicKeys.OtherBallotDataEncryptionKey,
        ];
        originalValuesToHash.AddRange(originalGuardianViews.SelectMany(x => x.VoteEncryptionCommitments).Select(x => x.ToByteArray()));
        originalValuesToHash.AddRange(originalGuardianViews.SelectMany(x => x.OtherBallotDataEncryptionCommitments).Select(x => x.ToByteArray()));
        originalValuesToHash.AddRange(originalGuardianViews.Select(x => x.CommunicationPublicKey.ToByteArray()));
        var originalValuesHash = EGHash.Hash(EGParameters.ParameterBaseHash, originalValuesToHash.ToArray());

        var guardians = record.Guardians.OrderBy(x => (int)x.Index);
        List<byte[]> valuesToHash = [
            [0x13],
            record.ElectionPublicKeys.VoteEncryptionKey,
            record.ElectionPublicKeys.OtherBallotDataEncryptionKey,
        ];
        valuesToHash.AddRange(guardians.SelectMany(x => x.VoteEncryptionCommitments).Select(x => x.ToByteArray()));
        valuesToHash.AddRange(guardians.SelectMany(x => x.OtherBallotDataEncryptionCommitments).Select(x => x.ToByteArray()));
        valuesToHash.AddRange(guardians.Select(x => x.CommunicationPublicKey.ToByteArray()));
        var valuesHash = EGHash.Hash(EGParameters.ParameterBaseHash, originalValuesToHash.ToArray());

        if (!originalValuesHash.SequenceEqual(valuesHash))
        {
            throw new Exception("Original guardian values did not match values in the guardian record.");
        }

        // Verification 1
        var parameterVerification = new ParameterVerification();
        parameterVerification.Verify(record.CryptographicParameters, record.GuardianParameters, record.ParameterBaseHash);

        // Verification 2
        var guardianVerification = new GuardianPublicKeyVerification();
        guardianVerification.Verify(record.Guardians);

        // Verification 3
        var electionKeyVerification = new ElectionPublicKeyVerification();
        electionKeyVerification.Verify(record.Guardians, record.ElectionPublicKeys);

        // Verify decrypted shares against that guardians' commitments.
        foreach (var polynomial in _voteEncryptionSharePolynomials)
        {
            IntegerModP p = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, polynomial.Value);
            IntegerModP p2 = guardians.Single(x => x.Index == polynomial.SourceIndex)
                .VoteEncryptionCommitments
                    .Select((x, j) => IntegerModP.PowModP(x, BigInteger.Pow(Index.Index, j)))
                .Product();
            if (p != p2)
            {
                throw new Exception($"Could not verify vote encryption polynomial against commitments for index: {polynomial.SourceIndex.Index}.");
            }
        }

        foreach (var polynomial in _otherBallotDataEncryptionSharePolynomials)
        {
            IntegerModP p = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, polynomial.Value);
            IntegerModP p2 = guardians.Single(x => x.Index == polynomial.SourceIndex)
                .OtherBallotDataEncryptionCommitments
                    .Select((x, j) => IntegerModP.PowModP(x, BigInteger.Pow(Index.Index, j)))
                .Product();
            if (p != p2)
            {
                throw new Exception($"Could not verify other ballot data encryption polynomial against commitments for index: {polynomial.SourceIndex.Index}.");
            }
        }
    }

    private IntegerModQ ComputePolynomial(List<KeyPair> keyPairs, int destinationGuardianIndex)
    {
        var result = new IntegerModQ(0);
        var power = new IntegerModQ(1);

        foreach(var keyPair in keyPairs)
        {
            var term = keyPair.SecretKey * power;
            result += term;
            power *= destinationGuardianIndex;
        }
        return result;
        //return keyPairs.Select((x, j) => new IntegerModQ(x.SecretKey * BigInteger.Pow(destinationGuardianIndex, j))).Sum();
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

    private SchnorrProof GenerateKeyProof(List<KeyPair> keyPairs, KeyPair communicationKeyPair, string encryptionKeyType)
    {
        List<KeyPair> randomKeyPairs = new List<KeyPair>();
        for (int i = 0; i <= EGParameters.GuardianParameters.K; i++)
        {
            var random = KeyPair.GenerateRandom();
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

        IntegerModQ challengeValue = EGHash.HashModQ(EGParameters.ParameterBaseHash, bytesToHash.ToArray());

        List<IntegerModQ> responseValues = new List<IntegerModQ>();
        for (int i = 0; i < EGParameters.GuardianParameters.K; i++)
        {
            var responseValue = randomKeyPairs[i].SecretKey - challengeValue * keyPairs[i].SecretKey;
            responseValues.Add(responseValue);
        }

        var communicationResponseValue = randomKeyPairs[EGParameters.GuardianParameters.K].SecretKey - challengeValue * communicationKeyPair.SecretKey;
        responseValues.Add(communicationResponseValue);

        var proof = new SchnorrProof
        {
            Challenge = challengeValue,
            Responses = responseValues.ToArray(),
        };

        return proof;
    }
}

public class SharePolynomial
{
    public required GuardianIndex SourceIndex { get; init; }
    public required IntegerModQ Value { get; init; }
}