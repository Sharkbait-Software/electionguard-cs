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
        ArgumentNullException.ThrowIfNull(index);

        // §3.2.1: guardians are G_1..G_n. GuardianIndex already rejects anything below 1, which
        // matters most: the share sent to index 0 would be P_i(0) = s_i, the secret key itself.
        if (index.Index < 1 || index.Index > EGParameters.GuardianParameters.N)
        {
            throw new ArgumentOutOfRangeException(nameof(index), index.Index, $"Guardian index must be between 1 and n ({EGParameters.GuardianParameters.N}).");
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

    /// <summary>
    /// §3.2.2 share encryption: encrypts P_i(l) and P-hat_i(l) to "each other guardian G_l
    /// (1 &lt;= l &lt;= n, l != i)". <paramref name="guardians"/> must therefore be exactly the other
    /// n - 1 guardians, each once. A share is a point on this guardian's secret polynomials, so
    /// evaluating at an index outside that set is refused outright: index 0 would give away s_i,
    /// and k extra points would give away the whole polynomial.
    /// </summary>
    public List<GuardianEncryptedShare> EncryptShares(List<GuardianPublicView> guardians)
    {
        if (_keys == null)
        {
            throw new Exception("Keys not generated.");
        }

        ArgumentNullException.ThrowIfNull(guardians);
        RequireOtherGuardians(guardians.Select(x => x.Index), nameof(guardians), "guardian view");

        // A copy: this guardian's own view of the other guardians' key data, compared with the
        // guardian record in Verify. The caller's list is left as it was.
        _guardians = new List<GuardianPublicView>(guardians);

        List<GuardianEncryptedShare> encryptedShares = new List<GuardianEncryptedShare>();

        foreach (var guardian in guardians)
        {
            var keyPair = KeyPair.GenerateRandom();
            IntegerModQ epsilon = keyPair.SecretKey;
            IntegerModP alpha = keyPair.PublicKey;

            IntegerModP beta = MontgomeryModP.PowModP(guardian.CommunicationPublicKey, epsilon);
            var symmetricKey = ComputeShareSecretKey(EGParameters.ParameterBaseHash, Index, guardian.Index, guardian.CommunicationPublicKey, alpha, beta);

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

    /// <summary>
    /// §3.2.2 share decryption and eq. (24): z_i is the sum of exactly n shares, one from each
    /// guardian. <paramref name="encryptedShares"/> must therefore hold exactly one share from each
    /// of the other n - 1 guardians, all addressed to this guardian; a missing or repeated share
    /// would otherwise give a wrong z_i here and an unattributable decryption failure much later.
    /// </summary>
    public GuardianSecretShares DecryptShares(List<GuardianEncryptedShare> encryptedShares)
    {
        if (_keys == null)
        {
            throw new Exception("Keys not generated.");
        }

        ArgumentNullException.ThrowIfNull(encryptedShares);
        foreach (var encryptedShare in encryptedShares)
        {
            if (encryptedShare.DestinationIndex != Index)
            {
                throw new ArgumentException($"The share from guardian {encryptedShare.SourceIndex.Index} is addressed to guardian {encryptedShare.DestinationIndex.Index}, not to this guardian ({Index.Index}).", nameof(encryptedShares));
            }
        }
        RequireOtherGuardians(encryptedShares.Select(x => x.SourceIndex), nameof(encryptedShares), "share");

        _voteEncryptionSharePolynomials = new List<SharePolynomial>();
        _otherBallotDataEncryptionSharePolynomials = new List<SharePolynomial>();

        foreach (var encryptedShare in encryptedShares)
        {
            var gamma = MontgomeryModP.PowModP(EGParameters.G, encryptedShare.Response) * MontgomeryModP.PowModP(new IntegerModP(encryptedShare.C0), encryptedShare.Challenge);
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
                throw new InvalidOperationException($"Could not decrypt guardian {encryptedShare.SourceIndex.Index} shares.");
            }

            var alpha = new IntegerModP(encryptedShare.C0);
            var beta = MontgomeryModP.PowModP(alpha, _keys.CommunicationKeyPair.SecretKey);

            // l in eqs. (16)-(18) is this guardian's own index; DestinationIndex was checked equal to it above.
            var k = ComputeShareSecretKey(EGParameters.ParameterBaseHash, encryptedShare.SourceIndex, Index, _keys.CommunicationKeyPair.PublicKey, alpha, beta);

            (byte[] k1, byte[] k2) = ComputeShareEncryptionKeys(k, encryptedShare.SourceIndex, Index);
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

    /// <summary>
    /// §3.2.2 "Share verification and the guardian record": this guardian's checks of the
    /// preliminary guardian record, in the spec's order.
    /// <list type="number">
    /// <item>Verification 1 (1.A-1.F), which checks H_P and H_B, then the comparison of the record's
    /// key data with this guardian's own view through H_G (eq. 27), keyed with H_B.</item>
    /// <item>Verification 2 for every guardian.</item>
    /// <item>Verification 3.</item>
    /// <item>Every share P_i(l) and P-hat_i(l), 1 &lt;= i &lt;= n, against G_i's commitments (eqs. 28, 29).</item>
    /// </list>
    /// Verification 1 and steps 2 and 3 throw <see cref="VerificationFailedException"/>; the H_G
    /// comparison and step 4 throw <see cref="KeyCeremonyException"/>, naming the guardian at fault
    /// where one can be named.
    /// </summary>
    /// <param name="record">The preliminary guardian record the administrator presents.</param>
    /// <param name="manifestFile">
    /// This guardian's own copy of the manifest file, if it holds one. Its H_B then keys the
    /// own-view side of H_G, so a record built over a different manifest fails step 1. Without it,
    /// both sides are keyed with the record's H_B, which Verification 1.F has just checked against
    /// the record's manifest file.
    /// </param>
    public void Verify(GuardianRecord record, ManifestFile? manifestFile = null)
    {
        if (_keys == null || _guardians == null || _voteEncryptionSharePolynomials == null || _otherBallotDataEncryptionSharePolynomials == null)
        {
            throw new Exception("Don't have original guardian data to compare against the guardian record.");
        }

        ArgumentNullException.ThrowIfNull(record);

        // Step 1, second half: "Guardian G_l also verifies the correctness of the base hash H_B by
        // performing Verification 1." Done first, so that H_B is known good before it keys H_G, and
        // so that a wrong H_B is reported as 1.F rather than as a key-data mismatch.
        var parameterVerification = new ParameterVerification();
        parameterVerification.Verify(record);

        // Step 1: compare all key data in the record with this guardian's own view, as H_G (eq. 27).
        // _guardians holds every guardian's public view as this guardian received it, its own included.
        byte[] ownElectionBaseHash = manifestFile is null
            ? record.ElectionBaseHash
            : ElectionBaseHash.Compute(EGParameters.ParameterBaseHash, manifestFile.Bytes);
        var ownGuardianViews = _guardians.OrderBy(x => x.Index.Index).ToList();
        foreach (var view in ownGuardianViews)
        {
            RequireOwnViewShape(view);
        }

        var ownElectionPublicKeys = new ElectionPublicKeys(
            ownGuardianViews.Select(x => x.VoteEncryptionCommitments[0]),
            ownGuardianViews.Select(x => x.OtherBallotDataEncryptionCommitments[0]));
        var ownRecordHash = ComputeGuardianRecordHash(ownElectionBaseHash, ownElectionPublicKeys, ownGuardianViews);
        var recordHash = ComputeGuardianRecordHash(record.ElectionBaseHash, record.ElectionPublicKeys, record.Guardians);

        if (!ownRecordHash.SequenceEqual(recordHash))
        {
            throw new KeyCeremonyException(1, null, "Original guardian values did not match values in the guardian record.");
        }

        // Step 2: Verification 2, which also requires the record to hold exactly G_1..G_n.
        var guardianVerification = new GuardianPublicKeyVerification();
        guardianVerification.Verify(record.Guardians);

        // Step 3: Verification 3.
        var electionKeyVerification = new ElectionPublicKeyVerification();
        electionKeyVerification.Verify(record.Guardians, record.ElectionPublicKeys);

        // Step 4: every share against its sender's commitments, "for all 1 <= i <= n" (eqs. 28, 29),
        // this guardian's own P_l(l) included. DecryptShares took exactly one share from each other
        // guardian and Verification 2 has just required one record entry per guardian, so each
        // lookup below finds exactly one.
        for (int i = 1; i <= EGParameters.GuardianParameters.N; i++)
        {
            var source = new GuardianIndex(i);
            var sender = record.Guardians.Single(x => x.Index == source);

            var share = _voteEncryptionSharePolynomials.Single(x => x.SourceIndex == source);
            if (MontgomeryModP.PowModP(EGParameters.G, share.Value) != EvaluateCommitments(sender.VoteEncryptionCommitments, Index))
            {
                throw new KeyCeremonyException(4, source, $"Could not verify vote encryption polynomial against commitments for index: {i}.");
            }

            var shareHat = _otherBallotDataEncryptionSharePolynomials.Single(x => x.SourceIndex == source);
            if (MontgomeryModP.PowModP(EGParameters.G, shareHat.Value) != EvaluateCommitments(sender.OtherBallotDataEncryptionCommitments, Index))
            {
                throw new KeyCeremonyException(4, source, $"Could not verify other ballot data encryption polynomial against commitments for index: {i}.");
            }
        }
    }

    /// <summary>
    /// Step 1 compares key data of a fixed shape: k commitments K_{i,0..k-1} and k commitments
    /// K-hat_{i,0..k-1} per guardian (eqs. 9, 10, 27). EncryptShares reads only a peer view's index
    /// and communication key, so a view of any other shape reaches Verify unchecked. It is reported
    /// here, against the guardian whose view it is, before K = prod K_{i,0} indexes into it; the
    /// record's own shape is Verification 2's to check (2.A).
    /// </summary>
    private static void RequireOwnViewShape(GuardianPublicView view)
    {
        int k = EGParameters.GuardianParameters.K;
        int voteCount = view.VoteEncryptionCommitments?.Count ?? 0;
        int ballotDataCount = view.OtherBallotDataEncryptionCommitments?.Count ?? 0;

        if (voteCount != k || ballotDataCount != k)
        {
            throw new KeyCeremonyException(1, view.Index, $"The view this guardian received of guardian {view.Index.Index} has {voteCount} vote encryption and {ballotDataCount} other ballot data encryption commitments; k = {k} of each are required.");
        }
    }

    /// <summary>
    /// Eq. (14): g^{P_i(l)} = prod_j K_{i,j}^(l^j) mod p, from the published commitments alone. The
    /// exponents l^j are small public values (Note 3.3), so this is a plain ModPow.
    /// </summary>
    private static IntegerModP EvaluateCommitments(List<IntegerModP> commitments, int l)
    {
        return commitments
            .Select((x, j) => IntegerModP.PowModP(x, BigInteger.Pow(l, j)))
            .Product();
    }

    /// <summary>
    /// §3.2.2 eq. (27): H_G = H(H_B; 0x13, K, K-hat, K_{1,0}, ..., K_{n,k-1}, K-hat_{1,0}, ...,
    /// K-hat_{n,k-1}, kappa_1, ..., kappa_n), the comparison hash of a guardian record's key data,
    /// 1 + (2 + 2nk + n) * 512 bytes hashed (§5.5.2). Guardians are taken in index order whatever
    /// order <paramref name="guardians"/> lists them in, and each guardian's commitments in list
    /// order (j = 0..k-1). It hashes what it is given; the shape of the set is Verification 2's to
    /// check.
    /// </summary>
    internal static byte[] ComputeGuardianRecordHash(byte[] electionBaseHash, ElectionPublicKeys electionPublicKeys, IEnumerable<GuardianPublicView> guardians)
    {
        var ordered = guardians.OrderBy(x => x.Index.Index).ToList();

        List<byte[]> valuesToHash = [
            [0x13],
            electionPublicKeys.VoteEncryptionKey,
            electionPublicKeys.OtherBallotDataEncryptionKey,
        ];
        valuesToHash.AddRange(ordered.SelectMany(x => x.VoteEncryptionCommitments).Select(x => x.ToByteArray()));
        valuesToHash.AddRange(ordered.SelectMany(x => x.OtherBallotDataEncryptionCommitments).Select(x => x.ToByteArray()));
        valuesToHash.AddRange(ordered.Select(x => x.CommunicationPublicKey.ToByteArray()));

        return EGHash.Hash(electionBaseHash, valuesToHash.ToArray());
    }

    /// <summary>
    /// Requires <paramref name="indices"/> to be exactly {1..n} minus this guardian's own index, each
    /// once: one entry for every other guardian G_l, 1 &lt;= l &lt;= n, l != i (§3.2.2).
    /// </summary>
    private void RequireOtherGuardians(IEnumerable<GuardianIndex> indices, string parameterName, string what)
    {
        int n = EGParameters.GuardianParameters.N;
        var seen = new bool[n + 1];
        int count = 0;

        foreach (var index in indices)
        {
            int l = index.Index;
            if (l < 1 || l > n)
            {
                throw new ArgumentException($"A {what} for guardian {l} was given, but guardian indices run from 1 to n ({n}).", parameterName);
            }

            if (l == Index.Index)
            {
                throw new ArgumentException($"A {what} for this guardian itself ({l}) was given; only the other guardians take part here.", parameterName);
            }

            if (seen[l])
            {
                throw new ArgumentException($"More than one {what} for guardian {l} was given.", parameterName);
            }

            seen[l] = true;
            count++;
        }

        if (count != n - 1)
        {
            var missing = Enumerable.Range(1, n).Where(l => l != Index.Index && !seen[l]);
            throw new ArgumentException($"Expected a {what} from each of the other {n - 1} guardians; missing guardian(s) {string.Join(", ", missing)}.", parameterName);
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

    /// <summary>
    /// §3.2.2 eq. (16): the secret key k_{i,l} = H(H_P; 0x11, b(i, 4), b(l, 4), kappa_l, alpha, beta)
    /// from which guardian i's share encryption keys for guardian l are derived, 1545 bytes hashed
    /// (§5.5.2). It is a full 32-byte H, not H_q: both the encrypting and the decrypting guardian
    /// come through here so that they cannot derive it differently.
    /// </summary>
    internal static byte[] ComputeShareSecretKey(byte[] parameterBaseHash, int sourceIndex, int destinationIndex, IntegerModP destinationCommunicationKey, IntegerModP alpha, IntegerModP beta)
    {
        return EGHash.Hash(parameterBaseHash,
            [0x11],
            sourceIndex.ToByteArray(),
            destinationIndex.ToByteArray(),
            destinationCommunicationKey,
            alpha,
            beta
            );
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