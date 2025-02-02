using ElectionGuard.Core.Extensions;
using System.Numerics;

namespace ElectionGuard.Core.Verify;

/// <summary>
/// Verification 1 (Parameter validation)
/// </summary>
public class ParameterValidation
{
    /// <summary>
    /// Performs parameter verification except for the election base hash (which includes the manifest).
    /// Guardians during the key ceremony do not need to validate the manifest because it has not been included yet.
    /// </summary>
    /// <param name="cryptographicParameters"></param>
    /// <param name="guardianParameters"></param>
    /// <param name="manifest"></param>
    /// <param name="parameterBaseHash"></param>
    /// <exception cref="VerificationFailedException"></exception>
    public void Verify(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters, byte[] parameterBaseHash)
    {
        // 1.A
        if (EGParameters.CryptographicParameters.Version != cryptographicParameters.Version)
        {
            throw new VerificationFailedException("1.A", $"Version does not match expected version. Expected: {EGParameters.CryptographicParameters.Version} Actual: {cryptographicParameters.Version}");
        }

        // 1.B
        if (EGParameters.CryptographicParameters.P != cryptographicParameters.P)
        {
            throw new VerificationFailedException("1.B", $"P does not match expected value. Expected: {EGParameters.CryptographicParameters.P} Actual: {cryptographicParameters.P}");
        }

        // 1.C
        if (EGParameters.CryptographicParameters.Q != cryptographicParameters.Q)
        {
            throw new VerificationFailedException("1.C", $"Q does not match expected value. Expected: {EGParameters.CryptographicParameters.Q} Actual: {cryptographicParameters.Q}");
        }

        // 1.D
        if (EGParameters.CryptographicParameters.G != cryptographicParameters.G)
        {
            throw new VerificationFailedException("1.D", $"G does not match expected value. Expected: {EGParameters.CryptographicParameters.G} Actual: {cryptographicParameters.G}");
        }

        // 1.E
        var expectedParameterHash = EGHash.Hash(new Version(cryptographicParameters.Version),
            [0x00],
            cryptographicParameters.P.ToByteArray(),
            cryptographicParameters.Q.ToByteArray(),
            cryptographicParameters.G.ToByteArray(),
            guardianParameters.N.ToByteArray(),
            guardianParameters.K.ToByteArray());

        if (!expectedParameterHash.SequenceEqual(parameterBaseHash))
        {
            throw new VerificationFailedException("1.E", $"Parameter Base Hash does not match expected value. Expected: {Convert.ToHexString(expectedParameterHash)} Actual: {Convert.ToHexString(parameterBaseHash)}");
        }
    }

    /// <summary>
    /// Performs a full parameter verification.
    /// </summary>
    /// <param name="cryptographicParameters"></param>
    /// <param name="guardianParameters"></param>
    /// <param name="manifest"></param>
    /// <param name="parameterBaseHash"></param>
    /// <param name="electionBaseHash"></param>
    /// <exception cref="VerificationFailedException"></exception>
    public void Verify(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters, byte[] parameterBaseHash, byte[] manifest, byte[] electionBaseHash)
    {
        Verify(cryptographicParameters, guardianParameters, parameterBaseHash);

        // 1.F
        var expectedElectionBaseHash = EGHash.Hash(parameterBaseHash,
            [0x01],
            manifest);

        if (expectedElectionBaseHash != electionBaseHash)
        {
            throw new VerificationFailedException("1.F", $"Election Base Hash does not match expected value. Expected: {Convert.ToHexString(expectedElectionBaseHash)} Actual: {Convert.ToHexString(electionBaseHash)}");
        }
    }
}

/// <summary>
/// Verification 2 (Guardian public-key validation)
/// </summary>
public class GuardianPublicKeyValidation
{
    public void Verify(IEnumerable<GuardianPublicView> guardians)
    {
        foreach(var guardian in guardians)
        {
            Verify(guardian);
        }
    }

    public void Verify(GuardianPublicView guardian)
    {
        List<IntegerModP> hValues = new List<IntegerModP>();

        // 2.1
        for(int j = 0; j < EGParameters.GuardianParameters.K; j++)
        {
            IntegerModP hij = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, guardian.VoteEncryptionProof.Responses[j]) * IntegerModP.PowModP(guardian.VoteEncryptionCommitments[j], guardian.VoteEncryptionProof.Challenge);
            hValues.Add(hij);
        }

        // 2.2
        IntegerModP hik = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, guardian.VoteEncryptionProof.Responses[EGParameters.GuardianParameters.K]) * IntegerModP.PowModP(guardian.CommunicationPublicKey, guardian.VoteEncryptionProof.Challenge);
        hValues.Add(hik);

        // 2.3
        for (int j = 0; j < EGParameters.GuardianParameters.K; j++)
        {
            IntegerModP hHatij = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, guardian.OtherDataEncryptionProof.Responses[j]) * IntegerModP.PowModP(guardian.OtherBallotDataEncryptionCommitments[j], guardian.OtherDataEncryptionProof.Challenge);
            hValues.Add(hHatij);
        }

        // 2.2
        IntegerModP hHatik = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, guardian.OtherDataEncryptionProof.Responses[EGParameters.GuardianParameters.K]) * IntegerModP.PowModP(guardian.CommunicationPublicKey, guardian.OtherDataEncryptionProof.Challenge);
        hValues.Add(hHatik);

        // 2.A
        for(int j = 0; j < EGParameters.GuardianParameters.K; j++)
        {
            if (IntegerModP.PowModP(guardian.VoteEncryptionCommitments[j], EGParameters.CryptographicParameters.Q) != new BigInteger(1))
            {
                throw new VerificationFailedException("2.A", "Public commitment is not valid.");
            }
        }

        for (int j = 0; j < EGParameters.GuardianParameters.K; j++)
        {
            if (IntegerModP.PowModP(guardian.OtherBallotDataEncryptionCommitments[j], EGParameters.CryptographicParameters.Q) != new BigInteger(1))
            {
                throw new VerificationFailedException("2.A", "Public commitment is not valid.");
            }
        }

        if (IntegerModP.PowModP(guardian.CommunicationPublicKey, EGParameters.CryptographicParameters.Q) != new BigInteger(1))
        {
            throw new VerificationFailedException("2.A", "Communication public key is not valid.");
        }

        // 2.B
        for(int j = 0; j <= guardian.VoteEncryptionProof.Responses.Length; j++)
        {
            // Because all objects are already IntegerModQ, this is already true for the time being.
        }

        // 2.C
        List<byte[]> cBytes = [
            [0x10],
            System.Text.Encoding.UTF8.GetBytes("pk_vote"),
            guardian.Index,
        ];
        cBytes.AddRange(guardian.VoteEncryptionCommitments.Select(c => c.ToByteArray()));
        cBytes.Add(guardian.CommunicationPublicKey);
        cBytes.AddRange(hValues.Select(h => h.ToByteArray()));

        IntegerModQ ci = EGHash.HashModQ(EGParameters.ParameterBaseHash, cBytes.ToArray());
        if(ci != guardian.VoteEncryptionProof.Challenge)
        {
            throw new VerificationFailedException("2.C", "Challenge value Ci was not computed correctly.");
        }

        List<byte[]> cHatBytes = [
            [0x10],
            System.Text.Encoding.UTF8.GetBytes("pk_data"),
            guardian.Index,
        ];
        cHatBytes.AddRange(guardian.OtherBallotDataEncryptionCommitments.Select(c => c.ToByteArray()));
        cHatBytes.Add(guardian.CommunicationPublicKey);
        cHatBytes.AddRange(hValues.Select(h => h.ToByteArray()));

        IntegerModQ cHati = EGHash.HashModQ(EGParameters.ParameterBaseHash, cHatBytes.ToArray());
        if (cHati != guardian.OtherDataEncryptionProof.Challenge)
        {
            throw new VerificationFailedException("2.C", "Challenge value CHati was not computed correctly.");
        }
    }
}