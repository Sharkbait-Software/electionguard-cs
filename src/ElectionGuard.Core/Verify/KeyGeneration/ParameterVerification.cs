using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using Version = ElectionGuard.Core.Models.Version;

namespace ElectionGuard.Core.Verify.KeyGeneration;

/// <summary>
/// Verification 1 (Parameter validation)
/// </summary>
public class ParameterVerification
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
