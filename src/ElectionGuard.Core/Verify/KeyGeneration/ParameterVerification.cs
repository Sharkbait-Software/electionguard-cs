using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using Version = ElectionGuard.Core.Models.Version;

namespace ElectionGuard.Core.Verify.KeyGeneration;

/// <summary>
/// Verification 1 (Parameter validation)
/// </summary>
public class ParameterVerification
{
    /// <summary>
    /// The full Verification 1 (1.A-1.F) for an election record: the parameters it claims, its H_P,
    /// and its H_B against its manifest file. This is the entry point verifiers use.
    /// </summary>
    public void Verify(EncryptionRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        Verify(record.CryptographicParameters, record.GuardianParameters, record.ParameterBaseHash, record.ManifestFile.Bytes, record.ElectionBaseHash);
    }

    /// <summary>
    /// The full Verification 1 (1.A-1.F) for a preliminary guardian record. §3.2.2 step 1 has every
    /// guardian check H_B this way before it accepts the record.
    /// </summary>
    public void Verify(GuardianRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        Verify(record.CryptographicParameters, record.GuardianParameters, record.ParameterBaseHash, record.ManifestFile.Bytes, record.ElectionBaseHash);
    }

    /// <summary>
    /// Verification 1.A-1.E: the version, p, q and g, and H_P. Leaves out 1.F, the election base
    /// hash; a complete Verification 1 also needs the manifest and H_B, which the record overloads
    /// supply.
    /// </summary>
    /// <exception cref="VerificationFailedException"></exception>
    public void Verify(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters, byte[] parameterBaseHash)
    {
        // 1.A
        if (EGParameters.CryptographicParameters.Version != cryptographicParameters.Version)
        {
            throw new VerificationFailedException("1.A", $"Version does not match expected version. Expected: {EGParameters.CryptographicParameters.Version} Actual: {cryptographicParameters.Version}");
        }

        // 1.B
        if (EGParameters.P != cryptographicParameters.P)
        {
            throw new VerificationFailedException("1.B", $"P does not match expected value. Expected: {EGParameters.P} Actual: {cryptographicParameters.P}");
        }

        // 1.C
        if (EGParameters.Q != cryptographicParameters.Q)
        {
            throw new VerificationFailedException("1.C", $"Q does not match expected value. Expected: {EGParameters.Q} Actual: {cryptographicParameters.Q}");
        }

        // 1.D
        if (EGParameters.G != cryptographicParameters.G)
        {
            throw new VerificationFailedException("1.D", $"G does not match expected value. Expected: {EGParameters.G} Actual: {cryptographicParameters.G}");
        }

        // 1.E: recomputed through the same constructor that produces H_P everywhere else, so the
        // check and the value it checks cannot disagree about the encoding of eq. (4).
        byte[] expectedParameterHash = new ParameterBaseHash(cryptographicParameters, guardianParameters);

        if (!expectedParameterHash.SequenceEqual(parameterBaseHash))
        {
            throw new VerificationFailedException("1.E", $"Parameter Base Hash does not match expected value. Expected: {Convert.ToHexString(expectedParameterHash)} Actual: {Convert.ToHexString(parameterBaseHash)}");
        }

        // 1.E, continued: n and k enter Verification 1 only through H_P. 1.A-1.D pin the version and
        // p, q, g to the parameters this process verifies with; this pins n and k the same way.
        // Every later check (the guardian count in Verifications 2 and 3, the k commitments and
        // k + 1 responses of each proof) reads n and k from EGParameters, so a record that claims a
        // different n or k must fail here, under the step that covers them, and not later as a
        // confusing 2.x or 3.x.
        if (guardianParameters.N != EGParameters.GuardianParameters.N || guardianParameters.K != EGParameters.GuardianParameters.K)
        {
            throw new VerificationFailedException("1.E", $"Guardian parameters do not match the parameters in force. Expected: n = {EGParameters.GuardianParameters.N}, k = {EGParameters.GuardianParameters.K} Actual: n = {guardianParameters.N}, k = {guardianParameters.K}");
        }
    }

    /// <summary>
    /// Performs a full parameter verification (1.A-1.F).
    /// </summary>
    /// <exception cref="VerificationFailedException"></exception>
    public void Verify(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters, byte[] parameterBaseHash, byte[] manifest, byte[] electionBaseHash)
    {
        Verify(cryptographicParameters, guardianParameters, parameterBaseHash);

        // 1.F: eq. (5), through the helper ElectionBaseHash itself uses. Compared by content: these
        // are byte arrays, and != would compare references.
        var expectedElectionBaseHash = ElectionBaseHash.Compute(parameterBaseHash, manifest);

        if (!expectedElectionBaseHash.SequenceEqual(electionBaseHash))
        {
            throw new VerificationFailedException("1.F", $"Election Base Hash does not match expected value. Expected: {Convert.ToHexString(expectedElectionBaseHash)} Actual: {Convert.ToHexString(electionBaseHash)}");
        }
    }
}
