namespace ElectionGuard.Core.Models;

public static class EGParameters
{
    public static void Init(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters)
    {
        _cryptographicParameters = cryptographicParameters;
        _guardianParameters = guardianParameters;
        _parameterBaseHash = new ParameterBaseHash(CryptographicParameters, GuardianParameters);
    }

    private static CryptographicParameters? _cryptographicParameters;
    public static CryptographicParameters CryptographicParameters => _cryptographicParameters ?? throw new Exception("EGParameters not initialized.");

    private static GuardianParameters? _guardianParameters;
    public static GuardianParameters GuardianParameters => _guardianParameters ?? throw new Exception("EGParameters not initialized.");

    private static ParameterBaseHash? _parameterBaseHash;
    public static ParameterBaseHash ParameterBaseHash => _parameterBaseHash ?? throw new Exception("EGParameters not initialized.");
}
