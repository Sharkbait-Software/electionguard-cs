using System.Numerics;

namespace ElectionGuard.Core.Models;

/// <summary>
/// Process-wide holder for the active election's cryptographic/guardian parameters. Defaults to
/// the spec's v2.1.0 parameters, so <see cref="IntegerModP"/>/<see cref="IntegerModQ"/> and every
/// other type that reads P/Q/G work with no setup. <see cref="Init"/> and <see cref="OverrideScope"/>
/// exist only to swap in a different parameter set.
/// </summary>
public static class EGParameters
{
    private static CryptographicParameters _cryptographicParameters = new();
    private static GuardianParameters _guardianParameters = new();
    private static ParameterBaseHash _parameterBaseHash = new(_cryptographicParameters, _guardianParameters);

    public static CryptographicParameters CryptographicParameters => _cryptographicParameters;
    public static GuardianParameters GuardianParameters => _guardianParameters;
    public static ParameterBaseHash ParameterBaseHash => _parameterBaseHash;

    /// <summary>
    /// Cached accessors so hot-path arithmetic (IntegerModP/IntegerModQ) doesn't walk through
    /// CryptographicParameters on every operation.
    /// </summary>
    public static BigInteger P => _cryptographicParameters.P;
    public static BigInteger Q => _cryptographicParameters.Q;
    public static BigInteger G => _cryptographicParameters.G;

    /// <summary>
    /// Overrides the process-wide parameters.
    /// </summary>
    public static void Init(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters)
    {
        _cryptographicParameters = cryptographicParameters;
        _guardianParameters = guardianParameters;
        _parameterBaseHash = new ParameterBaseHash(_cryptographicParameters, _guardianParameters);
    }

    /// <summary>
    /// Overrides the process-wide parameters for the lifetime of the returned scope, restoring the
    /// previous values on Dispose.
    /// </summary>
    public static IDisposable OverrideScope(CryptographicParameters cryptographicParameters, GuardianParameters guardianParameters)
    {
        var previousCryptographicParameters = _cryptographicParameters;
        var previousGuardianParameters = _guardianParameters;
        var previousParameterBaseHash = _parameterBaseHash;

        Init(cryptographicParameters, guardianParameters);

        return new RestoreScope(() =>
        {
            _cryptographicParameters = previousCryptographicParameters;
            _guardianParameters = previousGuardianParameters;
            _parameterBaseHash = previousParameterBaseHash;
        });
    }

    private sealed class RestoreScope(Action onDispose) : IDisposable
    {
        public void Dispose() => onDispose();
    }
}
