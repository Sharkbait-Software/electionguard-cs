using System.Numerics;
using System.Security.Cryptography;

namespace ElectionGuard.Core;

public static class ElectionGuardRandom
{
    public static IntegerModQ GetIntegerModQ()
    {
        // Naive implementation for now. Generate a random bigint with the correct number of bytes, 
        // and return it if it is within our requested bounds.
        // A better implementation would probably carry over insignificant 0 bits at least.
        while (true)
        {
            var randomBytes = RandomNumberGenerator.GetBytes(EGParameters.CryptographicParameters.Q.GetByteCount(true));
            var b = new BigInteger(randomBytes, true, true);
            if (b < EGParameters.CryptographicParameters.Q)
            {
                return new IntegerModQ(b);
            }
        }
    }
}
