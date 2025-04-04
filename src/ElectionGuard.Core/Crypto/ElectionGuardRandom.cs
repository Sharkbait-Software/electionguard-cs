using ElectionGuard.Core.Models;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;

namespace ElectionGuard.Core.Crypto;

public static class ElectionGuardRandom
{
    public static IntegerModQ GetIntegerModQ()
    {
        // Naive implementation for now. Generate a random bigint with the correct number of bytes, 
        // and return it if it is within our requested bounds.
        // A better implementation would probably carry over insignificant 0 bits at least.
        // This works most of the time though because Q is very close to the max possible value represented in 32 bytes.
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

    public static byte[] GetBytes(int numBytes)
    {
        return RandomNumberGenerator.GetBytes(numBytes);
    }
}
