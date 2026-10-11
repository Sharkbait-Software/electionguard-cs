using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.Extensions;

public static class IEnumerableExtensions
{
    public static IntegerModQ Sum(this IEnumerable<IntegerModQ> items)
    {
        IntegerModQ result = new IntegerModQ(0);
        foreach (var item in items)
        {
            result += item;
        }

        return result;
    }

    /// <summary>
    /// The product of <paramref name="items"/> mod p. Throws on an empty input, deliberately: an
    /// empty product here would be a joint key K = 1 (eq. 25) or an aggregate of no selections,
    /// and RangeProofChallenge mirrors the throw. Compare the Z_q overload below.
    /// </summary>
    public static IntegerModP Product(this IEnumerable<IntegerModP> items)
    {
        return items.Aggregate((a, b) => a * b);
    }

    /// <summary>
    /// The product of <paramref name="items"/> mod q. The empty product is 1: the Lagrange
    /// coefficient of eq. (85) for |U| = 1 (k = 1) is a product over the empty set U \ {i}. This used
    /// to be a seedless Aggregate, which threw on an empty input (G28).
    /// </summary>
    public static IntegerModQ Product(this IEnumerable<IntegerModQ> items)
    {
        return items.Aggregate(new IntegerModQ(1), (a, b) => a * b);
    }

    public static int Product(this IEnumerable<int> items)
    {
        return items.Aggregate((a, b) => a * b);
    }
}
