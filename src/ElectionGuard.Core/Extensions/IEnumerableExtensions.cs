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

    public static IntegerModP Product(this IEnumerable<IntegerModP> items)
    {
        return items.Aggregate((a, b) => a * b);
    }

    public static IntegerModQ Product(this IEnumerable<IntegerModQ> items)
    {
        return items.Aggregate((a, b) => a * b);
    }

    public static int Product(this IEnumerable<int> items)
    {
        return items.Aggregate((a, b) => a * b);
    }
}
