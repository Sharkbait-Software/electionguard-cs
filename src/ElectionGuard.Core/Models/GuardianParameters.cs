namespace ElectionGuard.Core.Models;

public class GuardianParameters
{
    /// <summary>
    /// The spec's default threshold scheme: 3 guardians, 2 required to decrypt.
    /// </summary>
    public GuardianParameters()
    {
    }

    /// <summary>
    /// A threshold scheme of <paramref name="k"/>-of-<paramref name="n"/> guardians. No single
    /// guardian's secret key can decrypt anything alone, so <paramref name="k"/> is the number of
    /// guardians whose partial decryptions must be combined.
    /// </summary>
    public GuardianParameters(int n, int k)
    {
        if (n < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(n), n, "Guardian count must be at least 1.");
        }

        if (k < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(k), k, "Guardian threshold must be at least 1.");
        }

        if (k > n)
        {
            throw new ArgumentOutOfRangeException(nameof(k), k, $"Guardian threshold ({k}) cannot exceed the guardian count ({n}).");
        }

        N = n;
        K = k;
    }

    public int N { get; } = 3;
    public int K { get; } = 2;
}
