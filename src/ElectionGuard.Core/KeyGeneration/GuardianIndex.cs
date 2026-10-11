using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.KeyGeneration;

public class GuardianIndex : IEquatable<GuardianIndex?>
{
    /// <summary>
    /// A guardian's sequence number. §3.2.1 numbers the guardians G_1..G_n, and every share is
    /// P_i(l) for 1 <= l <= n (§3.2.2): an index of 0 would be handed P_i(0) = a_{i,0} = s_i, the
    /// guardian's secret key itself, so indices below 1 are rejected here. The upper bound n is
    /// election state, checked where it is known (the <see cref="Guardian"/> constructor and the
    /// key-ceremony checks).
    /// </summary>
    public GuardianIndex(int index)
    {
        if (index < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(index), index, "Guardian indices are 1-based (§3.2.1): an index must be at least 1.");
        }

        Index = index;
    }

    public int Index { get; }

    public override bool Equals(object? obj)
    {
        return Equals(obj as GuardianIndex);
    }

    public bool Equals(GuardianIndex? other)
    {
        return other is not null &&
               Index == other.Index;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Index);
    }

    public static bool operator ==(GuardianIndex? left, GuardianIndex? right)
    {
        return EqualityComparer<GuardianIndex>.Default.Equals(left, right);
    }

    public static bool operator !=(GuardianIndex? left, GuardianIndex? right)
    {
        return !(left == right);
    }

    public static implicit operator byte[](GuardianIndex i)
    {
        return i.Index.ToByteArray();
    }

    public static implicit operator int(GuardianIndex i)
    {
        return i.Index;
    }
}
