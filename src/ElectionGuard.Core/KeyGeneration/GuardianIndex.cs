using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.KeyGeneration;

public class GuardianIndex : IEquatable<GuardianIndex?>
{
    public GuardianIndex(int index)
    {
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
