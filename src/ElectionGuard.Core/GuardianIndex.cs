using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core;

public class GuardianIndex
{
    public GuardianIndex(int index)
    {
        Index = index;
    }

    public int Index { get; }

    public static implicit operator byte[](GuardianIndex i)
    {
        return i.Index.ToByteArray();
    }

    public static implicit operator int(GuardianIndex i)
    {
        return i.Index;
    }
}
