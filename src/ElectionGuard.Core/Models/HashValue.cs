namespace ElectionGuard.Core.Models;

public abstract class HashValue
{
    protected abstract byte[] Bytes { get; }

    public static implicit operator byte[](HashValue value)
    {
        return value.Bytes;
    }
}
