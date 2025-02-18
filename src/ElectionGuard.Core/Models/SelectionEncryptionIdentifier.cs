namespace ElectionGuard.Core.Models;

public struct SelectionEncryptionIdentifier
{
    public SelectionEncryptionIdentifier(byte[] value)
    {
        _value = value;
    }

    private readonly byte[] _value;

    public static implicit operator byte[](SelectionEncryptionIdentifier i)
    {
        return i._value;
    }
}
