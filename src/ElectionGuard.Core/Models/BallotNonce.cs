namespace ElectionGuard.Core.Models;

public struct BallotNonce
{
    public BallotNonce(byte[] value)
    {
        _value = value;
    }

    private readonly byte[] _value;

    public byte[] ToByteArray()
    {
        return _value;
    }

    public static implicit operator byte[](BallotNonce i)
    {
        return i._value;
    }
}
