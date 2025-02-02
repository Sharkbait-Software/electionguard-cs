using System.Buffers.Binary;

namespace ElectionGuard.Core.Extensions;

public static class IntExtensions
{
    public static byte[] ToByteArray(this int i)
    {
        byte[] bytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return bytes;
    }
}