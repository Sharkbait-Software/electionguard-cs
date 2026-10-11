using ElectionGuard.Core.Extensions;

namespace ElectionGuard.Core.Models;

public class Version : IEquatable<Version?>
{
    public Version(string version)
    {
        _version = version;
    }

    private readonly string _version;

    public override string ToString()
    {
        return _version;
    }

    public override bool Equals(object? obj)
    {
        return Equals(obj as Version);
    }

    public bool Equals(Version? other)
    {
        return other is not null &&
               _version == other._version;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_version);
    }

    public static implicit operator string(Version version)
    {
        return version._version;
    }

    /// <summary>
    /// §3.1.2 eq. (4): the key of the parameter base hash is ver = "v2.1.0" || b(0, 26), the
    /// version string's UTF-8 bytes followed by zero bytes up to 32. That is right-padding, unlike
    /// the left-padding b(a, m) gives integers, so this does not use PadToLength.
    /// </summary>
    public static implicit operator byte[](Version version)
    {
        var versionBytes = System.Text.Encoding.UTF8.GetBytes(version._version);
        if (versionBytes.Length > KeyLength)
        {
            throw new InvalidOperationException($"Version {version._version} is longer than {KeyLength} bytes.");
        }

        var key = new byte[KeyLength];
        versionBytes.CopyTo(key, 0);
        return key;
    }

    private const int KeyLength = 32;

    public static bool operator ==(Version? left, Version? right)
    {
        return EqualityComparer<Version>.Default.Equals(left, right);
    }

    public static bool operator !=(Version? left, Version? right)
    {
        return !(left == right);
    }
}
