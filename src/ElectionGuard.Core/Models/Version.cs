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

    public static implicit operator byte[](Version version)
    {
        return System.Text.Encoding.UTF8.GetBytes(version._version).PadToLength(32);
    }

    public static bool operator ==(Version? left, Version? right)
    {
        return EqualityComparer<Version>.Default.Equals(left, right);
    }

    public static bool operator !=(Version? left, Version? right)
    {
        return !(left == right);
    }
}
