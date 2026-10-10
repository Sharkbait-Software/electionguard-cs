using System.IO.Compression;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>Where a reader reads a record's files from: a directory, or the entries of a <c>.zip</c>.</summary>
internal interface IRecordSource : IDisposable
{
    RecordCarrier Carrier { get; }

    /// <summary>Every file (zip: every non-directory entry), as a relative '/'-separated name, in no particular order.</summary>
    IReadOnlyList<string> Files { get; }

    /// <summary>Opens <paramref name="path"/> for one sequential read.</summary>
    Stream OpenRead(string path);
}

/// <summary>Where a writer writes a record's files to.</summary>
internal interface IRecordSink : IDisposable
{
    RecordCarrier Carrier { get; }

    /// <summary>
    /// Creates <paramref name="path"/> for writing. <paramref name="compressible"/>: a JSON file a zip
    /// may DEFLATE (§5.4: protobuf entries are always STORED). A zip holds one open entry at a time.
    /// </summary>
    Stream Create(string path, bool compressible);
}

/// <summary>A record's files in a directory tree.</summary>
internal sealed class DirectoryRecordSource : IRecordSource
{
    private readonly string _root;

    public DirectoryRecordSource(string root)
    {
        _root = Path.GetFullPath(root);
        if (!Directory.Exists(_root))
        {
            throw new DirectoryNotFoundException($"No record directory at {_root}.");
        }

        Files = Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories)
            .Select(x => Path.GetRelativePath(_root, x).Replace(Path.DirectorySeparatorChar, '/'))
            .ToList();
    }

    public RecordCarrier Carrier => RecordCarrier.Directory;

    public IReadOnlyList<string> Files { get; }

    public Stream OpenRead(string path) =>
        new FileStream(Path.Combine(_root, path), FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan);

    public void Dispose()
    {
    }
}

/// <summary>A record written into a directory tree.</summary>
internal sealed class DirectoryRecordSink(string root) : IRecordSink
{
    public string Root { get; } = Path.GetFullPath(root);

    public RecordCarrier Carrier => RecordCarrier.Directory;

    public Stream Create(string path, bool compressible)
    {
        RecordLayout.RequireValidName(path);
        string full = Path.Combine(Root, path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        return new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 1 << 16);
    }

    /// <summary>Opens an existing file for appending (a resumed writer's last segment).</summary>
    public Stream Append(string path)
    {
        RecordLayout.RequireValidName(path);
        return new FileStream(Path.Combine(Root, path), FileMode.Append, FileAccess.Write, FileShare.Read, 1 << 16);
    }

    public void Dispose()
    {
    }
}

/// <summary>
/// A record written into a <c>.zip</c> (design §5.4) with <see cref="ZipArchive"/>: protobuf entries
/// STORED, JSON entries DEFLATEd when <paramref name="deflateJson"/> (else STORED), ZIP64 wherever an
/// entry or the archive needs it (the archive adds it), every entry stamped 1980-01-01 so that the
/// archive's bytes depend only on the record. Entries are written in the order they are created.
/// </summary>
internal sealed class ZipRecordSink : IRecordSink
{
    private static readonly DateTimeOffset Stamp = new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private readonly Stream _stream;
    private readonly ZipArchive _archive;
    private readonly bool _deflateJson;

    public ZipRecordSink(Stream stream, bool deflateJson)
    {
        _stream = stream;
        _deflateJson = deflateJson;
        _archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: false);
    }

    public RecordCarrier Carrier => RecordCarrier.Zip;

    public Stream Create(string path, bool compressible)
    {
        RecordLayout.RequireValidName(path);
        var entry = _archive.CreateEntry(path, compressible && _deflateJson ? CompressionLevel.Optimal : CompressionLevel.NoCompression);
        entry.LastWriteTime = Stamp;
        return entry.Open();
    }

    public void Dispose()
    {
        _archive.Dispose();
        _stream.Dispose();
    }
}
