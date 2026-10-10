using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 5.A over a record too large to hold its identifiers (design §6.5): exact, bounded in
/// memory, and resistant to a record built to defeat it.
/// <list type="number">
/// <item>Each id_B added is reduced to a keyed 64-bit prefix, the first 8 bytes of
/// SHA-256(k ‖ id_B), under a secret 128-bit key k drawn per run, so 8 bytes per ballot.</item>
/// <item>Prefixes are buffered up to the memory budget, then sorted and spilled to a run file. Runs are
/// sorted on the keyed prefix, not partitioned by id_B's own bytes, so a record that skews its id_B
/// values cannot overflow any partition, and without k it cannot aim two ballots at one prefix.</item>
/// <item><see cref="CollidingPrefixes"/> merges the runs and returns every prefix seen more than once:
/// about N²/2^65 of them by chance (3 × 10^-6 at 10^7 ballots), and one per planted duplicate.</item>
/// <item>A colliding prefix is not yet a failure. The caller makes one confirmation pass over the
/// ballots it added (a <see cref="Confirmation{T}"/>), which keeps the full id_B and the caller's
/// locator only for ballots whose prefix collided, and compares exactly: 5.A fails for each id_B
/// two ballots share, naming both.</item>
/// </list>
/// The run files and the key are local, trusted state: a verifier checkpoint holds them
/// (<see cref="Checkpoint"/>, <see cref="Restore"/>), and must never be accepted from a third party,
/// who could choose k. Not thread-safe. Disposing deletes the run files.
/// </summary>
public sealed class SpillingIdentifierSet : IDisposable
{
    /// <summary>The default memory budget, 256 MiB (about 32 million prefixes), as design §6.4 sets it.</summary>
    public const long DefaultMemoryBudgetBytes = 256L << 20;

    private const int InitialCapacity = 1 << 16;

    private readonly byte[] _key;
    private readonly string _directory;
    private readonly int _capacity;
    private ulong[] _buffer;
    private readonly List<string> _runs = [];
    private int _buffered;
    private bool _disposed;

    /// <summary>
    /// An empty set holding at most <paramref name="memoryBudgetBytes"/> of prefixes in memory (at
    /// least 16 prefixes; the budget is a ceiling: the buffer starts small and doubles up to it, so a
    /// small record never commits the whole budget), spilling runs to <paramref name="tempDirectory"/> (the system's temporary
    /// directory when null). <paramref name="key"/> is k, 16 bytes; a random one is drawn when it is
    /// empty, as it should be outside tests.
    /// </summary>
    public SpillingIdentifierSet(long memoryBudgetBytes = DefaultMemoryBudgetBytes, string? tempDirectory = null, ReadOnlySpan<byte> key = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(memoryBudgetBytes);
        if (!key.IsEmpty && key.Length != 16)
        {
            throw new ArgumentException("The key k is 16 bytes.", nameof(key));
        }

        _key = key.IsEmpty ? RandomNumberGenerator.GetBytes(16) : key.ToArray();
        _directory = tempDirectory ?? Path.GetTempPath();
        Directory.CreateDirectory(_directory);
        _capacity = (int)Math.Clamp(memoryBudgetBytes / sizeof(ulong), 16, Array.MaxLength);
        _buffer = new ulong[Math.Min(_capacity, InitialCapacity)];
    }

    /// <summary>The prefixes the buffer can hold before it grows or spills (at most the budget's).</summary>
    internal int BufferCapacity => _buffer.Length;

    /// <summary>The number of identifiers added.</summary>
    public long Count { get; private set; }

    /// <summary>The number of runs spilled to disk so far.</summary>
    public int RunCount => _runs.Count;

    /// <summary>The keyed prefix of <paramref name="identifier"/>: the first 8 bytes of SHA-256(k ‖ id_B), big-endian.</summary>
    public ulong PrefixOf(ReadOnlySpan<byte> identifier)
    {
        Span<byte> input = stackalloc byte[16 + 64];
        if (identifier.Length > 64)
        {
            throw new ArgumentException("An identifier is at most 64 bytes.", nameof(identifier));
        }

        _key.CopyTo(input);
        identifier.CopyTo(input[16..]);
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(input[..(16 + identifier.Length)], digest);
        return BinaryPrimitives.ReadUInt64BigEndian(digest);
    }

    /// <summary>Adds an identifier (id_B, 32 bytes for a ballot), spilling a run when the buffer is full.</summary>
    public void Add(ReadOnlySpan<byte> identifier)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_buffered == _buffer.Length)
        {
            if (_buffer.Length < _capacity)
            {
                Array.Resize(ref _buffer, (int)Math.Min((long)_buffer.Length * 2, _capacity));
            }
            else
            {
                Spill();
            }
        }

        _buffer[_buffered++] = PrefixOf(identifier);
        Count++;
    }

    /// <summary>
    /// Every prefix added more than once, ascending, by a k-way merge of the runs and the buffer. Reads
    /// the runs once; the set is unchanged and more may be added afterwards.
    /// </summary>
    public IReadOnlyList<ulong> CollidingPrefixes()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Array.Sort(_buffer, 0, _buffered);
        var readers = new List<RunReader>(_runs.Count + 1);
        try
        {
            foreach (var run in _runs)
            {
                readers.Add(RunReader.Open(run));
            }

            readers.Add(RunReader.Of(_buffer.AsMemory(0, _buffered)));
            var queue = new PriorityQueue<RunReader, ulong>();
            foreach (var reader in readers)
            {
                if (reader.TryRead(out ulong first))
                {
                    queue.Enqueue(reader, first);
                }
            }

            var colliding = new List<ulong>();
            bool any = false;
            ulong previous = 0;
            while (queue.TryDequeue(out var reader, out ulong prefix))
            {
                if (any && prefix == previous && (colliding.Count == 0 || colliding[^1] != prefix))
                {
                    colliding.Add(prefix);
                }

                any = true;
                previous = prefix;
                if (reader.TryRead(out ulong next))
                {
                    queue.Enqueue(reader, next);
                }
            }

            return colliding;
        }
        finally
        {
            foreach (var reader in readers)
            {
                reader.Dispose();
            }
        }
    }

    /// <summary>
    /// The set's state for a checkpoint: the key, the runs (the buffer is spilled as one first) and the
    /// count. Nothing is deleted before <see cref="Dispose"/>, so a process killed later leaves these
    /// runs on disk for <see cref="Restore"/> (and any later ones, which the restored set does not
    /// know, for the caller to remove).
    /// </summary>
    public State Checkpoint()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_buffered > 0)
        {
            Spill();
        }

        return new State(_key.ToArray(), _runs.ToArray(), Count);
    }

    /// <summary>A set continuing from <paramref name="state"/>: its key, its runs (which it then owns again) and its count.</summary>
    public static SpillingIdentifierSet Restore(State state, long memoryBudgetBytes = DefaultMemoryBudgetBytes, string? tempDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(state);
        var set = new SpillingIdentifierSet(memoryBudgetBytes, tempDirectory, state.Key);
        foreach (var run in state.Runs)
        {
            if (!File.Exists(run) || new FileInfo(run).Length % sizeof(ulong) != 0)
            {
                set.Dispose();
                throw new InvalidDataException($"The 5.A run {run} of the checkpoint is missing or damaged.");
            }

            set._runs.Add(run);
        }

        set.Count = state.Count;
        return set;
    }

    /// <summary>A checkpoint's 5.A state (<see cref="Checkpoint"/>): the key k, the run files in order, the identifiers added.</summary>
    public sealed record State(byte[] Key, string[] Runs, long Count);

    /// <summary>Deletes the run files; a checkpoint holding them is then void.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (var run in _runs)
        {
            try
            {
                File.Delete(run);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private void Spill()
    {
        Array.Sort(_buffer, 0, _buffered);
        string path = Path.Combine(_directory, $"egrf-5a-{Guid.NewGuid():N}.run");
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
        {
            Span<byte> bytes = stackalloc byte[sizeof(ulong)];
            for (int i = 0; i < _buffered; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(bytes, _buffer[i]);
                stream.Write(bytes);
            }

            stream.Flush(flushToDisk: true);
        }

        _runs.Add(path);
        _buffered = 0;
    }

    /// <summary>A sorted run, on disk or in memory, read one prefix at a time.</summary>
    private sealed class RunReader : IDisposable
    {
        private readonly Stream? _stream;
        private readonly ReadOnlyMemory<ulong> _memory;
        private int _index;

        private RunReader(Stream? stream, ReadOnlyMemory<ulong> memory)
        {
            _stream = stream;
            _memory = memory;
        }

        public static RunReader Open(string path) => new(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan), default);

        public static RunReader Of(ReadOnlyMemory<ulong> memory) => new(null, memory);

        public bool TryRead(out ulong value)
        {
            if (_stream is null)
            {
                if (_index < _memory.Length)
                {
                    value = _memory.Span[_index++];
                    return true;
                }

                value = 0;
                return false;
            }

            Span<byte> bytes = stackalloc byte[sizeof(ulong)];
            int read = _stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            value = read == bytes.Length ? BinaryPrimitives.ReadUInt64LittleEndian(bytes) : 0;
            return read == bytes.Length;
        }

        public void Dispose() => _stream?.Dispose();
    }

    /// <summary>
    /// The confirmation pass of design §6.5 step 4: offered every identifier again with where it is
    /// (<typeparamref name="T"/>, a locator), it keeps the full identifier only for those whose prefix
    /// is in the colliding set, so its memory is O(collisions), and then reports each identifier that
    /// more than one place holds.
    /// </summary>
    public sealed class Confirmation<T>
    {
        private readonly SpillingIdentifierSet _set;
        private readonly HashSet<ulong> _colliding;
        private readonly Dictionary<string, List<T>> _seen = new(StringComparer.Ordinal);

        public Confirmation(SpillingIdentifierSet set, IEnumerable<ulong> collidingPrefixes)
        {
            _set = set ?? throw new ArgumentNullException(nameof(set));
            _colliding = [.. collidingPrefixes];
        }

        /// <summary>Whether any prefix collided, so that a pass is needed at all.</summary>
        public bool IsNeeded => _colliding.Count > 0;

        /// <summary>Offers one identifier and its place.</summary>
        public void Offer(ReadOnlySpan<byte> identifier, T where)
        {
            if (!_colliding.Contains(_set.PrefixOf(identifier)))
            {
                return;
            }

            string key = Convert.ToHexStringLower(identifier);
            if (!_seen.TryGetValue(key, out var places))
            {
                _seen[key] = places = [];
            }

            places.Add(where);
        }

        /// <summary>Each identifier offered more than once (lowercase hex), with every place it was offered at, in order.</summary>
        public IReadOnlyList<(string IdentifierHex, IReadOnlyList<T> Places)> Duplicates() =>
            _seen.Where(x => x.Value.Count > 1).OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => (x.Key, (IReadOnlyList<T>)x.Value)).ToList();
    }
}
