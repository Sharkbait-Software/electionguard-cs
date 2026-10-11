namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// An external sort for the join sections (design §4.5: sorted by locator, then contest index,
/// unique): (key, item) pairs are buffered up to a byte budget, then sorted and spilled to a run
/// file in the temporary directory; <see cref="MergeAsync"/> merges the runs (and the buffer) in key
/// order with one open cursor per run. Memory is the budget plus one entry per run, however many
/// items are added. Keys compare as unsigned bytes; a key added twice is refused when the merge
/// meets it.
/// </summary>
internal sealed class SortedSpool : IAsyncDisposable
{
    private readonly string _directory;
    private readonly long _budget;
    private readonly List<(byte[] Key, byte[] Item)> _buffer = [];
    private readonly List<string> _runs = [];
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _bufferBytes;
    private long _count;
    private bool _merged;

    public SortedSpool(string? tempDirectory, long budgetBytes)
    {
        _directory = tempDirectory ?? Path.GetTempPath();
        _budget = budgetBytes;
    }

    /// <summary>The number of pairs added.</summary>
    public long Count
    {
        get
        {
            lock (_buffer)
            {
                return _count;
            }
        }
    }

    /// <summary>
    /// Adds one pair. It either holds the pair when it returns or throws without it: a full buffer is
    /// spilled before the pair goes in, and a failed spill keeps the buffer as it was. Concurrent
    /// calls take turns; a call after <see cref="MergeAsync"/> has started is refused
    /// (<see cref="InvalidOperationException"/>), since the merge would not see its pair.
    /// </summary>
    public async ValueTask AddAsync(byte[] key, byte[] item, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_merged)
            {
                throw new InvalidOperationException("The spool is being merged; nothing more can be added to it.");
            }

            long size = key.Length + item.Length + 64;
            if (_buffer.Count > 0 && _bufferBytes + size > _budget)
            {
                await SpillAsync(ct).ConfigureAwait(false);
            }

            lock (_buffer)
            {
                _buffer.Add((key, item));
                _count++;
            }

            _bufferBytes += size;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Every pair, in ascending key order. Throws <see cref="ArgumentException"/> when two pairs have
    /// the same key, naming <paramref name="what"/>. Once it starts, the spool takes no more pairs.
    /// </summary>
    public async IAsyncEnumerable<(byte[] Key, byte[] Item)> MergeAsync(string what, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        _merged = true;
        _gate.Release();
        _buffer.Sort((a, b) => a.Key.AsSpan().SequenceCompareTo(b.Key));
        var cursors = new List<IAsyncEnumerator<(byte[] Key, byte[] Item)>> { Buffered().GetAsyncEnumerator(ct) };
        cursors.AddRange(_runs.Select(run => ReadRunAsync(run, ct).GetAsyncEnumerator(ct)));
        var queue = new PriorityQueue<int, byte[]>(Comparer<byte[]>.Create((a, b) => a.AsSpan().SequenceCompareTo(b)));
        try
        {
            for (int i = 0; i < cursors.Count; i++)
            {
                if (await cursors[i].MoveNextAsync().ConfigureAwait(false))
                {
                    queue.Enqueue(i, cursors[i].Current.Key);
                }
            }

            byte[]? previous = null;
            while (queue.TryDequeue(out int i, out _))
            {
                var current = cursors[i].Current;
                if (previous is not null && previous.AsSpan().SequenceEqual(current.Key))
                {
                    throw new ArgumentException($"{what} lists the same entry twice (key {Convert.ToHexStringLower(current.Key)}); each appears once (design §4.5).");
                }

                previous = current.Key;
                yield return current;
                if (await cursors[i].MoveNextAsync().ConfigureAwait(false))
                {
                    queue.Enqueue(i, cursors[i].Current.Key);
                }
            }
        }
        finally
        {
            foreach (var cursor in cursors)
            {
                await cursor.DisposeAsync().ConfigureAwait(false);
            }
        }

        async IAsyncEnumerable<(byte[] Key, byte[] Item)> Buffered()
        {
            foreach (var entry in _buffer)
            {
                yield return entry;
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }
    }

    public ValueTask DisposeAsync()
    {
        foreach (var run in _runs)
        {
            try
            {
                File.Delete(run);
            }
            catch (IOException)
            {
                // A run that cannot be deleted is left in the temporary directory.
            }
        }

        _runs.Clear();
        _buffer.Clear();
        return ValueTask.CompletedTask;
    }

    private async ValueTask SpillAsync(CancellationToken ct)
    {
        _buffer.Sort((a, b) => a.Key.AsSpan().SequenceCompareTo(b.Key));
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, $"egrf-run-{Guid.NewGuid():N}.tmp");
        try
        {
            await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16);
            foreach (var (key, item) in _buffer)
            {
                await SegmentFraming.WriteFrameAsync(stream, key, ct).ConfigureAwait(false);
                await SegmentFraming.WriteFrameAsync(stream, item, ct).ConfigureAwait(false);
            }
        }
        catch
        {
            // The pairs stay in the buffer; the partial run is dropped.
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
            }

            throw;
        }

        _runs.Add(path);
        _buffer.Clear();
        _bufferBytes = 0;
    }

    private static async IAsyncEnumerable<(byte[] Key, byte[] Item)> ReadRunAsync(string path, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await using var stream = new BufferedStream(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan), 1 << 16);
        while (await SegmentFraming.ReadFrameAsync(stream, path, ct).ConfigureAwait(false) is { } key)
        {
            var item = await SegmentFraming.ReadFrameAsync(stream, path, ct).ConfigureAwait(false)
                ?? throw new InvalidDataException($"The spool run {path} ends after a key.");
            yield return (key, item);
        }
    }
}
