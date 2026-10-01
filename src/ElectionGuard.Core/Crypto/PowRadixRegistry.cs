using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.Models;
using System.Numerics;

namespace ElectionGuard.Core.Crypto;

/// <summary>
/// Opt-in store of precomputed <see cref="PowRadix"/> tables, consulted by
/// <see cref="MontgomeryModP"/>.
///
/// Nothing is built unless a caller asks. Building the tables for g, K and K-hat costs tens to
/// hundreds of milliseconds and tens of megabytes per base (see
/// <see cref="PowRadix.EstimateTableSizeInBytes"/>), which is the right trade for a process that
/// will encrypt ballots and the wrong one for a process that will not, so the decision is left to
/// the caller rather than made in a constructor.
///
/// <see cref="IntegerModP"/> never consults this registry. Its exponentiation stays the plain
/// BigInteger implementation, with no lookup on its path.
///
/// Tables are tied to the modulus they were built against. If <see cref="EGParameters"/> is later
/// pointed at a different p, lookups report a miss rather than returning values computed under the
/// wrong parameters, and callers fall back to the table-free path.
/// </summary>
public static class PowRadixRegistry
{
    private sealed record Snapshot(BigInteger Modulus, Dictionary<BigInteger, PowRadix> Tables);

    private static Snapshot? _snapshot;
    private static readonly object _gate = new();

    /// <summary>Number of bases currently precomputed for the active parameters.</summary>
    public static int Count => CurrentSnapshot()?.Tables.Count ?? 0;

    /// <summary>Total bytes held by all precomputed tables for the active parameters.</summary>
    public static long TotalTableSizeInBytes
    {
        get
        {
            Snapshot? snapshot = CurrentSnapshot();
            if (snapshot is null)
            {
                return 0;
            }

            long total = 0;
            foreach (PowRadix radix in snapshot.Tables.Values)
            {
                total += radix.TableSizeInBytes;
            }

            return total;
        }
    }

    /// <summary>
    /// Builds and registers tables for the given bases at the default window width. Bases that are
    /// already registered at that width are left alone, so calling this twice is cheap.
    /// </summary>
    public static void Precompute(params BigInteger[] bases)
    {
        Precompute(PowRadix.DefaultWindowBits, bases);
    }

    /// <inheritdoc cref="Precompute(BigInteger[])"/>
    public static void Precompute(params IntegerModP[] bases)
    {
        Precompute(PowRadix.DefaultWindowBits, bases);
    }

    /// <inheritdoc cref="Precompute(BigInteger[])"/>
    public static void Precompute(int windowBits, params IntegerModP[] bases)
    {
        ArgumentNullException.ThrowIfNull(bases);

        BigInteger[] values = new BigInteger[bases.Length];
        for (int i = 0; i < bases.Length; i++)
        {
            values[i] = bases[i].ToBigInteger();
        }

        Precompute(windowBits, values);
    }

    /// <summary>
    /// Builds and registers tables for the given bases at <paramref name="windowBits"/> bits per
    /// window. A base already registered at a different width is rebuilt.
    /// </summary>
    public static void Precompute(int windowBits, params BigInteger[] bases)
    {
        ArgumentNullException.ThrowIfNull(bases);

        if (bases.Length == 0)
        {
            return;
        }

        lock (_gate)
        {
            BigInteger modulus = EGParameters.P;
            Snapshot? current = Volatile.Read(ref _snapshot);

            Dictionary<BigInteger, PowRadix> tables = current is not null && current.Modulus == modulus
                ? new Dictionary<BigInteger, PowRadix>(current.Tables)
                : new Dictionary<BigInteger, PowRadix>();

            foreach (BigInteger basis in bases)
            {
                // Store under the reduced value so that lookups by an IntegerModP, which is always
                // reduced, find the table.
                BigInteger reduced = basis >= modulus || basis < 0 ? basis.Mod(modulus) : basis;

                if (tables.TryGetValue(reduced, out PowRadix? existing) && existing.WindowBits == windowBits)
                {
                    continue;
                }

                tables[reduced] = PowRadix.Build(reduced, windowBits);
            }

            Volatile.Write(ref _snapshot, new Snapshot(modulus, tables));
        }
    }

    /// <summary>
    /// Finds the table for <paramref name="basis"/>, if one has been precomputed for the active
    /// parameters. A miss is not an error: callers fall back to table-free exponentiation.
    /// </summary>
    public static bool TryGet(BigInteger basis, out PowRadix radix)
    {
        Snapshot? snapshot = CurrentSnapshot();
        if (snapshot is null)
        {
            radix = null!;
            return false;
        }

        return snapshot.Tables.TryGetValue(basis, out radix!);
    }

    /// <inheritdoc cref="TryGet(BigInteger, out PowRadix)"/>
    public static bool TryGet(IntegerModP basis, out PowRadix radix)
    {
        return TryGet(basis.ToBigInteger(), out radix);
    }

    /// <summary>Discards every precomputed table and the memory they hold.</summary>
    public static void Clear()
    {
        lock (_gate)
        {
            Volatile.Write(ref _snapshot, null);
        }
    }

    /// <summary>
    /// The snapshot, but only if it was built for the parameters currently in force. Returning null
    /// for a stale snapshot is what keeps a parameter swap from silently using tables computed
    /// against the previous p.
    /// </summary>
    private static Snapshot? CurrentSnapshot()
    {
        Snapshot? snapshot = Volatile.Read(ref _snapshot);
        if (snapshot is null || snapshot.Modulus != EGParameters.P)
        {
            return null;
        }

        return snapshot;
    }
}
