using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The RFC 9162 (Certificate Transparency v2, §2.1) Merkle Tree Hash with SHA-256, as the election
/// record uses it (design §4.9):
/// <code>
/// leaf(d)    = SHA-256(0x00 || d)
/// node(l, r) = SHA-256(0x01 || l || r)
/// MTH([])    = SHA-256("")
/// MTH([d])   = leaf(d)
/// MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n])), n > 1, k the largest power of two below n
/// </code>
/// </summary>
public static class MerkleTree
{
    /// <summary>MTH of the empty tree, SHA-256 of no bytes.</summary>
    public static Sha256Digest EmptyRoot { get; } = Sha256Digest.Of([]);

    /// <summary>leaf(d) = SHA-256(0x00 || d): the leaf hash of one item's canonical bytes.</summary>
    public static Sha256Digest LeafHash(ReadOnlySpan<byte> data)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData([0x00]);
        hash.AppendData(data);
        Span<byte> digest = stackalloc byte[Sha256Digest.ByteLength];
        hash.GetHashAndReset(digest);
        return Sha256Digest.FromBytes(digest);
    }

    /// <summary>node(l, r) = SHA-256(0x01 || l || r).</summary>
    public static Sha256Digest NodeHash(in Sha256Digest left, in Sha256Digest right)
    {
        Span<byte> input = stackalloc byte[1 + 2 * Sha256Digest.ByteLength];
        input[0] = 0x01;
        left.CopyTo(input[1..]);
        right.CopyTo(input[(1 + Sha256Digest.ByteLength)..]);
        return Sha256Digest.Of(input);
    }

    /// <summary>MTH over leaf hashes already computed, in order.</summary>
    public static Sha256Digest Root(IEnumerable<Sha256Digest> leafHashes)
    {
        ArgumentNullException.ThrowIfNull(leafHashes);
        var frontier = new MerkleFrontier();
        foreach (var leaf in leafHashes)
        {
            frontier.AppendLeafHash(leaf);
        }

        return frontier.Root();
    }

    /// <summary>The largest power of two strictly below <paramref name="n"/> (n &gt; 1): RFC 9162's split point k.</summary>
    internal static long Split(long n) => (long)BitOperations.RoundUpToPowerOf2((ulong)n) >> 1;
}

/// <summary>
/// An append-only RFC 9162 Merkle tree kept as its frontier: the roots of the perfect subtrees that
/// the binary digits of <see cref="Count"/> describe, largest first, so O(log n) state. Workers hash
/// leaves in parallel and one sequencer appends them in order (design §6.2); the frontier can be
/// saved and restored to resume a run (<see cref="Serialize"/>, <see cref="Deserialize"/>).
/// Not thread-safe.
/// </summary>
public sealed class MerkleFrontier
{
    // _nodes[i] is the root of a perfect subtree; their sizes are the set bits of _count, largest first.
    private readonly List<Sha256Digest> _nodes = [];
    private long _count;

    /// <summary>The number of leaves appended.</summary>
    public long Count => _count;

    /// <summary>leaf(d) = SHA-256(0x00 || d) (<see cref="MerkleTree.LeafHash"/>).</summary>
    public static Sha256Digest LeafHash(ReadOnlySpan<byte> canonicalItem) => MerkleTree.LeafHash(canonicalItem);

    /// <summary>Appends the leaf hash of <paramref name="canonicalItem"/>.</summary>
    public void Append(ReadOnlySpan<byte> canonicalItem) => AppendLeafHash(MerkleTree.LeafHash(canonicalItem));

    /// <summary>Appends a leaf hash computed elsewhere.</summary>
    public void AppendLeafHash(in Sha256Digest leaf)
    {
        if (_count == long.MaxValue)
        {
            throw new InvalidOperationException("The tree is full.");
        }

        var node = leaf;
        // Each trailing one bit of the old count is a perfect subtree of the same size as the
        // node being carried; merge them, as binary addition carries.
        for (long bits = _count; (bits & 1) == 1; bits >>= 1)
        {
            node = MerkleTree.NodeHash(_nodes[^1], node);
            _nodes.RemoveAt(_nodes.Count - 1);
        }

        _nodes.Add(node);
        _count++;
    }

    /// <summary>
    /// MTH of the leaves appended so far: the subtree roots folded from the smallest up, which is
    /// RFC 9162's split at the largest power of two, applied recursively to the right.
    /// </summary>
    public Sha256Digest Root()
    {
        if (_nodes.Count == 0)
        {
            return MerkleTree.EmptyRoot;
        }

        var root = _nodes[^1];
        for (int i = _nodes.Count - 2; i >= 0; i--)
        {
            root = MerkleTree.NodeHash(_nodes[i], root);
        }

        return root;
    }

    /// <summary>
    /// The frontier's state: the count as 8 big-endian bytes, then the 32-byte subtree roots, largest
    /// first (one per set bit of the count). <see cref="Deserialize"/> restores it exactly.
    /// </summary>
    public byte[] Serialize()
    {
        var bytes = new byte[8 + _nodes.Count * Sha256Digest.ByteLength];
        BinaryPrimitives.WriteInt64BigEndian(bytes, _count);
        for (int i = 0; i < _nodes.Count; i++)
        {
            _nodes[i].CopyTo(bytes.AsSpan(8 + i * Sha256Digest.ByteLength));
        }

        return bytes;
    }

    /// <summary>A frontier from <see cref="Serialize"/>'s bytes; throws <see cref="FormatException"/> if they are not one.</summary>
    public static MerkleFrontier Deserialize(ReadOnlySpan<byte> state)
    {
        if (state.Length < 8)
        {
            throw new FormatException("A Merkle frontier state starts with an 8-byte count.");
        }

        long count = BinaryPrimitives.ReadInt64BigEndian(state);
        if (count < 0)
        {
            throw new FormatException("A Merkle frontier's count is negative.");
        }

        int nodes = BitOperations.PopCount((ulong)count);
        if (state.Length != 8 + nodes * Sha256Digest.ByteLength)
        {
            throw new FormatException($"A Merkle frontier of {count} leaves holds {nodes} subtree roots, so {8 + nodes * Sha256Digest.ByteLength} bytes; got {state.Length}.");
        }

        var frontier = new MerkleFrontier { _count = count };
        for (int i = 0; i < nodes; i++)
        {
            frontier._nodes.Add(Sha256Digest.FromBytes(state.Slice(8 + i * Sha256Digest.ByteLength, Sha256Digest.ByteLength)));
        }

        return frontier;
    }
}

/// <summary>
/// RFC 9162 §2.1.3 inclusion proofs and §2.1.4 consistency proofs: generation over a list of leaf
/// hashes, and the verification algorithms exactly as the RFC states them. A voter's checker needs
/// only these and SHA-256 (design §5.6); a verifier uses consistency to show that a later phase root
/// extends an earlier one (§4.9).
/// </summary>
public static class MerkleProofs
{
    /// <summary>PATH(m, D[n]) (§2.1.3.1): the audit path of leaf <paramref name="index"/>.</summary>
    public static IReadOnlyList<Sha256Digest> InclusionProof(IReadOnlyList<Sha256Digest> leafHashes, long index)
    {
        ArgumentNullException.ThrowIfNull(leafHashes);
        if (index < 0 || index >= leafHashes.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(index), index, $"A leaf index lies in [0, {leafHashes.Count}).");
        }

        var path = new List<Sha256Digest>();
        Path(leafHashes, 0, leafHashes.Count, index, path);
        return path;
    }

    private static void Path(IReadOnlyList<Sha256Digest> leaves, int start, int n, long m, List<Sha256Digest> path)
    {
        if (n <= 1)
        {
            return;
        }

        int k = (int)MerkleTree.Split(n);
        if (m < k)
        {
            Path(leaves, start, k, m, path);
            path.Add(Range(leaves, start + k, n - k));
        }
        else
        {
            Path(leaves, start + k, n - k, m - k, path);
            path.Add(Range(leaves, start, k));
        }
    }

    /// <summary>
    /// PROOF(m, D[n]) (§2.1.4.1): the consistency proof from the tree of the first
    /// <paramref name="oldSize"/> leaves to the tree of all of them. Empty when the sizes are equal
    /// or the old tree is empty.
    /// </summary>
    public static IReadOnlyList<Sha256Digest> ConsistencyProof(IReadOnlyList<Sha256Digest> leafHashes, long oldSize)
    {
        ArgumentNullException.ThrowIfNull(leafHashes);
        if (oldSize < 0 || oldSize > leafHashes.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(oldSize), oldSize, $"The old size lies in [0, {leafHashes.Count}].");
        }

        var proof = new List<Sha256Digest>();
        if (oldSize > 0 && oldSize < leafHashes.Count)
        {
            SubProof(leafHashes, 0, leafHashes.Count, (int)oldSize, true, proof);
        }

        return proof;
    }

    private static void SubProof(IReadOnlyList<Sha256Digest> leaves, int start, int n, int m, bool complete, List<Sha256Digest> proof)
    {
        if (m == n)
        {
            if (!complete)
            {
                proof.Add(Range(leaves, start, n));
            }

            return;
        }

        int k = (int)MerkleTree.Split(n);
        if (m <= k)
        {
            SubProof(leaves, start, k, m, complete, proof);
            proof.Add(Range(leaves, start + k, n - k));
        }
        else
        {
            SubProof(leaves, start + k, n - k, m - k, false, proof);
            proof.Add(Range(leaves, start, k));
        }
    }

    private static Sha256Digest Range(IReadOnlyList<Sha256Digest> leaves, int start, int count)
    {
        var frontier = new MerkleFrontier();
        for (int i = start; i < start + count; i++)
        {
            frontier.AppendLeafHash(leaves[i]);
        }

        return frontier.Root();
    }

    /// <summary>
    /// §2.1.3.2: whether <paramref name="path"/> proves that <paramref name="leafHash"/> is leaf
    /// <paramref name="index"/> of the tree of <paramref name="size"/> leaves with root
    /// <paramref name="root"/>.
    /// </summary>
    public static bool VerifyInclusion(Sha256Digest leafHash, long index, long size, Sha256Digest root, IReadOnlyList<Sha256Digest> path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (index < 0 || index >= size)
        {
            return false;
        }

        long fn = index, sn = size - 1;
        var r = leafHash;
        foreach (var p in path)
        {
            if (sn == 0)
            {
                return false;
            }

            if ((fn & 1) == 1 || fn == sn)
            {
                r = MerkleTree.NodeHash(p, r);
                if ((fn & 1) == 0)
                {
                    while ((fn & 1) == 0 && fn != 0)
                    {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            }
            else
            {
                r = MerkleTree.NodeHash(r, p);
            }

            fn >>= 1;
            sn >>= 1;
        }

        return sn == 0 && r == root;
    }

    /// <summary>
    /// §2.1.4.2: whether <paramref name="proof"/> proves that the tree of <paramref name="oldSize"/>
    /// leaves with root <paramref name="oldRoot"/> is a prefix of the tree of
    /// <paramref name="newSize"/> leaves with root <paramref name="newRoot"/>. Two cases the RFC's
    /// algorithm does not reach take their natural meaning: equal sizes need an empty proof and
    /// equal roots, and an empty old tree needs an empty proof and the empty root.
    /// </summary>
    public static bool VerifyConsistency(long oldSize, Sha256Digest oldRoot, long newSize, Sha256Digest newRoot, IReadOnlyList<Sha256Digest> proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        if (oldSize < 0 || newSize < oldSize)
        {
            return false;
        }

        if (oldSize == newSize)
        {
            return proof.Count == 0 && oldRoot == newRoot;
        }

        if (oldSize == 0)
        {
            return proof.Count == 0 && oldRoot == MerkleTree.EmptyRoot;
        }

        if (proof.Count == 0)
        {
            return false;
        }

        var path = new List<Sha256Digest>(proof.Count + 1);
        if (BitOperations.IsPow2(oldSize))
        {
            path.Add(oldRoot);
        }

        path.AddRange(proof);

        long fn = oldSize - 1, sn = newSize - 1;
        while ((fn & 1) == 1)
        {
            fn >>= 1;
            sn >>= 1;
        }

        var fr = path[0];
        var sr = path[0];
        for (int i = 1; i < path.Count; i++)
        {
            var c = path[i];
            if (sn == 0)
            {
                return false;
            }

            if ((fn & 1) == 1 || fn == sn)
            {
                fr = MerkleTree.NodeHash(c, fr);
                sr = MerkleTree.NodeHash(c, sr);
                if ((fn & 1) == 0)
                {
                    while ((fn & 1) == 0 && fn != 0)
                    {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            }
            else
            {
                sr = MerkleTree.NodeHash(sr, c);
            }

            fn >>= 1;
            sn >>= 1;
        }

        return fr == oldRoot && sr == newRoot && sn == 0;
    }
}
