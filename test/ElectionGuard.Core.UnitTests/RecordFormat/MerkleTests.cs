using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-5: the RFC 9162 Merkle tree (design §4.9). Pinned to the Certificate Transparency reference
/// vectors (test/egrf/vectors/merkle-rfc9162.json, transcribed from transparency-dev/merkle; RFC 9162
/// itself carries none), and cross-checked against a naive recursive MTH written straight from the
/// RFC's definition for every size 0..17 and 1,000.
/// </summary>
public class MerkleTests
{
    private static readonly JsonObject Vectors = JsonNode.Parse(EgrfTestFiles.ReadText(EgrfTestFiles.Vector("merkle-rfc9162.json")))!.AsObject();

    private static Sha256Digest D(JsonNode? hex) => Sha256Digest.FromHex((string)hex!);

    private static List<Sha256Digest> Proof(JsonNode? array) => array!.AsArray().Select(D).ToList();

    /// <summary>The RFC's definition, recursively, independent of the frontier.</summary>
    private static Sha256Digest NaiveRoot(IReadOnlyList<byte[]> data)
    {
        if (data.Count == 0)
        {
            return Sha256Digest.FromBytes(SHA256.HashData(Array.Empty<byte>()));
        }

        if (data.Count == 1)
        {
            return Sha256Digest.FromBytes(SHA256.HashData([0x00, .. data[0]]));
        }

        int k = 1;
        while (k * 2 < data.Count)
        {
            k *= 2;
        }

        var left = NaiveRoot(data.Take(k).ToList()).ToArray();
        var right = NaiveRoot(data.Skip(k).ToList()).ToArray();
        return Sha256Digest.FromBytes(SHA256.HashData([0x01, .. left, .. right]));
    }

    private static List<byte[]> Leaves(int n) => Enumerable.Range(0, n).Select(i => BitConverter.GetBytes(i * 7919 + 3).Concat(new byte[i % 5]).ToArray()).ToList();

    private static List<Sha256Digest> LeafHashes(IEnumerable<byte[]> leaves) => leaves.Select(x => MerkleTree.LeafHash(x)).ToList();

    [Fact]
    public void ReferenceVectors_RootsBySize_0To8()
    {
        var leaves = Vectors["leafInputs"]!.AsArray().Select(x => Convert.FromHexString((string)x!)).ToList();
        var roots = Vectors["rootsBySize"]!.AsArray().Select(D).ToList();
        Assert.Equal(9, roots.Count);
        Assert.Equal(D(Vectors["emptyRoot"]), MerkleTree.EmptyRoot);

        var frontier = new MerkleFrontier();
        Assert.Equal(roots[0], frontier.Root());
        for (int n = 1; n <= 8; n++)
        {
            frontier.Append(leaves[n - 1]);
            Assert.Equal(roots[n], frontier.Root());
            Assert.Equal(roots[n], NaiveRoot(leaves.Take(n).ToList()));
        }
    }

    [Fact]
    public void ReferenceVectors_InclusionProofs_VerifyAndAreTheOnesGenerated()
    {
        var leaves = LeafHashes(Vectors["leafInputs"]!.AsArray().Select(x => Convert.FromHexString((string)x!)));
        var probes = Vectors["inclusion"]!.AsArray();
        Assert.NotEmpty(probes);
        foreach (var probe in probes)
        {
            long index = (long)probe!["leafIdx"]!, size = (long)probe["treeSize"]!;
            var root = D(probe["root"]);
            var leaf = D(probe["leafHash"]);
            var proof = Proof(probe["proof"]);

            Assert.True(MerkleProofs.VerifyInclusion(leaf, index, size, root, proof), (string)probe["source"]!);
            Assert.Equal(leaves[(int)index], leaf);
            Assert.Equal(proof, MerkleProofs.InclusionProof(leaves.Take((int)size).ToList(), index));

            // The probes' own negatives, in kind: another leaf, an extra node, an index past the size.
            // (A wrong size is not always caught by the path alone: index 1's path in a tree of 5
            // computes the same root read as a tree of 6. The root is what binds the size.)
            Assert.False(MerkleProofs.VerifyInclusion(MerkleTree.LeafHash([0xFF]), index, size, root, proof));
            Assert.False(MerkleProofs.VerifyInclusion(leaf, index, size, root, [.. proof, leaf]));
            Assert.False(MerkleProofs.VerifyInclusion(leaf, size, size, root, proof));
        }
    }

    [Fact]
    public void ReferenceVectors_ConsistencyProofs_VerifyAndAreTheOnesGenerated()
    {
        var leaves = LeafHashes(Vectors["leafInputs"]!.AsArray().Select(x => Convert.FromHexString((string)x!)));
        var probes = Vectors["consistency"]!.AsArray();
        Assert.NotEmpty(probes);
        foreach (var probe in probes)
        {
            long size1 = (long)probe!["size1"]!, size2 = (long)probe["size2"]!;
            var root1 = D(probe["root1"]);
            var root2 = D(probe["root2"]);
            var proof = Proof(probe["proof"]);

            Assert.True(MerkleProofs.VerifyConsistency(size1, root1, size2, root2, proof), (string)probe["source"]!);
            Assert.Equal(proof, MerkleProofs.ConsistencyProof(leaves.Take((int)size2).ToList(), size1));
            Assert.False(MerkleProofs.VerifyConsistency(size1, root2, size2, root2, proof) && root1 != root2);
            Assert.False(MerkleProofs.VerifyConsistency(size1, root1, size2, root1, proof) && root1 != root2);
        }
    }

    [Fact]
    public void Frontier_EqualsTheNaiveDefinition_ForSizes0To17And1000()
    {
        foreach (int n in Enumerable.Range(0, 18).Append(1000))
        {
            var leaves = Leaves(n);
            var frontier = new MerkleFrontier();
            leaves.ForEach(x => frontier.Append(x));

            Assert.Equal(n, frontier.Count);
            Assert.Equal(NaiveRoot(leaves), frontier.Root());
            Assert.Equal(frontier.Root(), MerkleTree.Root(LeafHashes(leaves)));
        }
    }

    /// <summary>A frontier saved and restored at any point continues exactly as an uninterrupted one.</summary>
    [Fact]
    public void Frontier_SerializedAndResumed_EqualsAnUninterruptedRun()
    {
        var leaves = Leaves(70);
        var uninterrupted = new MerkleFrontier();
        leaves.ForEach(x => uninterrupted.Append(x));

        for (int cut = 0; cut <= leaves.Count; cut++)
        {
            var first = new MerkleFrontier();
            leaves.Take(cut).ToList().ForEach(x => first.Append(x));
            byte[] state = first.Serialize();
            Assert.Equal(8 + 32 * System.Numerics.BitOperations.PopCount((ulong)cut), state.Length);

            var resumed = MerkleFrontier.Deserialize(state);
            Assert.Equal(first.Root(), resumed.Root());
            leaves.Skip(cut).ToList().ForEach(x => resumed.Append(x));
            Assert.Equal(uninterrupted.Root(), resumed.Root());
            Assert.Equal(uninterrupted.Serialize(), resumed.Serialize());
        }

        Assert.Throws<FormatException>(() => MerkleFrontier.Deserialize(new byte[7]));
        Assert.Throws<FormatException>(() => MerkleFrontier.Deserialize([0, 0, 0, 0, 0, 0, 0, 3, .. new byte[32]]));
        Assert.Throws<FormatException>(() => MerkleFrontier.Deserialize([0x80, 0, 0, 0, 0, 0, 0, 0]));
    }

    /// <summary>Every inclusion proof of every leaf in trees of 1..17 leaves verifies, and fails for any other leaf, index or root.</summary>
    [Fact]
    public void InclusionProofs_AllLeaves_Sizes1To17_VerifyAndRejectTampering()
    {
        for (int n = 1; n <= 17; n++)
        {
            var leaves = LeafHashes(Leaves(n));
            var root = MerkleTree.Root(leaves);
            for (int m = 0; m < n; m++)
            {
                var proof = MerkleProofs.InclusionProof(leaves, m);
                Assert.True(MerkleProofs.VerifyInclusion(leaves[m], m, n, root, proof), $"n={n} m={m}");
                Assert.False(MerkleProofs.VerifyInclusion(leaves[(m + 1) % n], m, n, root, proof) && n > 1);
                Assert.False(MerkleProofs.VerifyInclusion(leaves[m], m, n, MerkleTree.LeafHash([1]), proof));
                for (int i = 0; i < proof.Count; i++)
                {
                    var tampered = proof.ToList();
                    tampered[i] = MerkleTree.NodeHash(tampered[i], tampered[i]);
                    Assert.False(MerkleProofs.VerifyInclusion(leaves[m], m, n, root, tampered));
                }

                if (proof.Count > 0)
                {
                    Assert.False(MerkleProofs.VerifyInclusion(leaves[m], m, n, root, proof.Take(proof.Count - 1).ToList()));
                }
            }
        }
    }

    /// <summary>
    /// Prefix consistency, the property phase roots rely on: for every pair of sizes 0 &lt;= m &lt;= n
    /// &lt;= 17 the generated proof verifies, and it fails once a leaf of the old tree is changed.
    /// </summary>
    [Fact]
    public void ConsistencyProofs_EveryPrefixPair_UpTo17_VerifyAndRejectAChangedLeaf()
    {
        var all = LeafHashes(Leaves(17));
        for (int n = 0; n <= 17; n++)
        {
            var leaves = all.Take(n).ToList();
            var newRoot = MerkleTree.Root(leaves);
            for (int m = 0; m <= n; m++)
            {
                var oldRoot = MerkleTree.Root(leaves.Take(m));
                var proof = MerkleProofs.ConsistencyProof(leaves, m);
                Assert.True(MerkleProofs.VerifyConsistency(m, oldRoot, n, newRoot, proof), $"m={m} n={n}");

                if (m > 0)
                {
                    var changed = leaves.ToList();
                    changed[m - 1] = MerkleTree.LeafHash([0xEE]);
                    Assert.False(MerkleProofs.VerifyConsistency(m, oldRoot, n, MerkleTree.Root(changed), MerkleProofs.ConsistencyProof(changed, m)), $"m={m} n={n} changed");
                    Assert.False(MerkleProofs.VerifyConsistency(m, MerkleTree.Root(changed.Take(m)), n, newRoot, proof), $"m={m} n={n} old root");
                }
            }
        }

        // A large tree: prefix 600 of 1000.
        var big = LeafHashes(Leaves(1000));
        Assert.True(MerkleProofs.VerifyConsistency(600, MerkleTree.Root(big.Take(600)), 1000, MerkleTree.Root(big), MerkleProofs.ConsistencyProof(big, 600)));
        Assert.False(MerkleProofs.VerifyConsistency(600, MerkleTree.Root(big.Take(601)), 1000, MerkleTree.Root(big), MerkleProofs.ConsistencyProof(big, 600)));
    }

    /// <summary>Design §4.9's exact leaf bytes: leaf = SHA-256(0x00 || 0x9A 0x03 0x22 0x0A 0x20 || H_j).</summary>
    [Fact]
    public void CodesRoot_LeafBytesAreTheDesignsExactBytes()
    {
        var codes = Enumerable.Range(1, 5).Select(i => new ConfirmationCode(Enumerable.Repeat((byte)i, 32).ToArray())).ToList();

        byte[] leaf = RecordDigests.ConfirmationCodeLeafBytes(codes[0]);
        Assert.Equal([0x9A, 0x03, 0x22, 0x0A, 0x20, .. (byte[])codes[0]], leaf);

        var expected = NaiveRoot(codes.Select(x => (byte[])[0x9A, 0x03, 0x22, 0x0A, 0x20, .. (byte[])x]).ToList());
        Assert.Equal(expected, RecordDigests.CodesRoot(codes));
        Assert.Equal(MerkleTree.EmptyRoot, RecordDigests.CodesRoot([]));
    }

    [Fact]
    public void Sha256Digest_RoundTripsAndOrdersByBytes()
    {
        var bytes = Enumerable.Range(0, 32).Select(i => (byte)(i * 9)).ToArray();
        var digest = Sha256Digest.FromBytes(bytes);
        Assert.Equal(bytes, digest.ToArray());
        Assert.Equal(Convert.ToHexStringLower(bytes), digest.ToString());
        Assert.Equal(digest, Sha256Digest.FromHex(digest.ToString().ToUpperInvariant()));
        Assert.Throws<ArgumentException>(() => Sha256Digest.FromBytes(new byte[31]));

        var lower = bytes.ToArray();
        lower[31]--;
        Assert.True(Sha256Digest.FromBytes(lower).CompareTo(digest) < 0);
        var higher = bytes.ToArray();
        higher[0] = 0xFF;
        Assert.True(Sha256Digest.FromBytes(higher).CompareTo(digest) > 0);
    }
}
