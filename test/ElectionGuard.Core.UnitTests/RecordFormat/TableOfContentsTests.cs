using ElectionGuard.Core.RecordFormat;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>S10b-5: the table of contents, its phase roots and the Extends check (design §4.5, §4.9).</summary>
public class TableOfContentsTests
{
    private static Sha256Digest Root(int seed) => Sha256Digest.Of([(byte)seed, (byte)(seed >> 8)]);

    private static TocEntry Entry(RecordSectionType type, int seed, byte[]? key = null, long count = 1, bool critical = true) =>
        new(type, key ?? [], critical, count, Root(seed));

    private static byte[] DeviceKey(byte kind, byte fill) => [kind, .. Enumerable.Repeat(fill, 32)];

    private static List<TocEntry> Setup() =>
    [
        Entry(RecordSectionType.Header, 1),
        Entry(RecordSectionType.Parameters, 2),
        Entry(RecordSectionType.Manifest, 3),
        Entry(RecordSectionType.Guardians, 4, count: 3),
        Entry(RecordSectionType.ElectionKeys, 5),
    ];

    private static List<TocEntry> Sealed() =>
    [
        .. Setup(),
        Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x11), 7),
        Entry(RecordSectionType.Device, 11, DeviceKey(1, 0x22), 4),
        Entry(RecordSectionType.Device, 12, DeviceKey(2, 0x05), 3),
        Entry(RecordSectionType.DeviceAttestations, 13, count: 0),
    ];

    private static List<TocEntry> Aggregated() =>
    [
        .. Sealed(),
        Entry(RecordSectionType.EncryptedTally, 20, count: 2),
        Entry(RecordSectionType.ContestDataRequests, 21, count: 0),
    ];

    private static List<TocEntry> Final() =>
    [
        .. Aggregated(),
        Entry(RecordSectionType.DecryptedTally, 30),
        Entry(RecordSectionType.ChallengedBallotDecryptions, 31, count: 1),
        Entry(RecordSectionType.ContestDataDecryptions, 32, count: 0),
        Entry(RecordSectionType.UncastNonceReleases, 33, count: 0),
        Entry((RecordSectionType)0x8001, 40, [0xAB], critical: false),
    ];

    [Fact]
    public void Entry_LeafBytes_StartWithTheTocEntryTag_AndAreCanonical()
    {
        var entry = Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x11), 7);
        byte[] bytes = entry.ToRecordItemBytes();

        Assert.Equal([0x92, 0x03], bytes[..2]);
        Assert.True(CanonicalProtobuf.Check(bytes, 0).IsCanonical);
        Assert.Equal(MerkleTree.LeafHash(bytes), entry.LeafHash());

        // A false critical bit is absent (W2), not written as 0.
        Assert.True(Entry(RecordSectionType.Header, 1, critical: false).ToRecordItemBytes().Length < Entry(RecordSectionType.Header, 1).ToRecordItemBytes().Length);
    }

    [Fact]
    public void PhaseOf_IsTheHighByteCappedAtFinal()
    {
        Assert.Equal(RecordPhase.Setup, RecordSections.PhaseOf(RecordSectionType.ElectionKeys));
        Assert.Equal(RecordPhase.Sealed, RecordSections.PhaseOf(RecordSectionType.DeviceAttestations));
        Assert.Equal(RecordPhase.Aggregated, RecordSections.PhaseOf(RecordSectionType.ContestDataRequests));
        Assert.Equal(RecordPhase.Final, RecordSections.PhaseOf(RecordSectionType.UncastNonceReleases));
        Assert.Equal(RecordPhase.Final, RecordSections.PhaseOf((RecordSectionType)0x8000));
        Assert.True(RecordSections.IsVendor((RecordSectionType)0xFFFD));
        Assert.False(RecordSections.IsVendor((RecordSectionType)0xFFFE));
        Assert.True(RecordSections.FixedCritical(RecordSectionType.Device));
        Assert.Null(RecordSections.FixedCritical((RecordSectionType)0x8000));
        Assert.Null(RecordSections.FixedCritical((RecordSectionType)0x0203));
    }

    /// <summary>R_setup ⊑ R_sealed ⊑ R_aggregated ⊑ R_final: each phase root is the MTH of a prefix, and a consistency proof links any two.</summary>
    [Fact]
    public void PhaseRoots_ArePrefixes_AndConsistent()
    {
        var toc = new TableOfContents(Final());
        Assert.Equal(RecordPhase.Final, toc.Phase);
        Assert.Equal(toc.Root, toc.PhaseRoot(RecordPhase.Final));

        var phases = new[] { RecordPhase.Setup, RecordPhase.Sealed, RecordPhase.Aggregated, RecordPhase.Final };
        var sizes = new[] { 5, 9, 11, 16 };
        for (int i = 0; i < phases.Length; i++)
        {
            Assert.Equal(sizes[i], toc.PrefixLength(phases[i]));
            Assert.Equal(MerkleTree.Root(toc.LeafHashes.Take(sizes[i])), toc.PhaseRoot(phases[i]));
            for (int j = 0; j <= i; j++)
            {
                Assert.True(MerkleProofs.VerifyConsistency(sizes[j], toc.PhaseRoot(phases[j]), sizes[i], toc.PhaseRoot(phases[i]),
                    MerkleProofs.ConsistencyProof(toc.LeafHashes.Take(sizes[i]).ToList(), sizes[j])));
            }
        }

        // Each earlier record's own TOC has the same phase root as the later record's prefix.
        Assert.Equal(new TableOfContents(Setup()).Root, toc.PhaseRoot(RecordPhase.Setup));
        Assert.Equal(new TableOfContents(Sealed()).Root, toc.PhaseRoot(RecordPhase.Sealed));
        Assert.Equal(new TableOfContents(Aggregated()).Root, toc.PhaseRoot(RecordPhase.Aggregated));

        var aggregated = new TableOfContents(Aggregated());
        Assert.Throws<ArgumentOutOfRangeException>(() => aggregated.PhaseRoot(RecordPhase.Final));
    }

    [Fact]
    public void Extends_HoldsForEveryEarlierPhase_AndProvesIt()
    {
        var earlier = new[] { new TableOfContents(Setup()), new TableOfContents(Sealed()), new TableOfContents(Aggregated()) };
        var final = new TableOfContents(Final());
        foreach (var toc in earlier)
        {
            Assert.True(final.Extends(toc));
            Assert.True(MerkleProofs.VerifyConsistency(toc.Entries.Count, toc.Root, final.Entries.Count, final.Root, final.ConsistencyProof(toc)));
            Assert.False(toc.Extends(final));
        }

        Assert.True(final.Extends(final));
    }

    /// <summary>
    /// What the seal guards against: after R_sealed is fixed, a ballot appended to a device (its
    /// section's count and root change), a device section added after the last one, or a status byte
    /// flipped (the root changes) all break Extends, even though the later TOC still has every phase.
    /// </summary>
    [Fact]
    public void Extends_FailsWhenAnythingAtOrBeforeTheEarlierPhaseChanged()
    {
        var sealedToc = new TableOfContents(Sealed());

        var appended = Final();
        appended[5] = Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x11), 8);
        Assert.False(new TableOfContents(appended).Extends(sealedToc));

        var flipped = Final();
        flipped[6] = Entry(RecordSectionType.Device, 99, DeviceKey(1, 0x22), 4);
        Assert.False(new TableOfContents(flipped).Extends(sealedToc));

        var lateDevice = Final();
        lateDevice.Insert(8, Entry(RecordSectionType.Device, 14, DeviceKey(2, 0x77), 1));
        var late = new TableOfContents(lateDevice);
        Assert.False(late.Extends(sealedToc));
        Assert.Throws<ArgumentException>(() => late.ConsistencyProof(sealedToc));

        var removed = Final();
        removed.RemoveAt(8);
        Assert.False(new TableOfContents(removed).Extends(sealedToc));
    }

    [Fact]
    public void Constructor_RefusesNonCanonicalOrder_RepeatsAndPseudoSections()
    {
        Assert.Throws<ArgumentException>(() => new TableOfContents([]));

        var swapped = Setup();
        (swapped[1], swapped[2]) = (swapped[2], swapped[1]);
        Assert.Throws<ArgumentException>(() => new TableOfContents(swapped));

        var devices = Sealed();
        (devices[5], devices[6]) = (devices[6], devices[5]);
        Assert.Throws<ArgumentException>(() => new TableOfContents(devices));

        var repeated = Setup();
        repeated.Insert(1, Entry(RecordSectionType.Header, 9));
        Assert.Throws<ArgumentException>(() => new TableOfContents(repeated));

        Assert.Throws<ArgumentOutOfRangeException>(() => Entry((RecordSectionType)0xFFFE, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Entry((RecordSectionType)0xFFFF, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Entry(RecordSectionType.Header, 1, count: -1));

        // A key that is a prefix of another sorts first.
        Assert.True(TocEntry.CompareSections(Entry((RecordSectionType)0x8000, 1, [1]), Entry((RecordSectionType)0x8000, 1, [1, 0])) < 0);
    }

    [Fact]
    public void Entries_CompareKeysByContent()
    {
        Assert.Equal(Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x11)), Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x11)));
        Assert.Equal(Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x11)).GetHashCode(), Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x11)).GetHashCode());
        Assert.NotEqual(Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x11)), Entry(RecordSectionType.Device, 10, DeviceKey(1, 0x12)));
    }
}
