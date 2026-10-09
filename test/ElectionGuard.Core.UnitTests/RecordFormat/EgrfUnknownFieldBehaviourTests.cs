using ElectionGuard.Core.RecordFormat.Protobuf;
using Google.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// What C# Google.Protobuf does with fields its schema does not know, which the canonicality check's
/// Method B (design document §4.4) relies on under user decision NQ-1: unknown fields are allowed
/// only after every known field, in ascending number order, and survive re-encoding. These pin the
/// runtime's behaviour so that an upgrade that changes it fails here, not in a verifier.
///
/// The messages are RecordHeader (fields 1 and 2; 3 reserved) and ElectionKeys (fields 1-3), as
/// a reader of this minor sees a record of a later minor that appended fields 4 and 5.
/// </summary>
public class EgrfUnknownFieldBehaviourTests
{
    // RecordHeader: format_major = 2 (08 02), format_minor = 1 (10 01).
    private static readonly byte[] Known = [0x08, 0x02, 0x10, 0x01];

    // Field 4, VARINT 7 (20 07); field 5, LEN "ab" (2A 02 61 62).
    private static readonly byte[] Unknown4 = [0x20, 0x07];
    private static readonly byte[] Unknown5 = [0x2A, 0x02, 0x61, 0x62];

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(x => x).ToArray();

    private static byte[] ReEncode(byte[] bytes, bool discardUnknown = false) =>
        (discardUnknown ? RecordHeader.Parser.WithDiscardUnknownFields(true) : RecordHeader.Parser).ParseFrom(bytes).ToByteArray();

    /// <summary>
    /// A canonical newer-minor encoding (known fields, then unknown fields ascending) re-encodes to
    /// the same bytes when unknown fields are kept (the default), so a re-encode by an older
    /// library preserves every digest. Discarding them shortens the bytes, which is how a reader at
    /// the record's own minor rejects any unknown field.
    /// </summary>
    [Fact]
    public void KnownThenAscendingUnknownTail_SurvivesReEncoding_UnlessDiscarded()
    {
        byte[] canonical = Concat(Known, Unknown4, Unknown5);

        Assert.Equal(canonical, ReEncode(canonical));
        Assert.Equal(Known, ReEncode(canonical, discardUnknown: true));

        // A repeated unknown LEN field (two contiguous records of field 5) is kept as it was.
        byte[] repeated = Concat(Known, Unknown5, Unknown5);
        Assert.Equal(repeated, ReEncode(repeated));
    }

    /// <summary>
    /// An unknown field placed before a known one is moved after the known fields on re-encoding,
    /// so Method B's byte comparison rejects it.
    /// </summary>
    [Fact]
    public void UnknownFieldBeforeAKnownField_IsMovedToTheEnd_SoMethodBRejectsIt()
    {
        byte[] interleaved = Concat([0x08, 0x02], Unknown4, [0x10, 0x01]);

        Assert.Equal(Concat(Known, Unknown4), ReEncode(interleaved));
        Assert.NotEqual(interleaved, ReEncode(interleaved));

        // The same in a message whose known fields are bytes: ElectionKeys k, k_hat, h_e, with an
        // unknown field 4 between k_hat and h_e.
        byte[] k = Concat([0x0A, 0x01, 0x11]), kHat = Concat([0x12, 0x01, 0x22]), hE = Concat([0x1A, 0x01, 0x33]);
        byte[] keys = Concat(k, kHat, Unknown4, hE);
        Assert.Equal(Concat(k, kHat, hE, Unknown4), ElectionKeys.Parser.ParseFrom(keys).ToByteArray());
    }

    /// <summary>
    /// Unknown fields out of number order are written back in the order they were read, so they
    /// re-encode to the same bytes: Method B alone does NOT catch them. The design therefore has a
    /// newer-minor record's unknown fields checked by the wire walk (Method A), which requires them
    /// ascending; this test documents why that check is not optional.
    /// </summary>
    [Fact]
    public void DescendingUnknownTail_SurvivesReEncoding_SoMethodBAloneDoesNotCatchIt()
    {
        byte[] descending = Concat(Known, Unknown5, Unknown4);

        Assert.Equal(descending, ReEncode(descending));
    }
}
