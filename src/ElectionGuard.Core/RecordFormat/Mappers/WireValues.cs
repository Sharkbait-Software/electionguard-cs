using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Serialization;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using System.Numerics;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat.Mappers;

/// <summary>
/// Value conversions shared by the record mappers: fixed-width values to and from <see cref="ByteString"/>,
/// packed (c ‖ v) proof lists, timestamps (D3) and hashed ciphertexts. Decoding assumes the item
/// passed <see cref="CanonicalProtobuf.Check"/> (so widths hold, D1); a wrong width here is a
/// <see cref="NonCanonicalEncodingException"/>, never a silent truncation or padding.
/// </summary>
internal static class WireValues
{
    public static ByteString Bytes(byte[] bytes) => ByteString.CopyFrom(bytes);

    public static ByteString Zp(IntegerModP value) => ByteString.CopyFrom(value.ToByteArray());

    public static ByteString Zq(IntegerModQ value) => ByteString.CopyFrom(value.ToByteArray());

    /// <summary>b(x, width) of a big integer that fits; throws <see cref="ArgumentException"/> if it does not.</summary>
    public static byte[] Fixed(BigInteger value, int width, string what)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length > width)
        {
            throw new ArgumentException($"{what} does not fit {width} bytes.");
        }

        return [.. new byte[width - bytes.Length], .. bytes];
    }

    /// <summary>(c_0 ‖ v_0 ‖ c_1 ‖ v_1 ‖ ...), 64 bytes per pair.</summary>
    public static ByteString Proofs(IEnumerable<ChallengeResponsePair> proofs)
    {
        var list = proofs.ToList();
        byte[] bytes = new byte[64 * list.Count];
        for (int i = 0; i < list.Count; i++)
        {
            list[i].Challenge.ToByteArray().CopyTo(bytes, 64 * i);
            list[i].Response.ToByteArray().CopyTo(bytes, 64 * i + 32);
        }

        return ByteString.CopyFrom(bytes);
    }

    public static ChallengeResponsePair[] Proofs(ByteString bytes, RecordDecodeContext context, string challengeCode, string responseCode, string what)
    {
        var span = Require(bytes, 64, what, multiple: true);
        var pairs = new ChallengeResponsePair[span.Length / 64];
        for (int i = 0; i < pairs.Length; i++)
        {
            pairs[i] = new ChallengeResponsePair
            {
                Challenge = context.Zq(span.Slice(64 * i, 32), challengeCode, $"{what}: c_{i}"),
                Response = context.Zq(span.Slice(64 * i + 32, 32), responseCode, $"{what}: v_{i}"),
            };
        }

        return pairs;
    }

    /// <summary>The bytes of a width-checked field (exactly <paramref name="width"/> bytes, or a positive multiple when <paramref name="multiple"/>).</summary>
    public static ReadOnlySpan<byte> Require(ByteString bytes, int width, string what, bool multiple = false)
    {
        var span = bytes.Span;
        bool ok = multiple ? span.Length > 0 && span.Length % width == 0 : span.Length == width;
        if (!ok)
        {
            throw new NonCanonicalEncodingException($"{what} has {span.Length} bytes, not {(multiple ? "a positive multiple of " : "")}{width} (D1; check the item's canonicality first).");
        }

        return span;
    }

    public static byte[] RequireArray(ByteString bytes, int width, string what, bool multiple = false) => Require(bytes, width, what, multiple).ToArray();

    /// <summary>
    /// D3: a UTC time of whole milliseconds as a <see cref="Timestamp"/>. Throws
    /// <see cref="ArgumentException"/> for a time before 1970 (the profile has no negative seconds)
    /// or with sub-millisecond ticks.
    /// </summary>
    public static Timestamp Time(DateTimeOffset time, string what)
    {
        if (time.Offset != TimeSpan.Zero || time.Ticks % TimeSpan.TicksPerMillisecond != 0)
        {
            throw new ArgumentException($"{what} is a UTC time of whole milliseconds in the record; got {time:O}.");
        }

        long milliseconds = time.ToUnixTimeMilliseconds();
        if (milliseconds < 0)
        {
            throw new ArgumentException($"{what} is before 1970-01-01T00:00:00Z, which the record cannot carry (D3); got {time:O}.");
        }

        return new Timestamp { Seconds = milliseconds / 1000, Nanos = (int)(milliseconds % 1000) * 1_000_000 };
    }

    public static DateTimeOffset Time(Timestamp timestamp) =>
        DateTimeOffset.FromUnixTimeMilliseconds(checked(timestamp.Seconds * 1000 + timestamp.Nanos / 1_000_000));

    public static Pb.HashedCiphertext Hashed(IntegerModP c0, byte[] c1, IntegerModQ challenge, IntegerModQ response) => new()
    {
        C0 = Zp(c0),
        C1 = Bytes(c1),
        C2 = Bytes([.. challenge.ToByteArray(), .. response.ToByteArray()]),
    };

    /// <summary>
    /// C_ξB of a ballot item, its C_ξB,0 and (c_B, v_B) out of range reported under
    /// <paramref name="subSection"/>: 13.structure on a ballot (Verification 13 reads it), 18.structure
    /// on an uncast pre-encrypted ballot (Verification 18 replaces 13 there, §4.5 p.66).
    /// </summary>
    public static EncryptedBallotNonce BallotNonce(Pb.HashedCiphertext? hashed, RecordDecodeContext context, string what, string subSection = RecordValueRanges.BallotNonce)
    {
        if (hashed is null)
        {
            // A missing C_ξB is structure (BallotStructure reports it); keep the ballot decodable.
            return null!;
        }

        var c2 = Require(hashed.C2, 64, $"{what}: C_ξB,2");
        return new EncryptedBallotNonce
        {
            C0 = context.Zp(Require(hashed.C0, 512, $"{what}: C_ξB,0"), subSection, $"{what}: C_ξB,0"),
            C1 = RequireArray(hashed.C1, 32, $"{what}: C_ξB,1", multiple: true),
            Challenge = context.Zq(c2[..32], subSection, $"{what}: c_B"),
            Response = context.Zq(c2[32..], subSection, $"{what}: v_B"),
        };
    }

    public static Pb.HashedCiphertext? BallotNonce(EncryptedBallotNonce? nonce) =>
        nonce is null ? null : Hashed(nonce.C0, nonce.C1, nonce.Challenge, nonce.Response);

    /// <summary>m × (α ‖ β), 1,024 bytes per encryption, in option position order.</summary>
    public static ByteString Vector(IEnumerable<EncryptedValue> vector)
    {
        var values = vector.ToList();
        byte[] bytes = new byte[1024 * values.Count];
        for (int i = 0; i < values.Count; i++)
        {
            values[i].Alpha.ToByteArray().CopyTo(bytes, 1024 * i);
            values[i].Beta.ToByteArray().CopyTo(bytes, 1024 * i + 512);
        }

        return ByteString.CopyFrom(bytes);
    }

    public static List<EncryptedValue> Vector(ByteString bytes, RecordDecodeContext context, string what)
    {
        var span = Require(bytes, 1024, what, multiple: true);
        var values = new List<EncryptedValue>(span.Length / 1024);
        for (int i = 0; i < span.Length / 1024; i++)
        {
            values.Add(new EncryptedValue
            {
                Alpha = context.Zp(span.Slice(1024 * i, 512), RecordValueRanges.SelectionCiphertext, $"{what}: α_{i + 1}"),
                Beta = context.Zp(span.Slice(1024 * i + 512, 512), RecordValueRanges.SelectionCiphertext, $"{what}: β_{i + 1}"),
            });
        }

        return values;
    }

    /// <summary>Splits a packed list of 32-byte values.</summary>
    public static IEnumerable<byte[]> Chunks(ByteString bytes, int width, string what)
    {
        var array = RequireArray(bytes, width, what, multiple: true);
        for (int i = 0; i < array.Length; i += width)
        {
            yield return array[i..(i + width)];
        }
    }

    /// <summary>A string that is not text: never equal to a manifest label (labels are what the manifest says).</summary>
    public static string UnknownLabel(string kind, long index) => $"\u0000{kind}-{index}";

    /// <summary>
    /// The schema's "ascending index" on a list inside an item (design §4.6, §4.8 layer 3): reports
    /// under <paramref name="subSection"/> the first entry whose index is below its predecessor's. Out of
    /// order, the same content would have a second byte encoding (and leaf hash) that a verifier
    /// enforcing the schema refuses, so this one does too. A repeated index is not reported here: it
    /// is a content error, which the structure checks of the verifications that read the list report
    /// (a contest listed twice).
    /// </summary>
    public static void RequireAscending<T>(IEnumerable<T> entries, Func<T, uint> index, RecordDecodeContext context, string subSection, string what)
    {
        bool first = true;
        uint previous = 0;
        foreach (var entry in entries)
        {
            uint current = index(entry);
            if (!first && current < previous)
            {
                context.Add(subSection, $"{what} are not in ascending index order: {current} follows {previous} (design §4.6).");
                return;
            }

            first = false;
            previous = current;
        }
    }
}
