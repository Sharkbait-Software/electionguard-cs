using ElectionGuard.Core.RecordFormat;
using Google.Protobuf;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordDirectoryCarrierTests;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// Edits a written protobuf directory record item by item, then rewrites its claimed TOC from what is
/// on disk, so a tamper is caught by the check it targets, not by <c>R.root</c>.
/// </summary>
internal static class RecordTamper
{
    /// <summary>Each device's S_device to its key.</summary>
    public static async Task<Dictionary<string, DeviceKey>> DevicesAsync(string directory)
    {
        await using var reader = await ElectionRecord.OpenAsync(directory);
        var devices = new Dictionary<string, DeviceKey>();
        foreach (var key in reader.Devices)
        {
            devices[(await reader.OpenDevice(key).ReadHeaderAsync()).DeviceId] = key;
        }

        return devices;
    }

    public static string PathOf(string directory, SectionKey section) => Path.Combine(directory, RecordLayout.SegmentPath(section, 0, RecordEncoding.Protobuf));

    /// <summary>Hands the items of <paramref name="section"/>'s first segment to <paramref name="edit"/> (ordinal = list index), then writes them back.</summary>
    public static void Edit(string directory, SectionKey section, Action<List<Pb.RecordItem>> edit)
    {
        string path = PathOf(directory, section);
        var frames = Frames(File.ReadAllBytes(path));
        var items = frames.Skip(1).Select(x => Pb.RecordItem.Parser.ParseFrom(Payload(x))).ToList();
        edit(items);
        File.WriteAllBytes(path, Join([frames[0], .. items.Select(x => Frame(x.ToByteArray()))]));
    }

    public static void Edit(string directory, RecordSectionType type, Action<List<Pb.RecordItem>> edit) => Edit(directory, SectionKey.Of(type), edit);

    /// <summary>Rewrites the claimed TOC as the TOC of the sections on disk.</summary>
    public static async Task ReTocAsync(string directory)
    {
        TableOfContents toc;
        await using (var reader = await ElectionRecord.OpenAsync(directory))
        {
            toc = await ElectionRecord.ComputeTocAsync(reader);
        }

        await ElectionRecordWriter.WriteTocAsync(directory, toc, RecordEncoding.Protobuf, CancellationToken.None);
    }

    /// <summary>The bytes with their last byte's lowest bit flipped: a value of the same width that is another one.</summary>
    public static ByteString Flip(ByteString bytes, int fromEnd = 1)
    {
        byte[] copy = bytes.ToByteArray();
        copy[^fromEnd] ^= 0x01;
        return ByteString.CopyFrom(copy);
    }
}
