using ElectionGuard.Core.Models;
using static ElectionGuard.Core.RecordFormat.Mappers.WireValues;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat.Mappers;

/// <summary>
/// Device sections' framing items (design §4.5) and ballot locators. A domain
/// <see cref="DeviceChainRecord"/> is a <c>device_header</c> and a <c>device_close</c>; its
/// confirmation codes are not stored, they are the section's ballot items in order (§3.1). The
/// header's kind is the schema's <c>DeviceKind</c> number (1, 2), not the
/// <see cref="DeviceChainBallotKind"/> value (0, 1).
/// </summary>
internal static class DeviceMapper
{
    public static Pb.RecordItem ToItem(DeviceHeader header)
    {
        ArgumentNullException.ThrowIfNull(header);
        var item = new Pb.DeviceHeader
        {
            Kind = (Pb.DeviceKind)DeviceKey.KindNumber(header.Kind),
            DeviceId = header.DeviceId,
            HDi = Bytes(header.DeviceInformationHash),
            ChainingMode = (uint)header.ChainingMode,
        };

        if (header.InitialHash is { } initial)
        {
            item.InitialHash = Bytes(initial);
        }

        return new Pb.RecordItem { DeviceHeader = item };
    }

    /// <summary>
    /// The header of a device section. A kind the schema does not declare cannot be a section of
    /// this minor (D2 refuses it first); it is an <see cref="ArgumentException"/> here.
    /// </summary>
    public static DeviceHeader FromItem(Pb.DeviceHeader item)
    {
        ArgumentNullException.ThrowIfNull(item);
        var kind = DeviceKey.KindOf((long)item.Kind) ?? throw new ArgumentException($"Device kind {(int)item.Kind} is not declared (D2).", nameof(item));
        return new DeviceHeader(
            kind,
            item.DeviceId,
            VotingDeviceInformationHash.FromCanonicalBytes(RequireArray(item.HDi, 32, "H_DI")),
            (ChainingMode)item.ChainingMode,
            item.InitialHash.IsEmpty ? null : ConfirmationCode.FromCanonicalBytes(RequireArray(item.InitialHash, 32, "H_0")));
    }

    public static Pb.RecordItem ToItem(DeviceClose close)
    {
        ArgumentNullException.ThrowIfNull(close);
        ArgumentOutOfRangeException.ThrowIfNegative(close.BallotCount);
        var item = new Pb.DeviceClose
        {
            BallotCount = (ulong)close.BallotCount,
            ClosedAt = close.ClosedAt is { } at ? Time(at, "The device close time") : null,
        };

        if (close.ClosingChainingField is { } field)
        {
            item.ClosingChainingField = Bytes(field);
        }

        if (close.ClosingHash is { } hash)
        {
            item.ClosingHash = Bytes(hash);
        }

        return new Pb.RecordItem { DeviceClose = item };
    }

    public static DeviceClose FromItem(Pb.DeviceClose item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return new DeviceClose(
            (long)Math.Min(item.BallotCount, long.MaxValue),
            item.ClosingChainingField.IsEmpty ? null : ChainingField.FromCanonicalBytes(Require(item.ClosingChainingField, ChainingField.ByteLength, "B-bar_C")),
            item.ClosingHash.IsEmpty ? null : ConfirmationCode.FromCanonicalBytes(RequireArray(item.ClosingHash, 32, "H-bar")),
            item.ClosedAt is { } at ? Time(at) : null);
    }

    /// <summary>A device chain record as its section's header and close items.</summary>
    public static (Pb.RecordItem Header, Pb.RecordItem Close) ToItems(DeviceChainRecord record, DateTimeOffset? closedAt = null)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(record.ConfirmationCodes);
        return (
            ToItem(new DeviceHeader(record.BallotKind, record.DeviceId, record.DeviceInformationHash, record.ChainingMode, record.InitialHash)),
            ToItem(new DeviceClose(record.ConfirmationCodes.Count, record.ClosingChainingField, record.ClosingHash, closedAt)));
    }

    /// <summary>The device chain record of a section: its header, its close, and its ballot items' confirmation codes in order.</summary>
    public static DeviceChainRecord FromItems(DeviceHeader header, DeviceClose close, IEnumerable<ConfirmationCode> confirmationCodes)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(close);
        ArgumentNullException.ThrowIfNull(confirmationCodes);
        return new DeviceChainRecord
        {
            DeviceId = header.DeviceId,
            DeviceInformationHash = header.DeviceInformationHash,
            BallotKind = header.Kind,
            ChainingMode = header.ChainingMode,
            ConfirmationCodes = confirmationCodes.ToList(),
            InitialHash = header.InitialHash,
            ClosingChainingField = close.ClosingChainingField,
            ClosingHash = close.ClosingHash,
        };
    }

    public static Pb.BallotLocator ToItem(BallotLocator locator)
    {
        if (locator.Position < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(locator), locator.Position, "A ballot's chain position is 1-based.");
        }

        return new Pb.BallotLocator
        {
            Kind = (Pb.DeviceKind)locator.Device.KindByte,
            HDi = Bytes(locator.Device.DeviceInformationHash),
            Position = (ulong)locator.Position,
        };
    }

    public static BallotLocator FromItem(Pb.BallotLocator? item)
    {
        if (item is null)
        {
            throw new ArgumentException("The item names no ballot (locator absent).", nameof(item));
        }

        var kind = DeviceKey.KindOf((long)item.Kind) ?? throw new ArgumentException($"Device kind {(int)item.Kind} is not declared (D2).", nameof(item));
        return new BallotLocator(new DeviceKey(kind, VotingDeviceInformationHash.FromCanonicalBytes(RequireArray(item.HDi, 32, "H_DI"))), (long)Math.Min(item.Position, long.MaxValue));
    }
}
