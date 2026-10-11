using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Verify;
using Google.Protobuf;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// The election record's item codec for one encrypted ballot at a time (S10b-16): the encoding a
/// device and a collector exchange a ballot in, and the one a record stores it in. It replaces the
/// retired <c>IEncryptedBallotSerializer</c> pair (protobuf-net and System.Text.Json; design §9.2
/// S10b-16).
/// <para>The record holds a ballot as this library re-encodes it from the domain ballot
/// (<c>DeviceSectionWriter.AppendAsync</c> takes an <see cref="EncryptedBallot"/>; there is no
/// bytes-level append), not necessarily the bytes the device sent. For a canonical item of this
/// library's format minor that decodes without a finding, decoding then encoding is meant to give
/// those bytes back, with one known exception: an item without the free-text <c>ballot_ref</c>
/// decodes with the lowercase hex of id_B as its <see cref="EncryptedBallot.Id"/>, which encoding
/// writes back as <c>ballot_ref</c>. The stored item, its leaf and its section root then differ from
/// what the device computed over its own bytes. (A weight cannot diverge: one of 2^31 or more is
/// decode rule D4, refused before the mapper runs.)</para>
/// <para>The binary form is the canonical protobuf encoding of one <c>RecordItem</c> (design §4.2:
/// an <c>encrypted_ballot</c>, or a <c>pre_encrypted_cast_ballot</c> for a cast pre-encrypted
/// ballot), never framed; the JSON form is that item's proto3 JSON line (design §5.5), which is
/// not hashed and is read back into the canonical bytes. Items carry contest and field indices in
/// manifest order, not labels, so both directions take the manifest; the device id is the record
/// section's (<see cref="DeviceHeader.DeviceId"/>), not the item's, so decoding takes it.</para>
/// <para>Decoding is strict: bytes that are not the canonical encoding (wire rules W1-W8, decode
/// rules D1-D5), or a JSON line the projection refuses, throw <see cref="NonCanonicalEncodingException"/>
/// naming the rule; an item that is not a ballot throws it too. A value out of range (≥ p, ≥ q)
/// is not a format rule (design §4.8): it throws <see cref="VerificationFailedException"/> under
/// the sub-section of the verification that owns it (for example "6.A" for an α ≥ p), as the
/// record verifier reports it. Nothing is reduced.</para>
/// </summary>
public static class RecordItemCodec
{
    /// <summary>The canonical item bytes of <paramref name="ballot"/>, a ballot whose status has been recorded (cast, challenged or spoiled).</summary>
    public static byte[] EncodeBallot(EncryptedBallot ballot, Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(manifest);
        if (ballot.Status is not (BallotStatus.Cast or BallotStatus.Challenged or BallotStatus.Spoiled))
        {
            throw new ArgumentException($"Ballot {ballot.Id} is {ballot.Status}; its record item carries a recorded status (cast, challenged or spoiled).", nameof(ballot));
        }

        return BallotMapper.ToItem(ballot, manifest).ToByteArray();
    }

    /// <summary>The ballot in the canonical item bytes <paramref name="item"/>, recorded by device <paramref name="deviceId"/>.</summary>
    public static EncryptedBallot DecodeBallot(ReadOnlySpan<byte> item, Manifest manifest, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(deviceId);
        var parsed = ParseCanonical(item);
        if (parsed.ItemCase is not (Pb.RecordItem.ItemOneofCase.EncryptedBallot or Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot))
        {
            throw new NonCanonicalEncodingException($"The item is member {(int)parsed.ItemCase} of RecordItem, not an encrypted_ballot or a pre_encrypted_cast_ballot.");
        }

        var decoded = BallotMapper.FromItem(parsed, manifest, deviceId);
        if (decoded.Value is { } ballot)
        {
            return ballot;
        }

        var first = decoded.Findings[0];
        throw new VerificationFailedException(first.SubSection, string.Join(" ", decoded.Findings.Select(x => $"{x.SubSection}: {x.Message}")));
    }

    /// <summary>The proto3 JSON line (UTF-8, without a line feed) of <paramref name="ballot"/>.</summary>
    public static byte[] EncodeBallotJson(EncryptedBallot ballot, Manifest manifest) => ToJson(EncodeBallot(ballot, manifest));

    /// <summary>The ballot on the proto3 JSON line <paramref name="line"/>, recorded by device <paramref name="deviceId"/>.</summary>
    public static EncryptedBallot DecodeBallotJson(ReadOnlySpan<byte> line, Manifest manifest, string deviceId) => DecodeBallot(FromJson(line), manifest, deviceId);

    /// <summary>
    /// The proto3 JSON line (UTF-8, without a line feed) of the canonical item <paramref name="item"/>,
    /// any <c>RecordItem</c> of this library's format minor, as a <c>.jsonl</c> record holds it.
    /// </summary>
    public static byte[] ToJson(ReadOnlySpan<byte> item)
    {
        var check = CanonicalProtobuf.Check(item, RecordFormatVersion.Library.Minor);
        if (!check.IsCanonical)
        {
            throw new NonCanonicalEncodingException($"The item is not canonical ({check.Rule}): {check.Message}");
        }

        return RecordJson.FormatItem(item, check);
    }

    /// <summary>The canonical item bytes of the <c>RecordItem</c> on the proto3 JSON line <paramref name="line"/> (design §5.5).</summary>
    public static byte[] FromJson(ReadOnlySpan<byte> line)
    {
        byte[] item;
        try
        {
            item = RecordJson.ParseItem(line, RecordFormatVersion.Library.Minor);
        }
        catch (VerificationFailedException ex)
        {
            throw new NonCanonicalEncodingException($"The line is not a RecordItem in the proto3 JSON mapping ({ex.SubSection}): {ex.Message}");
        }

        // The parse yields Google.Protobuf's encoding of what it read; the decode rules (widths,
        // enums, timestamps, the one-member envelope) are checked on those bytes, as a reader does.
        var check = CanonicalProtobuf.Check(item, RecordFormatVersion.Library.Minor);
        if (!check.IsCanonical)
        {
            throw new NonCanonicalEncodingException($"The line's item is not canonical ({check.Rule}): {check.Message}");
        }

        return item;
    }

    private static Pb.RecordItem ParseCanonical(ReadOnlySpan<byte> item)
    {
        var check = CanonicalProtobuf.Check(item, RecordFormatVersion.Library.Minor);
        if (!check.IsCanonical)
        {
            throw new NonCanonicalEncodingException($"The item is not canonical ({check.Rule}): {check.Message}");
        }

        return Pb.RecordItem.Parser.ParseFrom(item);
    }
}
