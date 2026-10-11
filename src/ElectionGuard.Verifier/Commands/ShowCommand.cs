using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using Spectre.Console.Cli;

namespace ElectionGuard.Verifier.Commands;

/// <summary>
/// <c>egrecord show</c>: a summary of a record without verifying it: format, encoding, carrier,
/// phase, the manifest's election facts and contests, n and k, H_E, the sections with their item
/// counts as the claimed TOC states them, and each device's id, kind, mode and ballot count. Exits 0,
/// or 1 when the stored manifest does not parse (the rest is still shown). Nothing shown is verified;
/// run <c>verify</c> for that.
/// </summary>
public sealed class ShowCommand : AsyncCommand<RecordSettings>
{
    protected override async Task<int> ExecuteAsync(CommandContext context, RecordSettings settings, CancellationToken cancellationToken)
    {
        await using var reader = await ElectionRecord.OpenAsync(settings.Path, cancellationToken);
        var setup = await reader.ReadSetupAsync(cancellationToken);
        // The manifest is the record's content: one that does not parse is shown as such, and the exit
        // code is the verdict on the record (1), not a usage error.
        Manifest? manifest = null;
        string? manifestError = null;
        try
        {
            manifest = setup.ToEncryptionRecord().Manifest;
        }
        catch (InvalidManifestException ex)
        {
            manifestError = ex.Message;
        }

        var devices = new List<(DeviceKey Key, DeviceHeader Header, DeviceClose? Close)>();
        foreach (var key in reader.Devices)
        {
            var device = reader.OpenDevice(key);
            devices.Add((key, await device.ReadHeaderAsync(cancellationToken), await device.ReadCloseAsync(cancellationToken)));
        }

        string Device((DeviceKey Key, DeviceHeader Header, DeviceClose? Close) d) =>
            $"{d.Header.DeviceId} ({Formats.Device(d.Key)}): mode {d.Header.ChainingMode}, {(d.Close is { } close ? $"{close.BallotCount} ballots, closed" : "open")}";

        if (settings.Json)
        {
            Formats.WriteJson(json =>
            {
                json.WriteStartObject();
                json.WriteString("format", Formats.Version(reader.Format));
                json.WriteString("encoding", Formats.Encoding(reader.Encoding));
                json.WriteString("carrier", Formats.Carrier(reader.Carrier));
                json.WriteString("phase", Formats.Phase(reader.Phase));
                if (manifest is not null)
                {
                    json.WriteString("electionId", manifest.ElectionId);
                    json.WriteString("electionName", manifest.ElectionName);
                    json.WriteString("electionDate", manifest.ElectionDate);
                    json.WriteString("electionType", manifest.ElectionType);
                    json.WriteString("jurisdiction", manifest.Jurisdiction);
                    json.WriteString("location", manifest.Location);
                    json.WriteNumber("contests", manifest.Contests.Count);
                }
                else
                {
                    json.WriteString("manifestError", manifestError);
                }

                json.WriteNumber("n", setup.GuardianParameters.N);
                json.WriteNumber("k", setup.GuardianParameters.K);
                json.WriteString("extendedBaseHash", Convert.ToHexStringLower((byte[])setup.ExtendedBaseHash));
                json.WriteBoolean("claimedToc", reader.ClaimedToc is not null);
                json.WriteStartArray("sections");
                foreach (var section in reader.Sections)
                {
                    json.WriteStartObject();
                    json.WriteString("section", section.ToString());
                    var entry = reader.ClaimedToc?.Entries.FirstOrDefault(x => x.Type == section.Type && x.Key.Span.SequenceEqual(section.Key.Span));
                    if (entry is not null)
                    {
                        json.WriteNumber("claimedItemCount", entry.ItemCount);
                    }

                    json.WriteEndObject();
                }

                json.WriteEndArray();
                json.WriteStartArray("devices");
                foreach (var d in devices)
                {
                    json.WriteStartObject();
                    json.WriteString("deviceId", d.Header.DeviceId);
                    json.WriteString("device", Formats.Device(d.Key));
                    json.WriteString("chainingMode", d.Header.ChainingMode.ToString());
                    if (d.Close is { } close)
                    {
                        json.WriteNumber("ballots", close.BallotCount);
                    }

                    json.WriteEndObject();
                }

                json.WriteEndArray();
                json.WriteNumber("signatureFiles", reader.SignatureFiles.Count);
                json.WriteEndObject();
            });
        }
        else
        {
            Console.Out.WriteLine($"record     {settings.Path}");
            Console.Out.WriteLine($"format     EGRF {Formats.Version(reader.Format)}, {Formats.Encoding(reader.Encoding)} {Formats.Carrier(reader.Carrier)}, phase {Formats.Phase(reader.Phase)}");
            Console.Out.WriteLine(manifest is null
                ? $"election   unknown: the manifest does not parse ({manifestError})"
                : $"election   {manifest.ElectionId}{(manifest.ElectionName is { } name ? $" \"{name}\"" : "")}{(manifest.ElectionDate is { } date ? $", {date}" : "")}; {manifest.Contests.Count} contest(s), {manifest.BallotStyles.Count} ballot style(s)");
            Console.Out.WriteLine($"guardians  {setup.GuardianParameters.K} of {setup.GuardianParameters.N}; H_E {Convert.ToHexStringLower((byte[])setup.ExtendedBaseHash)}");
            foreach (var section in reader.Sections)
            {
                var entry = reader.ClaimedToc?.Entries.FirstOrDefault(x => x.Type == section.Type && x.Key.Span.SequenceEqual(section.Key.Span));
                Console.Out.WriteLine($"section    {section}{(entry is null ? "" : $": {entry.ItemCount} items (claimed)")}");
            }

            foreach (var d in devices)
            {
                Console.Out.WriteLine($"device     {Device(d)}");
            }

            Console.Out.WriteLine($"signatures {reader.SignatureFiles.Count} file(s); {(reader.ClaimedToc is null ? "no claimed TOC" : "a claimed TOC")} (nothing here is verified: run egrecord verify)");
        }

        return manifest is null ? Program.Failed : Program.Passed;
    }
}
