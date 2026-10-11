using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;
using Spectre.Console.Cli;

namespace ElectionGuard.Verifier.Commands;

/// <summary>
/// <c>egrecord digest</c>: the TOC recomputed from the sections (design §5.1: "printing the same
/// roots is the equivalence check"), and whether the record's claimed TOC states the same. Exits 0
/// when the roots are computed and any claimed TOC matches them, 1 otherwise.
/// </summary>
public sealed class DigestCommand : AsyncCommand<RecordSettings>
{
    protected override async Task<int> ExecuteAsync(CommandContext context, RecordSettings settings, CancellationToken cancellationToken)
    {
        await using var reader = await ElectionRecord.OpenAsync(settings.Path, cancellationToken);
        var toc = await ElectionRecord.ComputeTocAsync(reader, -1, cancellationToken);
        string? mismatch = null;
        if (reader.ClaimedToc is not null)
        {
            try
            {
                await ElectionRecord.CheckClaimedTocAsync(reader, cancellationToken);
            }
            catch (VerificationFailedException failure)
            {
                mismatch = $"{failure.SubSection}: {failure.Message}";
            }
        }

        var phases = Enum.GetValues<RecordPhase>().Where(x => x <= toc.Phase).ToList();
        if (settings.Json)
        {
            Formats.WriteJson(json =>
            {
                json.WriteStartObject();
                json.WriteString("phase", Formats.Phase(toc.Phase));
                json.WriteString("root", toc.Root.ToString());
                json.WriteStartObject("phaseRoots");
                foreach (var phase in phases)
                {
                    json.WriteString(Formats.Phase(phase), toc.PhaseRoot(phase).ToString());
                }

                json.WriteEndObject();
                json.WriteString("claimedToc", reader.ClaimedToc is null ? "absent" : mismatch is null ? "matches" : "differs");
                if (mismatch is not null)
                {
                    json.WriteString("claimedTocMismatch", mismatch);
                }

                json.WriteStartArray("sections");
                foreach (var entry in toc.Entries)
                {
                    json.WriteStartObject();
                    json.WriteString("section", new SectionKey(entry.Type, entry.Key.Span).ToString());
                    json.WriteNumber("itemCount", entry.ItemCount);
                    json.WriteString("root", entry.Root.ToString());
                    json.WriteEndObject();
                }

                json.WriteEndArray();
                json.WriteEndObject();
            });
        }
        else
        {
            foreach (var phase in phases)
            {
                Console.Out.WriteLine($"{Formats.Phase(phase),-10} {toc.PhaseRoot(phase)}");
            }

            foreach (var entry in toc.Entries)
            {
                Console.Out.WriteLine($"  {new SectionKey(entry.Type, entry.Key.Span),-75} {entry.ItemCount,8} {entry.Root}");
            }

            Console.Out.WriteLine(reader.ClaimedToc is null ? "claimed TOC: absent" : mismatch is null ? "claimed TOC: matches" : $"claimed TOC: DIFFERS ({mismatch})");
        }

        return mismatch is null ? Program.Passed : Program.Failed;
    }
}
