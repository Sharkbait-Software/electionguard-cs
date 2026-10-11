using System.Globalization;
using System.Text;
using System.Text.Json;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;

namespace ElectionGuard.Verifier;

/// <summary>A <see cref="VerificationReport"/> as text for people and as JSON for scripts.</summary>
internal static class ReportOutput
{
    public static string Text(string path, IElectionRecordReader reader, VerificationReport report)
    {
        var text = new StringBuilder();
        text.Line($"record     {path}");
        text.Line($"format     EGRF {Formats.Version(report.RecordFormat)} (reader {Formats.Version(report.ReaderFormat)}), {Formats.Encoding(reader.Encoding)} {Formats.Carrier(reader.Carrier)}, phase {Formats.Phase(report.Phase)}, profile {report.Profile}");
        foreach (var (phase, root) in report.PhaseRoots.OrderBy(x => x.Key))
        {
            text.Line($"root       {Formats.Phase(phase),-10} {root}");
        }

        text.Line($"claimed    {(reader.ClaimedToc is null ? "no claimed TOC" : report.RootsMatchClaimedToc ? "the claimed TOC matches" : "the claimed TOC does NOT match")}");
        text.Line("verifications");
        foreach (var (number, outcome) in report.Verifications.OrderBy(x => x.Key))
        {
            text.Line($"  {number,2}  {outcome}");
        }

        var s = report.Statistics;
        text.Line($"ballots    {s.BallotItems} ({s.Cast} cast, {s.Challenged} challenged, {s.Spoiled} spoiled, {s.PreEncryptedCast} pre-encrypted cast, {s.UncastFull} uncast in full, {s.UncastCompact} uncast compact) on {s.Devices} devices; {s.ItemsDigested} items, {s.BytesDigested} bytes digested");
        if (s.UncastCompact > 0)
        {
            text.Line($"           17.A and 19.A-D held by construction on the {s.UncastCompact} compact uncast items (design §3.2)");
        }

        foreach (var attestation in report.Attestations)
        {
            text.Line($"attest     {Formats.Device(attestation.Device)} {attestation.Kind?.ToString() ?? "-"}: {(attestation.Present ? attestation.ContentsMatch ? "contents match" : "contents DO NOT match" : "absent")}; signature {attestation.Signature?.Status.ToString() ?? "-"}");
        }

        foreach (var signature in report.Signatures)
        {
            text.Line($"signature  {(signature.Phase is { } p ? Formats.Phase(p) : "?")} by {signature.SignerRole}: {(signature.ContentsMatch ? "contents match" : "contents DO NOT match")}; {signature.Signature.Status}");
        }

        foreach (var inclusion in report.Inclusions)
        {
            text.Line($"included   {Formats.Locator(inclusion.Locator)}: leaf {inclusion.LeafHash}, TOC entry {inclusion.TocIndex} of {inclusion.TocSize}, root {inclusion.Root}");
        }

        foreach (var skipped in report.SkippedUnknownContent)
        {
            text.Line($"skipped    {skipped}");
        }

        text.Line($"findings   {report.Findings.Count}{(report.Truncated ? " (truncated)" : "")}");
        foreach (var finding in report.Findings)
        {
            string where = string.Join(" ", new[]
            {
                finding.Section?.ToString(),
                finding.Ordinal is { } o ? $"#{o}" : null,
                finding.Locator is { } l ? Formats.Locator(l) : null,
            }.Where(x => x is not null));
            text.Line($"  {finding.SubSection,-14} {where}: {finding.Message}");
        }

        text.Line(report.Passed
            ? report.Complete ? "PASSED" : $"PASSED, INCOMPLETE: the record is EGRF {Formats.Version(report.RecordFormat)}, newer than this reader; content it does not understand was skipped"
            : "FAILED");
        return text.ToString();
    }

    public static void Json(Utf8JsonWriter json, IElectionRecordReader reader, VerificationReport report, int exitCode)
    {
        json.WriteStartObject();
        json.WriteBoolean("passed", report.Passed);
        json.WriteBoolean("complete", report.Complete);
        json.WriteNumber("exitCode", exitCode);
        json.WriteString("profile", report.Profile.ToString());
        json.WriteString("phase", Formats.Phase(report.Phase));
        json.WriteString("recordFormat", Formats.Version(report.RecordFormat));
        json.WriteString("readerFormat", Formats.Version(report.ReaderFormat));
        json.WriteString("encoding", Formats.Encoding(reader.Encoding));
        json.WriteString("carrier", Formats.Carrier(reader.Carrier));
        json.WriteStartObject("phaseRoots");
        foreach (var (phase, root) in report.PhaseRoots.OrderBy(x => x.Key))
        {
            json.WriteString(Formats.Phase(phase), root.ToString());
        }

        json.WriteEndObject();
        json.WriteBoolean("rootsMatchClaimedToc", report.RootsMatchClaimedToc);
        json.WriteStartObject("verifications");
        foreach (var (number, outcome) in report.Verifications.OrderBy(x => x.Key))
        {
            json.WriteString(number.ToString(CultureInfo.InvariantCulture), outcome.ToString());
        }

        json.WriteEndObject();
        json.WriteStartArray("findings");
        foreach (var finding in report.Findings)
        {
            json.WriteStartObject();
            json.WriteString("subSection", finding.SubSection);
            json.WriteNumber("verification", finding.Verification);
            if (finding.Section is { } section)
            {
                json.WriteString("section", section.ToString());
            }

            if (finding.Ordinal is { } ordinal)
            {
                json.WriteNumber("ordinal", ordinal);
            }

            if (finding.Locator is { } locator)
            {
                json.WriteString("locator", Formats.Locator(locator));
            }

            if (finding.SelectionEncryptionIdentifierHex is { } idB)
            {
                json.WriteString("idB", idB);
            }

            json.WriteString("message", finding.Message);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        json.WriteBoolean("truncated", report.Truncated);
        json.WriteStartArray("attestations");
        foreach (var a in report.Attestations)
        {
            json.WriteStartObject();
            json.WriteString("device", Formats.Device(a.Device));
            json.WriteString("kind", a.Kind?.ToString());
            json.WriteBoolean("present", a.Present);
            json.WriteBoolean("contentsMatch", a.ContentsMatch);
            json.WriteString("signature", a.Signature?.Status.ToString());
            json.WriteString("message", a.Message);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        json.WriteStartArray("signatures");
        foreach (var signature in report.Signatures)
        {
            json.WriteStartObject();
            json.WriteString("phase", signature.Phase is { } p ? Formats.Phase(p) : null);
            json.WriteString("signerRole", signature.SignerRole);
            json.WriteBoolean("contentsMatch", signature.ContentsMatch);
            json.WriteString("status", signature.Signature.Status.ToString());
            json.WriteString("keyId", signature.Signature.KeyIdHex);
            json.WriteString("message", signature.Message);
            json.WriteEndObject();
        }

        json.WriteEndArray();
        json.WriteStartArray("skippedUnknownContent");
        foreach (var skipped in report.SkippedUnknownContent)
        {
            json.WriteStringValue(skipped);
        }

        json.WriteEndArray();
        Locators(json, "ballotsToOpen", report.BallotsToOpen);
        Locators(json, "uncastBallotsToRelease", report.UncastBallotsToRelease);
        json.WriteStartArray("inclusions");
        foreach (var inclusion in report.Inclusions)
        {
            Inclusion(json, inclusion);
        }

        json.WriteEndArray();
        var s = report.Statistics;
        json.WriteStartObject("statistics");
        json.WriteNumber("ballotItems", s.BallotItems);
        json.WriteNumber("cast", s.Cast);
        json.WriteNumber("challenged", s.Challenged);
        json.WriteNumber("spoiled", s.Spoiled);
        json.WriteNumber("preEncryptedCast", s.PreEncryptedCast);
        json.WriteNumber("uncastFull", s.UncastFull);
        json.WriteNumber("uncastCompact", s.UncastCompact);
        json.WriteNumber("devices", s.Devices);
        json.WriteNumber("itemsDigested", s.ItemsDigested);
        json.WriteNumber("bytesDigested", s.BytesDigested);
        json.WriteEndObject();
        json.WriteEndObject();
    }

    public static void Inclusion(Utf8JsonWriter json, BallotInclusion inclusion)
    {
        json.WriteStartObject();
        json.WriteString("locator", Formats.Locator(inclusion.Locator));
        json.WriteString("leafHash", inclusion.LeafHash.ToString());
        json.WriteNumber("sectionSize", inclusion.SectionSize);
        json.WriteStartArray("sectionPath");
        foreach (var node in inclusion.SectionPath)
        {
            json.WriteStringValue(node.ToString());
        }

        json.WriteEndArray();
        json.WriteString("sectionRoot", inclusion.SectionRoot.ToString());
        json.WriteNumber("tocIndex", inclusion.TocIndex);
        json.WriteNumber("tocSize", inclusion.TocSize);
        json.WriteStartArray("tocPath");
        foreach (var node in inclusion.TocPath)
        {
            json.WriteStringValue(node.ToString());
        }

        json.WriteEndArray();
        json.WriteString("root", inclusion.Root.ToString());
        json.WriteEndObject();
    }

    private static void Locators(Utf8JsonWriter json, string name, IEnumerable<BallotLocator> locators)
    {
        json.WriteStartArray(name);
        foreach (var locator in locators)
        {
            json.WriteStringValue(Formats.Locator(locator));
        }

        json.WriteEndArray();
    }
}
