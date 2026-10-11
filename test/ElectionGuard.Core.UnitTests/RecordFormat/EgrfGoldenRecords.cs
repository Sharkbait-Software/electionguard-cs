using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Testing.Common;
using Google.Protobuf;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordDirectoryCarrierTests;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// The golden records of design §5.7 (S10b-12) under <c>test/egrf/records/</c>: three complete
/// elections, each in all four representations (protobuf and JSON, directory and <c>.zip</c>), a few
/// positive edge cases, and negative records, at least one per R-code, each made from a golden record
/// by one mutation. <c>index.json</c> lists every record with the R-codes this library's reader and
/// verifier report for it, its phase roots and whether it is complete; the Python reference reader
/// (<c>test/egrf/egrf_ref.py</c>) must reproduce them (<see cref="EgrfGoldenRecordTests"/>).
/// Nonces are not seedable, so regenerating (<c>EGRF_WRITE_RECORDS=1</c>) rewrites every file; the
/// tests compare both readers on the committed files, never a root pinned in code.
/// <c>EGRF_WRITE_RECORDS=missing</c> writes only the records that are not there yet, from the committed
/// golden records, and rewrites <c>index.json</c> (the other entries' verdicts are recomputed from
/// files that did not change).
/// </summary>
internal static class EgrfGoldenRecords
{
    public const string WriteVariable = "EGRF_WRITE_RECORDS";

    public static string Root => Path.Combine(EgrfTestFiles.RepositoryRoot(), "test", "egrf", "records");

    public static string IndexPath => Path.Combine(Root, "index.json");

    /// <summary>The public key (PEM SubjectPublicKeyInfo) that signed the signed golden records' attestations and record signatures.</summary>
    public static string TrustKeyPath => Path.Combine(Root, "trust", "signer.pem");

    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static bool _ensured;

    /// <summary>Regenerates the committed records once per run when <see cref="WriteVariable"/> is "1", or adds the missing ones when it is "missing".</summary>
    public static async Task EnsureAsync()
    {
        await Gate.WaitAsync();
        try
        {
            string? mode = Environment.GetEnvironmentVariable(WriteVariable);
            if (!_ensured && mode is "1" or "missing")
            {
                await GenerateAsync(Root, onlyMissing: mode == "missing");
            }

            _ensured = true;
        }
        finally
        {
            Gate.Release();
        }
    }

    /// <summary>
    /// One record of index.json. <see cref="Basis"/>, when set, says where its expected codes come from
    /// when no user decision or design rule fixes them: an implementation-chosen reader rule awaiting the
    /// user's sign-off (S10b-E review round 3), so that the two readers agreeing on it is not read as
    /// independent evidence for the rule.
    /// </summary>
    public sealed record Entry(string Path, string Kind, string Description, IReadOnlyList<string> Expect, string? Basis = null);

    public static List<(Entry Entry, IReadOnlyList<string> Codes, Dictionary<string, string>? PhaseRoots, bool Complete)> ReadIndex()
    {
        var index = JsonNode.Parse(File.ReadAllText(IndexPath))!.AsObject();
        var list = new List<(Entry, IReadOnlyList<string>, Dictionary<string, string>?, bool)>();
        foreach (var node in index["records"]!.AsArray())
        {
            var o = node!.AsObject();
            var entry = new Entry((string)o["path"]!, (string)o["kind"]!, (string)o["description"]!, o["expect"]!.AsArray().Select(x => (string)x!).ToList(), (string?)o["basis"]);
            var roots = o["phaseRoots"] is JsonObject r ? r.ToDictionary(x => x.Key, x => (string)x.Value!) : null;
            list.Add((entry, o["codes"]!.AsArray().Select(x => (string)x!).ToList(), roots, (bool)o["complete"]!));
        }

        return list;
    }

    public static string FullPath(string relative) => Path.Combine(Root, Path.Combine(relative.Split('/')));

    /// <summary>
    /// This library's verdict on a record: the R-codes of a full verification (or the one an open
    /// refuses the record with), the phase roots it computed, and whether it is complete. Only R-codes
    /// are compared with the Python reader, which does not run the numbered verifications.
    /// </summary>
    /// <summary>
    /// This library's verdict on a record: its R-codes, phase roots (none when the read stopped at
    /// open) and completeness; whether a finding of a verification names a ballot (which leaves
    /// R.summary not evaluable when the ballot is cast); whether a setup verification (1-4) failed,
    /// which stops the cryptography and with it the device pass, where attestation contents and the
    /// tally header are compared (design §6.1 step B); and the findings' messages, for diagnostics.
    /// </summary>
    public sealed record Verdict(IReadOnlyList<string> Codes, Dictionary<string, string>? PhaseRoots, bool Complete, bool HasBallotFinding, IReadOnlyList<string> Messages, bool SetupFailed = false)
    {
        public void Deconstruct(out IReadOnlyList<string> codes, out Dictionary<string, string>? phaseRoots, out bool complete) =>
            (codes, phaseRoots, complete) = (Codes, PhaseRoots, Complete);
    }

    public static async Task<Verdict> VerdictAsync(string path)
    {
        try
        {
            await using var reader = await ElectionRecord.OpenAsync(path);
            var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions());
            var codes = report.Findings.Select(x => x.SubSection).Where(x => x.StartsWith("R.", StringComparison.Ordinal)).Distinct().Order(StringComparer.Ordinal).ToList();
            var roots = report.PhaseRoots.ToDictionary(x => RecordLayout.PhaseName(x.Key), x => x.Value.ToString());
            bool ballotFinding = report.Findings.Any(x => x.Locator is not null && !x.SubSection.StartsWith("R.", StringComparison.Ordinal));
            bool setupFailed = report.Findings.Any(x => x.Verification is >= 1 and <= 4 && !x.SubSection.StartsWith("R.", StringComparison.Ordinal));
            return new Verdict(codes, roots, report.Complete, ballotFinding, report.Findings.Select(x => $"{x.SubSection} {x.Message}").ToList(), setupFailed);
        }
        catch (VerificationFailedException failure) when (failure.SubSection.StartsWith("R.", StringComparison.Ordinal))
        {
            return new Verdict([failure.SubSection], null, false, false, [$"{failure.SubSection} {failure.Message}"]);
        }
    }

    // ---- generation ----------------------------------------------------------------------------

    public static async Task GenerateAsync(string root, bool onlyMissing = false)
    {
        if (Directory.Exists(root) && !onlyMissing)
        {
            foreach (var path in Directory.EnumerateFileSystemEntries(root).Where(x => Path.GetFileName(x) != ".gitattributes"))
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, recursive: true);
                }
                else
                {
                    File.Delete(path);
                }
            }
        }

        Directory.CreateDirectory(root);
        var entries = new List<Entry>();
        using var signer = EcdsaP256Sha256Signer.Generate();
        if (!onlyMissing)
        {
            Directory.CreateDirectory(Path.Combine(root, "trust"));
            File.WriteAllText(Path.Combine(root, "trust", "signer.pem"), PemEncoding.WriteString("PUBLIC KEY", signer.SubjectPublicKeyInfo) + "\n");
        }

        // Golden records: each written as a protobuf directory, then converted (the converter
        // preserves every root, design §5.1) to the other three representations. With onlyMissing the
        // committed ones are kept (new ones would change every record made from them).
        string unchained = Path.Combine(root, "golden", "regular-unchained");
        if (!onlyMissing)
        {
            await WriteUnchainedAsync(Path.Combine(unchained, "protobuf"), signer);
        }

        await AllRepresentationsAsync(unchained, "golden/regular-unchained", "Regular election, no chaining: two cast ballots and a spoiled one on one device, attested and signed.", entries, onlyMissing);

        string chained = Path.Combine(root, "golden", "regular-chained");
        if (!onlyMissing)
        {
            await WriteAsync(RegularElection.Value, Path.Combine(chained, "protobuf"), RecordEncoding.Protobuf, signer: signer);
        }

        await AllRepresentationsAsync(chained, "golden/regular-chained", "Regular election, simple chaining, two devices: cast (one of weight 2), spoiled and challenged ballots, contest data, its requests and decryptions, the challenged ballot's decryption; attested and signed.", entries, onlyMissing);

        string pre = Path.Combine(root, "golden", "pre-encrypted");
        if (!onlyMissing)
        {
            await WriteAsync(PreEncryptedRecord.Value, Path.Combine(pre, "protobuf"), RecordEncoding.Protobuf);
        }

        await AllRepresentationsAsync(pre, "golden/pre-encrypted", "Pre-encrypted election, simple chaining: two cast ballots, a returned uncast ballot in full, a never-returned and a returned-with-xi_B uncast ballot (both compact), and their releases.", entries, onlyMissing);

        // The edge cases start from the smallest golden record, except where they need what only the
        // chained one holds (contest-data requests, two items in a join section).
        string pb = Path.Combine(unchained, "protobuf");
        string json = Path.Combine(unchained, "json");
        string zip = Path.Combine(unchained, "protobuf.zip");
        string chainedPb = Path.Combine(chained, "protobuf");
        static string OnlyDevice(string d) => Directory.GetDirectories(Path.Combine(d, "devices")).Single();

        // Positive edge cases.
        async Task PositiveAsync(string relative, string from, string description, Func<string, Task> mutate) =>
            entries.Add(await MutateAsync(relative, from, description, [], mutate));
        async Task PositiveFileAsync(string relative, string from, string description, Func<byte[], byte[]> mutate) =>
            entries.Add(await MutateFileAsync(relative, from, description, [], mutate));

        await PositiveAsync("positive/jsonl-no-final-line-feed", json, "A JSON record whose decrypted tally file has no final line feed (design §5.5: optional).", d =>
        {
            string f = Path.Combine(d, "final", "decrypted_tally.jsonl");
            File.WriteAllBytes(f, File.ReadAllBytes(f)[..^1]);
            return Task.CompletedTask;
        });
        await PositiveAsync("positive/jsonl-crlf", json, "A JSON record with CRLF line endings in every file (design §5.5: read as LF).", d =>
        {
            foreach (var f in Directory.EnumerateFiles(d, "*.jsonl", SearchOption.AllDirectories))
            {
                File.WriteAllBytes(f, Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(File.ReadAllBytes(f)).Replace("\n", "\r\n", StringComparison.Ordinal)));
            }

            return Task.CompletedTask;
        });
        await PositiveFileAsync("positive/zip-data-descriptor-flag.zip", zip, "A zip whose first local header sets bit 3 with CRC-32 and both sizes zero (design §5.4: not compared).", bytes => SetLocalHeader(bytes, 0, flags: 0x0008, zeroCrc: true, zeroSizes: true));
        // From the unsigned pre-encrypted record: a changed ballot changes its section root, which an
        // attestation or record signature would no longer match.
        await PositiveAsync("positive/newer-minor", Path.Combine(pre, "protobuf"), "A record of format minor 1 whose first ballot (a cast pre-encrypted ballot) carries an unknown field 12 after its known fields (W6): passed, not complete.", async d =>
        {
            RecordTamper.Edit(d, RecordSectionType.Header, items => items[0].RecordHeader.FormatMinor = 1);
            var device = Directory.GetDirectories(Path.Combine(d, "devices")).Single();
            string segment = Path.Combine(device, "00000000.binpb");
            var frames = Frames(File.ReadAllBytes(segment));
            // Frame 0 is the segment header, frame 1 the device header, frame 2 the first ballot:
            // RecordItem{tag, length, message}, the unknown VARINT field 12 = 5 appended to the message.
            byte[] payload = Payload(frames[2]);
            int at = 1;
            while ((payload[at++] & 0x80) != 0)
            {
            }

            byte[] inner = [.. payload[at..], 0x60, 0x05];
            frames[2] = Frame([payload[0], .. Varint(inner.Length), .. inner]);
            File.WriteAllBytes(segment, Join(frames));
            await RecordTamper.ReTocAsync(d);
        });

        // Negative records: one mutation each, named by the code it targets.
        async Task Neg(string name, string description, string code, string from, Func<string, Task> mutate, string? basis = null) =>
            entries.Add(await MutateAsync($"negative/{name}", from, description, [code], mutate, basis));

        // Reader rules taken from this library's reader where no decision or design rule fixed the code
        // (S10b-E review rounds 2 and 3), listed for the user's sign-off; the Python reader follows them.
        const string ClaimedTocAtOpen = "implementation-chosen, awaiting sign-off: a claimed TOC that is not a well-formed list of toc_entry items stops the read at open (S10b-E review round 2)";
        const string HeaderAtOpen = "implementation-chosen, awaiting sign-off: a header section that cannot be read stops the read at open (S10b-E review round 3)";
        const string HeaderLineD6 = "implementation-chosen, awaiting sign-off: D6 governs a .jsonl segment header line, so any failure of it is R.container (S10b-E review round 3)";
        const string JsonOneForm = "implementation-chosen, awaiting sign-off: in JSON, bytes are standard padded base64 and integers plain decimal; other forms are R.encoding (design §5.5, S10b-E review round 3)";
        const string TocNameEncoding = "implementation-chosen, awaiting sign-off: an undeclared SectionType name in a JSON claimed TOC is R.encoding, NQ-7's R.version applying to the numeric form (S10b-E review round 3)";
        async Task NegZip(string name, string description, string code, Func<byte[], byte[]> mutate) =>
            entries.Add(await MutateFileAsync($"negative/{name}", zip, description, [code], mutate));

        await Neg("container-unlisted-file", "A file outside the layout (§5.3.1).", RecordCodes.Container, pb, d => Write(d, "extra.txt", "x"u8.ToArray()));
        await Neg("container-uppercase-hex", "A device directory named with uppercase hex (§5.3.1: lowercase).", RecordCodes.Container, pb, d =>
        {
            string device = Directory.GetDirectories(Path.Combine(d, "devices")).Order(StringComparer.Ordinal).First();
            string name = Path.GetFileName(device);
            string upper = "regular-" + name["regular-".Length..].ToUpperInvariant();
            Directory.Move(device, device + ".tmp");
            Directory.Move(device + ".tmp", Path.Combine(Path.GetDirectoryName(device)!, upper));
            return Task.CompletedTask;
        });
        await Neg("container-segment-gap", "A segmented section whose only segment is numbered 00000001 (§5.3.1: from 00000000, no gaps).", RecordCodes.Container, pb, d =>
        {
            string dir = Path.Combine(d, "final", "challenged_ballot_decryptions");
            File.Move(Path.Combine(dir, "00000000.binpb"), Path.Combine(dir, "00000001.binpb"));
            return Task.CompletedTask;
        });
        await Neg("container-header-disagrees-with-path", "A segment header naming another section type than its path (D6).", RecordCodes.Container, pb, d =>
        {
            string f = Path.Combine(d, "final", "contest_data_decryptions", "00000000.binpb");
            var frames = Frames(File.ReadAllBytes(f));
            frames[0] = Frame(new Pb.SegmentHeader { Magic = "EGRF", FormatMajor = 2, SectionType = Pb.SectionType.UncastNonceReleases }.ToByteArray());
            File.WriteAllBytes(f, Join(frames));
            return Task.CompletedTask;
        });
        await Neg("container-torn-tail", "A device segment cut short inside its last frame (§5.2: a verifier never repairs).", RecordCodes.Container, pb, d =>
        {
            string f = Path.Combine(OnlyDevice(d), "00000000.binpb");
            File.WriteAllBytes(f, File.ReadAllBytes(f)[..^2]);
            return Task.CompletedTask;
        });
        await Neg("container-zero-length-frame", "A zero-length frame after a device segment's last item (§5.2).", RecordCodes.Container, pb, d =>
        {
            string f = Path.Combine(OnlyDevice(d), "00000000.binpb");
            File.WriteAllBytes(f, [.. File.ReadAllBytes(f), 0x00]);
            return Task.CompletedTask;
        });
        await Neg("container-frame-over-ceiling", "A frame length of 64 MiB + 1 (§5.2: refused before allocating).", RecordCodes.Container, pb, d =>
        {
            string f = Path.Combine(d, "final", "challenged_ballot_decryptions", "00000000.binpb");
            File.WriteAllBytes(f, [.. File.ReadAllBytes(f), .. Varint((64 << 20) + 1), 0x0A, 0x00]);
            return Task.CompletedTask;
        });
        await Neg("container-manifest-copy-differs", "A setup/manifest.json that is not ManifestFile.content (§4.6).", RecordCodes.Container, pb, d =>
        {
            string f = Path.Combine(d, "setup", "manifest.json");
            File.WriteAllBytes(f, [.. File.ReadAllBytes(f), 0x20]);
            return Task.CompletedTask;
        });
        await Neg("container-mixed-encodings", "A .jsonl section file in a protobuf record (§5.3.1: one encoding per record).", RecordCodes.Container, pb, d =>
            Write(d, "final/uncast_nonce_releases/00000000.jsonl", "{\"magic\":\"EGRF\",\"formatMajor\":2,\"sectionType\":\"SECTION_TYPE_UNCAST_NONCE_RELEASES\"}\n"u8.ToArray()));
        await NegZip("container-zip-duplicate-entry.zip", "A zip holding toc.binpb twice (§5.4).", RecordCodes.Container, bytes => Rezip(bytes, (archive, entries) =>
        {
            var toc = entries.Single(x => x.Name == "toc.binpb");
            AddEntry(archive, toc.Name, toc.Data);
        }));
        await NegZip("container-zip-colon-in-derived-name.zip", "A zip entry derived/a:b (§5.3.1: no ':' in any name, derived/ included).", RecordCodes.Container, bytes => Rezip(bytes, (archive, _) => AddEntry(archive, "derived/a:b", "x"u8.ToArray())));
        await NegZip("container-zip-local-header-disagrees.zip", "A local header whose CRC-32 differs from the central directory's (§5.4).", RecordCodes.Container, bytes => SetLocalHeader(bytes, 0, flags: 0, zeroCrc: false, zeroSizes: false, flipCrc: true));
        await NegZip("container-zip-data-descriptor-partly-zero.zip", "A local header with bit 3 set and only its CRC-32 zero (§5.4: all three or none).", RecordCodes.Container, bytes => SetLocalHeader(bytes, 0, flags: 0x0008, zeroCrc: true, zeroSizes: false));

        await Neg("encoding-noncanonical-item", "A contest-data request with contest_index written twice (W2), the claimed TOC rewritten over it.", RecordCodes.Encoding, chainedPb, async d =>
        {
            string f = Path.Combine(d, "aggregated", "contest_data_requests.binpb");
            var frames = Frames(File.ReadAllBytes(f));
            var request = Pb.RecordItem.Parser.ParseFrom(Payload(frames[1])).ContestDataRequest;
            byte[] inner = [.. request.ToByteArray(), 0x18, 0x00];
            frames[1] = Frame([0xB2, 0x01, .. Varint(inner.Length), .. inner]);
            File.WriteAllBytes(f, Join(frames));
            await RecordTamper.ReTocAsync(d);
        });
        await Neg("encoding-jsonl-last-line-cut", "A JSON record whose decrypted tally's last line is cut short (design §5.5).", RecordCodes.Encoding, json, d =>
        {
            string f = Path.Combine(d, "final", "decrypted_tally.jsonl");
            byte[] bytes = File.ReadAllBytes(f);
            File.WriteAllBytes(f, bytes[..^40]);
            return Task.CompletedTask;
        });
        await Neg("encoding-jsonl-duplicate-member", "A JSON line of the decrypted tally naming index twice (design §5.5).", RecordCodes.Encoding, json, d =>
        {
            string f = Path.Combine(d, "final", "decrypted_tally.jsonl");
            string text = File.ReadAllText(f);
            File.WriteAllText(f, ReplaceFirst(text, "{\"index\":", "{\"index\":1,\"index\":"));
            return Task.CompletedTask;
        });

        await Neg("version-major", "The header section's segment header names format major 3 (§7).", RecordCodes.Version, pb, d =>
        {
            string f = Path.Combine(d, "setup", "header.binpb");
            var frames = Frames(File.ReadAllBytes(f));
            frames[0] = Frame(new Pb.SegmentHeader { Magic = "EGRF", FormatMajor = 3, SectionType = Pb.SectionType.Header }.ToByteArray());
            File.WriteAllBytes(f, Join(frames));
            return Task.CompletedTask;
        });
        await Neg("version-toc-unknown-section-type", "A claimed TOC entry naming section type 0x8001, once the vendor range (NQ-7; vendor sections removed).", RecordCodes.Version, pb, d =>
        {
            RewriteToc(d, x => x.Add(new Pb.TocEntry { SectionType = (Pb.SectionType)0x8001, ItemCount = 1, Root = ByteString.CopyFrom(new byte[32]) }));
            return Task.CompletedTask;
        });

        await Neg("root-claimed-root-differs", "A claimed TOC entry with another section root (§4.9).", RecordCodes.Root, pb, d =>
        {
            RewriteToc(d, x => x[3].Root = ByteString.CopyFrom(new byte[32]));
            return Task.CompletedTask;
        });
        await Neg("root-critical-bit", "A claimed TOC entry whose critical bit is false (§4.5: fixed per type).", RecordCodes.Root, pb, d =>
        {
            RewriteToc(d, x => x[5].Critical = false);
            return Task.CompletedTask;
        });
        // A claimed TOC that is not a well-formed list of toc_entry items stops the read at open, as one
        // naming a section kind of another major does (design §8.3 "As built (S10b-E)", review round 2).
        await Neg("encoding-toc-noncanonical-item", "A claimed TOC whose last toc_entry has its inner length written as a two-byte varint (W4): refused at open.", RecordCodes.Encoding, pb, d =>
        {
            string f = Path.Combine(d, "toc.binpb");
            var frames = Frames(File.ReadAllBytes(f));
            byte[] payload = Payload(frames[^1]);
            Assert.True(payload[0] == 0x92 && payload[1] == 0x03 && payload[2] < 0x80, "a toc_entry item: tag 50, a one-byte length");
            frames[^1] = Frame([0x92, 0x03, (byte)(payload[2] | 0x80), 0x00, .. payload[3..]]);
            File.WriteAllBytes(f, Join(frames));
            return Task.CompletedTask;
        }, ClaimedTocAtOpen);
        await Neg("encoding-jsonl-toc-undeclared-section-type", "A JSON claimed TOC with a last line naming SECTION_TYPE_TALLY_DEFINITIONS, no value of SectionType (closed): refused at open.", RecordCodes.Encoding, json, d =>
        {
            File.AppendAllText(Path.Combine(d, "toc.jsonl"), "{\"tocEntry\":{\"sectionType\":\"SECTION_TYPE_TALLY_DEFINITIONS\",\"critical\":true,\"itemCount\":\"1\",\"root\":\"" + Convert.ToBase64String(new byte[32]) + "\"}}\n");
            return Task.CompletedTask;
        }, TocNameEncoding);
        await Neg("root-toc-item-not-a-toc-entry", "A claimed TOC whose last item is the record_header item: refused at open.", RecordCodes.Root, pb, d =>
        {
            string f = Path.Combine(d, "toc.binpb");
            byte[] header = Frames(File.ReadAllBytes(Path.Combine(d, "setup", "header.binpb")))[1];
            File.WriteAllBytes(f, [.. File.ReadAllBytes(f), .. header]);
            return Task.CompletedTask;
        }, ClaimedTocAtOpen);
        await Neg("root-toc-entries-out-of-order", "A claimed TOC with its first two entries swapped (§4.9: canonical (type, key) order): refused at open.", RecordCodes.Root, pb, d =>
        {
            RewriteToc(d, x => (x[0], x[1]) = (x[1], x[0]));
            return Task.CompletedTask;
        }, ClaimedTocAtOpen);
        await Neg("container-toc-torn-tail", "A claimed TOC cut short inside its last frame (§5.2): refused at open.", RecordCodes.Container, pb, d =>
        {
            string f = Path.Combine(d, "toc.binpb");
            File.WriteAllBytes(f, File.ReadAllBytes(f)[..^2]);
            return Task.CompletedTask;
        }, ClaimedTocAtOpen);

        // S10b-E review round 3: what the round-2 records left out.
        await Neg("version-jsonl-toc-numeric-section-type", "A JSON claimed TOC with a last line naming section type 32769 as a number, a section kind v2 does not define: R.version at open (NQ-7).", RecordCodes.Version, json, d =>
        {
            File.AppendAllText(Path.Combine(d, "toc.jsonl"), "{\"tocEntry\":{\"sectionType\":32769,\"critical\":true,\"itemCount\":\"1\",\"root\":\"" + Convert.ToBase64String(new byte[32]) + "\"}}\n");
            return Task.CompletedTask;
        });
        await Neg("encoding-toc-noncanonical-item-then-torn-tail", "A claimed TOC whose last toc_entry is not canonical (W4) and is followed by a torn frame: R.encoding at open, judged before the torn frame is read (§5.2: frame by frame).", RecordCodes.Encoding, pb, d =>
        {
            string f = Path.Combine(d, "toc.binpb");
            var frames = Frames(File.ReadAllBytes(f));
            byte[] payload = Payload(frames[^1]);
            frames[^1] = Frame([0x92, 0x03, (byte)(payload[2] | 0x80), 0x00, .. payload[3..]]);
            File.WriteAllBytes(f, [.. Join(frames), 0x05, 0x0A]);
            return Task.CompletedTask;
        }, ClaimedTocAtOpen);
        await Neg("encoding-noncanonical-item-then-torn-tail", "A decrypted tally whose first contest is not canonical (W4) and is followed by a torn frame: R.encoding for the item, then R.container for the section (§5.2: frame by frame).", RecordCodes.Encoding, pb, d =>
        {
            string f = Path.Combine(d, "final", "decrypted_tally.binpb");
            var frames = Frames(File.ReadAllBytes(f));
            frames[1] = Frame(PadInnerLength(Payload(frames[1])));
            File.WriteAllBytes(f, [.. Join(frames), 0x05, 0x0A]);
            return Task.CompletedTask;
        });
        await Neg("container-header-section-torn", "The header section cut short inside its record_header frame: R.container at open (the header fixes the minor every item is judged at).", RecordCodes.Container, pb, d =>
        {
            string f = Path.Combine(d, "setup", "header.binpb");
            File.WriteAllBytes(f, File.ReadAllBytes(f)[..^2]);
            return Task.CompletedTask;
        }, HeaderAtOpen);
        await Neg("encoding-header-item-noncanonical", "A record_header item with its inner length written as a two-byte varint (W4): R.encoding at open.", RecordCodes.Encoding, pb, d =>
        {
            string f = Path.Combine(d, "setup", "header.binpb");
            var frames = Frames(File.ReadAllBytes(f));
            frames[1] = Frame(PadInnerLength(Payload(frames[1])));
            File.WriteAllBytes(f, Join(frames));
            return Task.CompletedTask;
        }, HeaderAtOpen);
        await Neg("structure-header-two-items", "A header section holding its record_header item twice (§4.5): R.structure at open.", RecordCodes.Structure, pb, d =>
        {
            string f = Path.Combine(d, "setup", "header.binpb");
            var frames = Frames(File.ReadAllBytes(f));
            File.WriteAllBytes(f, Join([.. frames, frames[1]]));
            return Task.CompletedTask;
        }, HeaderAtOpen);
        await Neg("container-singleton-setup-section-torn", "The parameters section cut short inside its only item: R.container for the section, and no R.structure (the section holds an item the reader could not read, not none; §6.9).", RecordCodes.Container, pb, d =>
        {
            string f = Path.Combine(d, "setup", "parameters.binpb");
            File.WriteAllBytes(f, File.ReadAllBytes(f)[..^2]);
            return Task.CompletedTask;
        });
        await Neg("container-jsonl-segment-header-unknown-member", "A JSON decrypted tally whose segment header line names an unknown member: R.container (D6 governs the header line).", RecordCodes.Container, json, d =>
        {
            string f = Path.Combine(d, "final", "decrypted_tally.jsonl");
            File.WriteAllText(f, ReplaceFirst(File.ReadAllText(f), "{\"magic\":", "{\"bogus\":1,\"magic\":"));
            return Task.CompletedTask;
        }, HeaderLineD6);
        await Neg("attestation-section-seal-with-noncanonical-ballot", "A JSON device section whose first ballot's status is the number 9 (D2): R.encoding at the item; the section is read whole, so its section seal is compared and differs (§4.9), while its chain close is not evaluable.", RecordCodes.Attestation, json, d =>
        {
            string f = Directory.EnumerateFiles(Path.Combine(d, "devices"), "*.jsonl", SearchOption.AllDirectories).Single();
            File.WriteAllText(f, ReplaceFirst(File.ReadAllText(f), "\"BALLOT_STATUS_CAST\"", "9"));
            return Task.CompletedTask;
        });
        await Neg("encoding-jsonl-urlsafe-base64", "A JSON line whose first base64 value with a '+' or '/' is written in the URL-safe alphabet (design §5.5: one form).", RecordCodes.Encoding, json, d =>
        {
            RewriteFirstBase64(d, value => value.Contains('+') || value.Contains('/'), value => value.Replace('+', '-').Replace('/', '_'));
            return Task.CompletedTask;
        }, JsonOneForm);
        await Neg("encoding-jsonl-unpadded-base64", "A JSON line whose first padded base64 value has its padding removed (design §5.5: one form).", RecordCodes.Encoding, json, d =>
        {
            RewriteFirstBase64(d, value => value.EndsWith('='), value => value.TrimEnd('='));
            return Task.CompletedTask;
        }, JsonOneForm);
        await Neg("encoding-jsonl-integer-leading-zero", "A JSON device close whose ballot count is written with a leading zero (design §5.5: plain decimal).", RecordCodes.Encoding, json, d =>
        {
            string f = Directory.EnumerateFiles(Path.Combine(d, "devices"), "*.jsonl", SearchOption.AllDirectories).Single();
            File.WriteAllText(f, ReplaceFirst(File.ReadAllText(f), "\"ballotCount\":\"", "\"ballotCount\":\"0"));
            return Task.CompletedTask;
        }, JsonOneForm);
        await Neg("structure-missing-section", "A final record without its decrypted tally (§4.5 presence), the TOC entry removed too.", RecordCodes.Structure, pb, d =>
        {
            File.Delete(Path.Combine(d, "final", "decrypted_tally.binpb"));
            RewriteToc(d, x => x.RemoveAll(e => e.SectionType == Pb.SectionType.DecryptedTally));
            return Task.CompletedTask;
        });
        await Neg("order-join-section", "Two contest-data decryptions out of locator order (§4.5), the TOC rewritten.", RecordCodes.Order, chainedPb, async d =>
        {
            RecordTamper.Edit(d, RecordSectionType.ContestDataDecryptions, items => (items[0], items[1]) = (items[1], items[0]));
            await RecordTamper.ReTocAsync(d);
        });
        await Neg("summary-tally-header", "An encrypted tally header counting one cast ballot too many, the TOC rewritten.", RecordCodes.Summary, pb, async d =>
        {
            RecordTamper.Edit(d, RecordSectionType.EncryptedTally, items => items[0].EncryptedTallyHeader.CastBallotCount += 1);
            await RecordTamper.ReTocAsync(d);
        });
        await Neg("attestation-chain-close-count", "A chain-close attestation whose ballot count is one too many (§4.9), the TOC rewritten.", RecordCodes.Attestation, pb, async d =>
        {
            RecordTamper.Edit(d, RecordSectionType.DeviceAttestations, items =>
            {
                var item = items.First(x => Pb.RecordItem.Parser.ParseFrom(x.DeviceAttestation.Statement).ItemCase == Pb.RecordItem.ItemOneofCase.ChainCloseStatement);
                var statement = Pb.RecordItem.Parser.ParseFrom(item.DeviceAttestation.Statement);
                statement.ChainCloseStatement.BallotCount += 1;
                item.DeviceAttestation.Statement = ByteString.CopyFrom(statement.ToByteArray());
            });
            await RecordTamper.ReTocAsync(d);
        });
        await Neg("signature-wrong-root", "A record signature whose statement names another final root (§4.9), the file named for the new statement.", RecordCodes.Signature, pb, d =>
        {
            string file = Directory.GetFiles(Path.Combine(d, "signatures")).Single();
            var frames = Frames(File.ReadAllBytes(file));
            var item = Pb.RecordItem.Parser.ParseFrom(Payload(frames[1]));
            var statement = Pb.RecordItem.Parser.ParseFrom(item.RecordSignature.Statement);
            statement.RecordStatement.Root = ByteString.CopyFrom(new byte[32]);
            byte[] bytes = statement.ToByteArray();
            item.RecordSignature.Statement = ByteString.CopyFrom(bytes);
            File.Delete(file);
            File.WriteAllBytes(Path.Combine(d, "signatures", $"final-{Convert.ToHexStringLower(SHA256.HashData(bytes))}.binpb"), Join([frames[0], Frame(item.ToByteArray())]));
            return Task.CompletedTask;
        });

        await WriteIndexAsync(root, entries);
    }

    private static async Task AllRepresentationsAsync(string directory, string relative, string description, List<Entry> entries, bool onlyMissing)
    {
        if (!onlyMissing)
        {
            await ConvertAllAsync(directory);
        }

        foreach (string representation in new[] { "protobuf", "json", "protobuf.zip", "json.zip" })
        {
            entries.Add(new Entry($"{relative}/{representation}", "golden", $"{description} ({representation})", []));
        }
    }

    private static async Task ConvertAllAsync(string directory)
    {
        await using (var reader = await ElectionRecord.OpenAsync(Path.Combine(directory, "protobuf")))
        {
            await ElectionRecord.ConvertAsync(reader, Path.Combine(directory, "json"), RecordEncoding.Json, RecordCarrier.Directory);
            await ElectionRecord.ConvertAsync(reader, Path.Combine(directory, "protobuf.zip"), RecordEncoding.Protobuf, RecordCarrier.Zip);
            await ElectionRecord.ConvertAsync(reader, Path.Combine(directory, "json.zip"), RecordEncoding.Json, RecordCarrier.Zip);
        }
    }

    private static async Task<Entry> MutateAsync(string relative, string from, string description, IReadOnlyList<string> expect, Func<string, Task> mutate, string? basis = null)
    {
        string destination = FullPath(relative);
        if (!Directory.Exists(destination))
        {
            CopyDirectory(from, destination);
            await mutate(destination);
        }

        return new Entry(relative, expect.Count == 0 ? "positive" : "negative", description, expect, basis);
    }

    private static Task<Entry> MutateFileAsync(string relative, string from, string description, IReadOnlyList<string> expect, Func<byte[], byte[]> mutate)
    {
        string destination = FullPath(relative);
        if (!File.Exists(destination))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.WriteAllBytes(destination, mutate(File.ReadAllBytes(from)));
        }

        return Task.FromResult(new Entry(relative, expect.Count == 0 ? "positive" : "negative", description, expect));
    }

    private static async Task WriteIndexAsync(string root, List<Entry> entries)
    {
        var records = new JsonArray();
        foreach (var entry in entries)
        {
            var (codes, roots, complete) = await VerdictAsync(FullPath(entry.Path));
            if (entry.Kind == "negative")
            {
                Assert.True(entry.Expect.All(codes.Contains), $"{entry.Path}: expected {string.Join(",", entry.Expect)}, the reader reports {string.Join(",", codes)}.");
            }
            else
            {
                Assert.True(codes.Count == 0, $"{entry.Path}: {string.Join(",", codes)}");
            }

            var node = new JsonObject
            {
                ["path"] = entry.Path,
                ["kind"] = entry.Kind,
                ["description"] = entry.Description,
                ["expect"] = new JsonArray(entry.Expect.Select(x => (JsonNode)x!).ToArray()),
                ["codes"] = new JsonArray(codes.Select(x => (JsonNode)x!).ToArray()),
                ["complete"] = complete,
            };
            if (entry.Basis is not null)
            {
                node["basis"] = entry.Basis;
            }

            if (roots is not null)
            {
                node["phaseRoots"] = new JsonObject(roots.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => KeyValuePair.Create(x.Key, (JsonNode?)x.Value)));
            }

            records.Add(node);
        }

        var index = new JsonObject
        {
            ["description"] = "EGRF v2 golden and negative records (design §5.7), generated by ElectionGuard.Core.UnitTests EgrfGoldenRecords. 'codes' are the R-codes this library reports for the record (a full VerifyAllAsync, or the code its open refuses the record with), 'expect' the code the mutation targets, 'phaseRoots' the roots it computed, 'basis' (when present) that the expected codes rest on an implementation-chosen reader rule awaiting the user's sign-off. test/egrf/egrf_ref.py --check must reproduce codes, roots and completeness. Nonces are random, so regenerating (EGRF_WRITE_RECORDS=1) rewrites every file. Signed records are signed by trust/signer.pem.",
            ["records"] = records,
        };
        await File.WriteAllTextAsync(Path.Combine(root, "index.json"), index.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }).Replace("\r\n", "\n", StringComparison.Ordinal) + "\n");
    }

    /// <summary>A regular election under no chaining: two cast ballots and a spoiled one on one device, attested and signed.</summary>
    private static async Task WriteUnchainedAsync(string directory, IStatementSigner signer)
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: ChainingMode.None);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var chain = new DeviceChain(record, "unchained-device");
        var ballots = new List<EncryptedBallot>();
        foreach (var (id, choice, status) in new[] { ("u-1", 1, BallotStatus.Cast), ("u-2", 1, BallotStatus.Spoiled), ("u-3", 0, BallotStatus.Cast) })
        {
            var ballot = ElectionFixtureBuilder.CreateEncryptedBallot(record, "unchained-device", chain.DeviceInformationHash,
                ElectionFixtureBuilder.CreateBallot(manifest, id, new Dictionary<string, int> { ["choice-1"] = choice }), chain.PreviousConfirmationCode, status);
            chain.Append(ballot);
            ballots.Add(ballot);
        }

        var tally = ElectionFixtureBuilder.CreateEncryptedTally(manifest, ballots.ToArray());
        var decrypted = new TallyAdmin().Decrypt(ElectionFixtureBuilder.TallyGuardians(guardianSet), tally, record);

        await using var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf);
        await writer.WriteSetupAsync(record);
        await using (var device = await writer.OpenDeviceAsync("unchained-device", DeviceChainBallotKind.Encrypted))
        {
            foreach (var ballot in ballots)
            {
                await device.AppendAsync(ballot);
            }

            var seal = await device.CloseAsync(ClosedAt);
            await writer.AddAttestationAsync(await signer.SignAsync(seal!.ChainCloseStatement(record.ExtendedBaseHash)));
            await writer.AddAttestationAsync(await signer.SignAsync(seal.SectionSealStatement(record.ExtendedBaseHash)));
        }

        await writer.SealVotingAsync();
        await writer.SealAggregatedAsync(tally, []);
        var toc = await writer.CompleteAsync(decrypted);
        await writer.AddRecordSignatureAsync(await signer.SignAsync(RecordStatements.Record(RecordPhase.Final, toc.Root, record.ExtendedBaseHash, ClosedAt.AddHours(1), "administrator")));
    }

    // ---- file helpers --------------------------------------------------------------------------

    private static Task Write(string directory, string relative, byte[] bytes)
    {
        string path = Path.Combine(directory, Path.Combine(relative.Split('/')));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return Task.CompletedTask;
    }

    private static void CopyDirectory(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (string file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(to, Path.GetRelativePath(from, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }
    }

    private static string ReplaceFirst(string text, string what, string with)
    {
        int at = text.IndexOf(what, StringComparison.Ordinal);
        Assert.True(at >= 0, $"'{what}' not found");
        return string.Concat(text.AsSpan(0, at), with, text.AsSpan(at + what.Length));
    }

    /// <summary>A RecordItem payload (tag, length, message) with its length varint given one more byte than it needs (W4).</summary>
    private static byte[] PadInnerLength(byte[] payload)
    {
        int at = 0;
        while ((payload[at++] & 0x80) != 0)
        {
        }

        while ((payload[at++] & 0x80) != 0)
        {
        }

        return [.. payload[..(at - 1)], (byte)(payload[at - 1] | 0x80), 0x00, .. payload[at..]];
    }

    /// <summary>Rewrites the first base64 JSON value (of 16 characters or more) that <paramref name="select"/> picks, in the record's .jsonl section files in ordinal path order.</summary>
    private static void RewriteFirstBase64(string directory, Func<string, bool> select, Func<string, string> rewrite)
    {
        var value = new System.Text.RegularExpressions.Regex(":\"([A-Za-z0-9+/]{16,}={0,2})\"");
        foreach (string file in Directory.EnumerateFiles(directory, "*.jsonl", SearchOption.AllDirectories).Where(x => Path.GetFileName(x) != "toc.jsonl").Order(StringComparer.Ordinal))
        {
            string text = File.ReadAllText(file);
            if (value.Matches(text).FirstOrDefault(x => select(x.Groups[1].Value)) is { } match)
            {
                var group = match.Groups[1];
                File.WriteAllText(file, string.Concat(text.AsSpan(0, group.Index), rewrite(group.Value), text.AsSpan(group.Index + group.Length)));
                return;
            }
        }

        Assert.Fail("no base64 value to rewrite");
    }

    public static byte[] Varint(int value)
    {
        var bytes = new List<byte>();
        uint v = (uint)value;
        do
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            bytes.Add(v != 0 ? (byte)(b | 0x80) : b);
        }
        while (v != 0);
        return [.. bytes];
    }

    private sealed record ZipItem(string Name, byte[] Data);

    /// <summary>Re-writes a zip entry by entry (STORED), then lets <paramref name="extra"/> add entries.</summary>
    private static byte[] Rezip(byte[] zip, Action<ZipArchive, List<ZipItem>> extra)
    {
        var items = new List<ZipItem>();
        using (var input = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read))
        {
            foreach (var entry in input.Entries)
            {
                using var s = entry.Open();
                using var m = new MemoryStream();
                s.CopyTo(m);
                items.Add(new ZipItem(entry.FullName, m.ToArray()));
            }
        }

        var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var item in items)
            {
                AddEntry(archive, item.Name, item.Data);
            }

            extra(archive, items);
        }

        return output.ToArray();
    }

    private static void AddEntry(ZipArchive archive, string name, byte[] data)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using var s = entry.Open();
        s.Write(data);
    }

    /// <summary>Edits the local header of the <paramref name="index"/>-th central directory entry in place.</summary>
    private static byte[] SetLocalHeader(byte[] zip, int index, ushort flags, bool zeroCrc, bool zeroSizes, bool flipCrc = false)
    {
        byte[] bytes = (byte[])zip.Clone();
        int eocd = bytes.AsSpan().LastIndexOf("PK\u0005\u0006"u8);
        int cd = BitConverter.ToInt32(bytes, eocd + 16);
        int at = cd;
        for (int i = 0; i < index; i++)
        {
            at += 46 + BitConverter.ToUInt16(bytes, at + 28) + BitConverter.ToUInt16(bytes, at + 30) + BitConverter.ToUInt16(bytes, at + 32);
        }

        int local = BitConverter.ToInt32(bytes, at + 42);
        Assert.Equal(0x04034B50, BitConverter.ToInt32(bytes, local));
        BitConverter.TryWriteBytes(bytes.AsSpan(local + 6), (ushort)(BitConverter.ToUInt16(bytes, local + 6) | flags));
        if (zeroCrc)
        {
            bytes.AsSpan(local + 14, 4).Clear();
        }

        if (flipCrc)
        {
            bytes[local + 14] ^= 0x01;
        }

        if (zeroSizes)
        {
            bytes.AsSpan(local + 18, 8).Clear();
        }

        return bytes;
    }
}
