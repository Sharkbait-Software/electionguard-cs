using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat.Mappers;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat;

public sealed partial class ElectionRecordWriter
{
    /// <summary>
    /// Resumes writing the record in <paramref name="directory"/> after a stop or a crash (design
    /// §5.2, §8.3). The claimed TOC says which phase was last fixed; every section it lists must still
    /// be on disk exactly as listed (<see cref="InvalidDataException"/> otherwise). What was written
    /// after that phase was fixed and is not covered by any root is handled as follows:
    /// <list type="bullet">
    /// <item>at the setup phase, each device section is taken up again: a torn tail is cut back to the
    /// last complete item (zero-filled tails included), a section that ends with its close is closed,
    /// any other is open again (<see cref="OpenDeviceAsync(DeviceHeader, CancellationToken)"/> hands it
    /// out once, with <see cref="DeviceSectionWriter.LastConfirmationCode"/> for the device's chain),
    /// and one whose header never got written is removed;</item>
    /// <item>a section of the next phase that is not in the TOC (a seal or a completion that did not
    /// finish) is removed, so that step is done again: at the aggregated phase that includes every
    /// decryption and release added so far, which the caller adds again.</item>
    /// </list>
    /// A corrupt item in the middle of a section, or a zero-length frame followed by data, is not
    /// repaired, and any other section not in the TOC (a device section after voting was sealed, a
    /// section of a phase other than the next) is not removed
    /// (<see cref="InvalidDataException"/> for both): the record stays as it is until an operator
    /// decides. A directory with no TOC has fixed no phase; write it again from the start.
    /// </summary>
    public static async ValueTask<ElectionRecordWriter> ResumeAsync(string directory, ElectionRecordWriterOptions? options = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        string root = Path.GetFullPath(directory);
        foreach (var temporary in new[] { "toc.binpb.tmp", "toc.jsonl.tmp" })
        {
            File.Delete(Path.Combine(root, temporary));
        }

        var reader = await ElectionRecordReader.OpenAsync(new DirectoryRecordSource(root), ct, checkPresence: false).ConfigureAwait(false);
        await using (reader.ConfigureAwait(false))
        {
            var toc = reader.ClaimedToc ?? throw new InvalidDataException($"{root} has no table of contents, so no phase of it was fixed; write the record again from the start.");
            var writer = new ElectionRecordWriter(root, reader.Encoding, options ?? new ElectionRecordWriterOptions());
            try
            {
                await writer.RestoreAsync(reader, toc, ct).ConfigureAwait(false);
                return writer;
            }
            catch
            {
                await writer.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }

    private async ValueTask RestoreAsync(ElectionRecordReader reader, TableOfContents toc, CancellationToken ct)
    {
        var listed = toc.Entries.ToDictionary(x => new SectionKey(x.Type, x.Key.Span));

        // Every section the TOC lists must be on disk as listed.
        foreach (var (section, entry) in listed)
        {
            if (!reader.Sections.Contains(section))
            {
                throw new InvalidDataException($"Section {section} is in the table of contents but not on disk.");
            }

            var frontier = new MerkleFrontier();
            await foreach (var item in reader.ReadCanonicalAsync(section, ct).ConfigureAwait(false))
            {
                frontier.Append(item.Bytes.Span);
            }

            if (frontier.Count != entry.ItemCount || frontier.Root() != entry.Root)
            {
                throw new InvalidDataException($"Section {section} on disk is not the one its table of contents fixed ({frontier.Count} items, root {frontier.Root()}; the TOC says {entry.ItemCount}, {entry.Root}).");
            }
        }

        var setup = SetupMapper.FromItems(await reader.ReadSetupItemsAsync(ct).ConfigureAwait(false));
        if (setup.Value is not { } value)
        {
            throw new InvalidDataException($"The record's setup has a finding: {setup.Findings[0].SubSection} {setup.Findings[0].Message}");
        }

        _record = value.ToEncryptionRecord();
        _entries.AddRange(toc.Entries);
        Toc = toc;
        Phase = toc.Phase;

        // Checked before anything is touched: a section this writer cannot have left behind is
        // foreign data, which is not deleted; an operator decides (design §5.2). That is a device
        // section after voting was sealed (sealing needs every device closed, and devices open only
        // before it), or a section of a phase other than the next one.
        var unlisted = reader.Sections.Where(x => !listed.ContainsKey(x)).ToList();
        foreach (var section in unlisted)
        {
            bool resumable = section.Type == RecordSectionType.Device && Phase == RecordPhase.Setup;
            bool unfinishedStep = section.Type != RecordSectionType.Device && RecordSections.IsStandard(section.Type) && section.Phase == Phase + 1;
            if (!resumable && !unfinishedStep)
            {
                throw new InvalidDataException($"Section {section} is not in the table of contents at phase {Phase}, and no unfinished step of this writer leaves it there (only a device section before voting is sealed, or a section of the next phase, is). This is not a torn tail; the record stays as it is until an operator decides (design §5.2).");
            }
        }

        foreach (var section in unlisted)
        {
            if (section.Type == RecordSectionType.Device)
            {
                await ResumeDeviceAsync(reader, section, ct).ConfigureAwait(false);
            }
            else
            {
                foreach (var path in reader.SegmentPaths(section))
                {
                    File.Delete(Path.Combine(_sink.Root, path));
                }

                DeleteEmptyDirectories(Path.GetDirectoryName(Path.Combine(_sink.Root, reader.SegmentPaths(section)[0]))!);
            }
        }

        // The ballot index of every sealed device section.
        foreach (var section in reader.Sections.Where(x => x.Type == RecordSectionType.Device && listed.ContainsKey(x)))
        {
            var device = ElectionRecordReader.DeviceKeyOf(section.Key.Span);
            await foreach (var item in reader.ReadCanonicalAsync(section, ct).ConfigureAwait(false))
            {
                var parsed = Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span);
                if (item.Ordinal > 0 && parsed.ItemCase != Pb.RecordItem.ItemOneofCase.DeviceClose)
                {
                    IndexBallot(parsed, new BallotLocator(device, item.Ordinal));
                }
            }

            _closedDevices.Add(section);
        }

        if (Phase >= RecordPhase.Aggregated)
        {
            await foreach (var item in reader.ReadCanonicalAsync(SectionKey.Of(RecordSectionType.ContestDataRequests), ct).ConfigureAwait(false))
            {
                var request = DecryptionMapper.FromItem(Pb.RecordItem.Parser.ParseFrom(item.Bytes.Span).ContestDataRequest).Value
                    ?? throw new InvalidDataException("A sealed contest-data request names no ballot.");
                _requests[(Key(request.IdentifierHash), request.ContestIndex)] = Phase == RecordPhase.Final;
            }
        }

        if (Phase == RecordPhase.Aggregated)
        {
            _challenged = new SortedSpool(_options.TempDirectory, _options.SortBudgetBytes);
            _contestData = new SortedSpool(_options.TempDirectory, _options.SortBudgetBytes);
            _releases = new SortedSpool(_options.TempDirectory, _options.SortBudgetBytes);
        }

        await WriteTocAsync(_sink.Root, toc, Encoding, ct).ConfigureAwait(false);
    }

    /// <summary>A device section of the voting phase, taken up again: its torn tail cut, then closed or open again.</summary>
    private async ValueTask ResumeDeviceAsync(ElectionRecordReader reader, SectionKey section, CancellationToken ct)
    {
        var paths = reader.SegmentPaths(section);
        var device = ElectionRecordReader.DeviceKeyOf(section.Key.Span);
        var frontier = new MerkleFrontier();
        var items = new List<Pb.RecordItem>();
        DeviceHeader? header = null;
        var codes = new List<ConfirmationCode>();
        bool closed = false;
        var scans = new List<SegmentRepair.Scan>();
        for (int i = 0; i < paths.Count; i++)
        {
            bool isLast = i == paths.Count - 1;
            var scan = await SegmentRepair.ScanAsync(Path.Combine(_sink.Root, paths[i]), Encoding, reader.Format.Minor, repair: isLast, item =>
            {
                if (closed)
                {
                    throw new InvalidDataException($"Device section {section} holds an item after its close.");
                }

                frontier.Append(item);
                var parsed = Pb.RecordItem.Parser.ParseFrom(item);
                long ordinal = frontier.Count - 1;
                if (ordinal == 0)
                {
                    header = parsed.ItemCase == Pb.RecordItem.ItemOneofCase.DeviceHeader
                        ? DeviceMapper.FromItem(parsed.DeviceHeader)
                        : throw new InvalidDataException($"Device section {section} does not start with its header.");
                }
                else if (parsed.ItemCase == Pb.RecordItem.ItemOneofCase.DeviceClose)
                {
                    closed = true;
                }
                else
                {
                    codes.Add(IndexBallot(parsed, new BallotLocator(device, ordinal)));
                }

                return ValueTask.CompletedTask;
            }, ct).ConfigureAwait(false);
            if (scan.HeaderBytes == 0 && !isLast)
            {
                // Only the newest segment can lack its header (a crash at rollover); an earlier one is corrupt.
                throw new InvalidDataException($"{paths[i]} has no segment header, and it is not the section's last segment. This is not a torn tail; the section stays unsealable until an operator decides (design §5.2).");
            }

            scans.Add(scan);
        }

        if (header is not null && paths.Count > 1 && scans[^1].HeaderBytes == 0)
        {
            // A crash after a rollover created the next segment but before its header was complete:
            // the scan cut it to nothing. Remove it and continue the previous segment, so the next
            // append rolls over again and writes the header (design §5.2).
            File.Delete(Path.Combine(_sink.Root, paths[^1]));
            paths = paths.Take(paths.Count - 1).ToList();
            scans.RemoveAt(scans.Count - 1);
        }

        if (header is null)
        {
            // The header itself never got written: the device left nothing to resume.
            foreach (var path in paths)
            {
                File.Delete(Path.Combine(_sink.Root, path));
            }

            DeleteEmptyDirectories(Path.GetDirectoryName(Path.Combine(_sink.Root, paths[0]))!);
            return;
        }

        if (header.Key != device)
        {
            throw new InvalidDataException($"Device section {section}'s header names another device.");
        }

        var last = scans[^1];
        var segmentWriter = new SectionWriter(_sink, section, Encoding, _options.SegmentSizeBytes, paths.Count - 1, last.HeaderBytes, last.Length, frontier, frontier.Count);
        if (closed)
        {
            var entry = await segmentWriter.CompleteAsync(critical: true, ct).ConfigureAwait(false);
            _closedDevices.Add(section);
            _entries.Add(entry);
            return;
        }

        var writer = new DeviceSectionWriter(this, header, segmentWriter);
        writer.Restore(codes);
        _openDevices[section] = writer;
    }

    /// <summary>Adds a sealed or resumed ballot item to the index; returns its confirmation code.</summary>
    private ConfirmationCode IndexBallot(Pb.RecordItem item, BallotLocator locator)
    {
        var (hi, code, status, form) = item.ItemCase switch
        {
            Pb.RecordItem.ItemOneofCase.EncryptedBallot => (item.EncryptedBallot.HI, item.EncryptedBallot.ConfirmationCode, (BallotStatus)(int)item.EncryptedBallot.Status, BallotForm.Regular),
            Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot => (item.PreEncryptedCastBallot.HI, item.PreEncryptedCastBallot.ConfirmationCode, BallotStatus.Cast, BallotForm.PreEncryptedCast),
            Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot => (item.PreEncryptedUncastBallot.HI, item.PreEncryptedUncastBallot.ConfirmationCode, BallotStatus.Challenged, BallotForm.UncastFull),
            Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot => (item.PreEncryptedCompactUncastBallot.HI, item.PreEncryptedCompactUncastBallot.ConfirmationCode, BallotStatus.Challenged, BallotForm.UncastCompact),
            _ => throw new InvalidDataException($"Item member {(int)item.ItemCase} is not a ballot item."),
        };

        AddBallot(SelectionEncryptionIdentifierHash.FromCanonicalBytes(hi.ToByteArray()), new BallotEntry(locator, status, form));
        return ConfirmationCode.FromCanonicalBytes(code.ToByteArray());
    }

    private void DeleteEmptyDirectories(string directory)
    {
        string root = _sink.Root.TrimEnd(Path.DirectorySeparatorChar);
        while (directory.Length > root.Length && System.IO.Directory.Exists(directory) && !System.IO.Directory.EnumerateFileSystemEntries(directory).Any())
        {
            System.IO.Directory.Delete(directory);
            directory = Path.GetDirectoryName(directory)!;
        }
    }
}
