using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using static ElectionGuard.Core.RecordFormat.Mappers.WireValues;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat.Mappers;

/// <summary>
/// The tallies (design §3.1, §4.5). The encrypted tally is an <c>encrypted_tally_header</c> (#17)
/// and one <c>encrypted_tally_contest</c> per manifest contest, ascending index, with (A ‖ B) per
/// field in manifest order and the contest's cast weight (S10a; <c>MaximumCount</c> is derived,
/// never stored). The decrypted tally is one <c>decrypted_tally_contest</c> per contest with index,
/// label, t, T and (c ‖ v) per field. Range findings: A 9.A, B 9.B, T 10.C, c 10.B, v 10.A; a
/// count that does not fit the domain's integers is "9.structure" or "10.structure".
/// </summary>
internal static class TallyMapper
{
    public static IReadOnlyList<Pb.RecordItem> ToItems(EncryptedTally tally)
    {
        ArgumentNullException.ThrowIfNull(tally);

        // Every cast ballot weighs at least 1, so a total below the count is not the tally's: it is
        // one restored from the JSON record format, which does not publish it (0). Writing it would
        // publish a false header value (#17).
        if (tally.TotalCastWeight < tally.BallotsCast)
        {
            throw new ArgumentException($"The tally's total cast weight ({tally.TotalCastWeight}) is below its {tally.BallotsCast} cast ballots, so it is unknown (a tally restored from the JSON record format does not carry it); aggregate the ballots again to write the record.", nameof(tally));
        }

        var manifest = tally.Manifest;
        var items = new List<Pb.RecordItem>
        {
            new() { EncryptedTallyHeader = new Pb.EncryptedTallyHeader { CastBallotCount = (ulong)tally.BallotsCast, TotalCastWeight = (ulong)tally.TotalCastWeight } },
        };

        foreach (var contest in manifest.Contests.OrderBy(x => x.Index))
        {
            var aggregate = tally.Contests.TryGetValue(contest.Id, out var found)
                ? found
                : throw new ArgumentException($"The tally has no aggregate for contest {contest.Id}; the record lists every manifest contest.", nameof(tally));
            var fields = contest.VerifiableFields().ToList();
            if (aggregate.Choices.Count != fields.Count)
            {
                throw new ArgumentException($"The tally of contest {contest.Id} has {aggregate.Choices.Count} fields; the manifest declares {fields.Count}.", nameof(tally));
            }

            byte[] bytes = new byte[1024 * fields.Count];
            for (int i = 0; i < fields.Count; i++)
            {
                var choice = aggregate.Choices.TryGetValue(fields[i].Id, out var c)
                    ? c
                    : throw new ArgumentException($"The tally of contest {contest.Id} has no field {fields[i].Id}.", nameof(tally));
                choice.A.ToByteArray().CopyTo(bytes, 1024 * i);
                choice.B.ToByteArray().CopyTo(bytes, 1024 * i + 512);
            }

            items.Add(new Pb.RecordItem
            {
                EncryptedTallyContest = new Pb.EncryptedTallyContest { Index = (uint)contest.Index, Fields = Bytes(bytes), CastWeight = (ulong)aggregate.CastWeight },
            });
        }

        if (tally.Contests.Count != manifest.Contests.Count)
        {
            throw new ArgumentException("The tally has contests the manifest does not.", nameof(tally));
        }

        return items;
    }

    /// <summary>
    /// The encrypted tally from its header and contest items, against <paramref name="manifest"/>.
    /// As the JSON reader does (S10a), the contests and fields are the items', not the manifest's,
    /// so Verification 9 sees one the manifest lacks or one missing ("9.structure"): an unknown index
    /// or a field past the manifest's gets an id that is not text.
    /// </summary>
    public static RecordDecoded<EncryptedTally> FromItems(Pb.EncryptedTallyHeader header, IEnumerable<Pb.EncryptedTallyContest> contests, Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(contests);
        ArgumentNullException.ThrowIfNull(manifest);
        var context = new RecordDecodeContext();
        if (header.CastBallotCount > int.MaxValue)
        {
            context.Add("9.structure", $"The tally header counts {header.CastBallotCount} cast ballots, more than this library counts ({int.MaxValue}).");
        }

        var restored = new List<(string ContestId, long CastWeight, IEnumerable<(string ChoiceId, IntegerModP A, IntegerModP B)> Choices)>();
        foreach (var item in contests)
        {
            var contest = manifest.Contests.SingleOrDefault(x => x.Index == item.Index);
            string contestId = contest?.Id ?? UnknownLabel("contest", item.Index);
            var declared = contest?.VerifiableFields().ToList() ?? [];
            var span = Require(item.Fields, 1024, $"tally contest {contestId}", multiple: true);
            var choices = new List<(string, IntegerModP, IntegerModP)>();
            for (int i = 0; i < span.Length / 1024; i++)
            {
                string fieldId = i < declared.Count ? declared[i].Id : UnknownLabel("field", i + 1);
                choices.Add((fieldId,
                    context.Zp(span.Slice(1024 * i, 512), RecordValueRanges.TallyA, $"tally contest {contestId}, field {fieldId}: A"),
                    context.Zp(span.Slice(1024 * i + 512, 512), RecordValueRanges.TallyB, $"tally contest {contestId}, field {fieldId}: B")));
            }

            restored.Add((contestId, (long)Math.Min(item.CastWeight, long.MaxValue), choices));
        }

        EncryptedTally tally;
        try
        {
            tally = EncryptedTally.Restore(manifest, (int)Math.Min(header.CastBallotCount, int.MaxValue), restored);
            tally.TotalCastWeight = (long)Math.Min(header.TotalCastWeight, long.MaxValue);
        }
        catch (ArgumentException ex)
        {
            context.Add("9.structure", ex.Message);
            tally = new EncryptedTally(manifest);
        }

        return context.Result(tally);
    }

    public static IReadOnlyList<Pb.RecordItem> ToItems(DecryptedTally tally)
    {
        ArgumentNullException.ThrowIfNull(tally);
        return tally.Contests.OrderBy(x => x.Value.ContestIndex).Select(contest =>
        {
            var item = new Pb.DecryptedTallyContest { Index = (uint)contest.Value.ContestIndex, Label = contest.Key };
            item.Fields.AddRange(contest.Value.Choices.OrderBy(x => x.Value.ChoiceIndex).Select(choice => new Pb.DecryptedTallyField
            {
                Index = (uint)choice.Value.ChoiceIndex,
                Label = choice.Key,
                Tally = (ulong)choice.Value.VoteCount,
                EncodedTally = Zp(choice.Value.T),
                Proof = Bytes([.. choice.Value.Challenge.ToByteArray(), .. choice.Value.Response.ToByteArray()]),
            }));
            return new Pb.RecordItem { DecryptedTallyContest = item };
        }).ToList();
    }

    /// <summary>The decrypted tally from its contest items: labels and indices as the items state them (Verifications 10 and 11 check them).</summary>
    public static RecordDecoded<DecryptedTally> FromItems(IEnumerable<Pb.DecryptedTallyContest> contests)
    {
        ArgumentNullException.ThrowIfNull(contests);
        var context = new RecordDecodeContext();
        var result = new Dictionary<string, DecryptedTally.DecryptedContest>(StringComparer.Ordinal);
        foreach (var item in contests)
        {
            var choices = new Dictionary<string, DecryptedTally.DecryptedChoice>(StringComparer.Ordinal);
            foreach (var field in item.Fields)
            {
                string where = $"decrypted tally contest {item.Label}, field {field.Label}";
                if (field.Tally > int.MaxValue)
                {
                    context.Add("10.structure", $"{where}: the count {field.Tally} is more than this library counts ({int.MaxValue}).");
                }

                var proof = Require(field.Proof, 64, where + ": proof");
                if (!choices.TryAdd(field.Label, new DecryptedTally.DecryptedChoice
                {
                    ChoiceIndex = (int)field.Index,
                    VoteCount = (int)Math.Min(field.Tally, int.MaxValue),
                    T = context.Zp(Require(field.EncodedTally, 512, where + ": T"), RecordValueRanges.TallyT, where + ": T"),
                    Challenge = context.Zq(proof[..32], RecordValueRanges.TallyChallenge, where + ": c"),
                    Response = context.Zq(proof[32..], RecordValueRanges.TallyResponse, where + ": v"),
                }))
                {
                    context.Add("11.structure", $"Decrypted tally contest {item.Label} lists field {field.Label} twice.");
                }
            }

            if (!result.TryAdd(item.Label, new DecryptedTally.DecryptedContest { ContestIndex = (int)item.Index, Choices = choices }))
            {
                context.Add("11.structure", $"The decrypted tally lists contest {item.Label} twice.");
            }
        }

        return context.Result(new DecryptedTally { Contests = result });
    }

    public static EncryptedTallyHeader Header(Pb.EncryptedTallyHeader item) =>
        new((long)Math.Min(item.CastBallotCount, long.MaxValue), (long)Math.Min(item.TotalCastWeight, long.MaxValue));
}
