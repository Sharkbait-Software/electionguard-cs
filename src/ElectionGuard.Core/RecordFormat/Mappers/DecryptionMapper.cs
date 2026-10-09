using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using static ElectionGuard.Core.RecordFormat.Mappers.WireValues;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat.Mappers;

/// <summary>
/// The decryption items (design §3.1, §4.5), which name their ballot by locator and H_I (a binding:
/// it must equal the ballot's), where the domain objects name it by string id; the
/// <see cref="RecordBallotIndex"/> joins the two (a locator the record does not hold, or an H_I
/// that is not the ballot's, is "12.structure" or "13.structure", and so is an item with no locator
/// at all, which is canonical: D1 and D2 do not cover an absent message). Range findings: a contest-data decryption's β
/// 12.structure, c 12.B, v 12.A; a challenged ballot's released nonces 13.structure. A challenged
/// decryption's contests out of ascending index order (the schema's rule) are 13.structure.
/// </summary>
internal static class DecryptionMapper
{
    public static Pb.RecordItem ToItem(ContestDataRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new Pb.RecordItem
        {
            ContestDataRequest = new Pb.ContestDataRequest
            {
                Ballot = DeviceMapper.ToItem(request.Ballot),
                HI = Bytes(request.IdentifierHash),
                ContestIndex = (uint)request.ContestIndex,
            },
        };
    }

    /// <summary>
    /// A contest-data request from its item. One that names no ballot (an absent locator, which is
    /// canonical) is "12.structure", the request join rule's code (design §6.2), with a placeholder
    /// locator in the object no verifier is handed. The locator is not resolved here: whether it
    /// names a cast regular ballot is the record verifier's join.
    /// </summary>
    public static RecordDecoded<ContestDataRequest> FromItem(Pb.ContestDataRequest item)
    {
        ArgumentNullException.ThrowIfNull(item);
        var context = new RecordDecodeContext();
        BallotLocator locator = default;
        if (item.Ballot is null)
        {
            context.Add("12.structure", $"The contest-data request for contest {item.ContestIndex} names no ballot (its locator is absent).");
        }
        else
        {
            locator = DeviceMapper.FromItem(item.Ballot);
        }

        return context.Result(new ContestDataRequest(
            locator,
            SelectionEncryptionIdentifierHash.FromCanonicalBytes(RequireArray(item.HI, 32, "H_I")),
            (int)item.ContestIndex));
    }

    /// <summary>
    /// A contest-data decryption of <paramref name="ballot"/>, which the item names by its locator in
    /// <paramref name="ballots"/>, found by H_I (a ballot's string id need not be unique).
    /// </summary>
    public static Pb.RecordItem ToItem(DecryptedContestData decrypted, BallotEncryption.EncryptedBallot ballot, RecordBallotIndex ballots)
    {
        ArgumentNullException.ThrowIfNull(decrypted);
        ArgumentNullException.ThrowIfNull(ballots);
        var (locator, identifierHash) = ballots.Locate(Decrypts(ballot, decrypted.BallotId));
        return new Pb.RecordItem
        {
            ContestDataDecryption = new Pb.ContestDataDecryption
            {
                Ballot = DeviceMapper.ToItem(locator),
                HI = Bytes(identifierHash),
                ContestIndex = (uint)decrypted.ContestIndex,
                Beta = Zp(decrypted.Beta),
                Proof = Bytes([.. decrypted.Challenge.ToByteArray(), .. decrypted.Response.ToByteArray()]),
                Data = Bytes(decrypted.Data),
            },
        };
    }

    public static RecordDecoded<DecryptedContestData> FromItem(Pb.ContestDataDecryption item, RecordBallotIndex ballots, Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(ballots);
        ArgumentNullException.ThrowIfNull(manifest);
        var context = new RecordDecodeContext();
        string ballotId = ballots.Resolve(item.Ballot, item.HI, context, "12.structure");
        string contestId = manifest.Contests.SingleOrDefault(x => x.Index == item.ContestIndex)?.Id ?? UnknownLabel("contest", item.ContestIndex);
        string where = $"contest data decryption of ballot {ballotId}, contest {contestId}";
        var proof = Require(item.Proof, 64, where + ": proof");
        return context.Result(new DecryptedContestData
        {
            BallotId = ballotId,
            ContestId = contestId,
            ContestIndex = (int)item.ContestIndex,
            Beta = context.Zp(Require(item.Beta, 512, where + ": β"), RecordValueRanges.ContestDataBeta, where + ": β"),
            Challenge = context.Zq(proof[..32], RecordValueRanges.ContestDataChallenge, where + ": c"),
            Response = context.Zq(proof[32..], RecordValueRanges.ContestDataResponse, where + ": v"),
            Data = RequireArray(item.Data, 32, where + ": D", multiple: true),
        });
    }

    /// <summary>
    /// A challenged ballot's decryption: per contest, ascending index, each field's index and label
    /// (options and supplemental fields alike, in manifest order) with σ and ξ_i,j, and contest data
    /// (ξ, D) where the contest has it. The writer refuses a decryption whose stated indices and
    /// labels disagree with the manifest (an honest decryption never does), or that misses or adds a
    /// field. The item names <paramref name="ballot"/> by its locator, found by H_I.
    /// </summary>
    public static Pb.RecordItem ToItem(DecryptedChallengedBallot decrypted, BallotEncryption.EncryptedBallot ballot, RecordBallotIndex ballots, Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(decrypted);
        ArgumentNullException.ThrowIfNull(ballots);
        ArgumentNullException.ThrowIfNull(manifest);
        var (locator, identifierHash) = ballots.Locate(Decrypts(ballot, decrypted.BallotId));
        var item = new Pb.ChallengedBallotDecryption { Ballot = DeviceMapper.ToItem(locator), HI = Bytes(identifierHash) };
        foreach (var contest in decrypted.Contests.OrderBy(x => x.Index))
        {
            var manifestContest = manifest.Contests.SingleOrDefault(c => c.Index == contest.Index && c.Id == contest.ContestId)
                ?? throw new ArgumentException($"Challenged ballot {decrypted.BallotId} decrypts contest {contest.ContestId} at index {contest.Index}, which is not a manifest contest's index and label.", nameof(decrypted));
            var entry = new Pb.DecryptedContest { Index = (uint)manifestContest.Index, Label = contest.ContestId };
            var fields = contest.Choices.Concat(contest.SupplementalFields).ToList();
            foreach (var declared in manifestContest.VerifiableFields())
            {
                var field = fields.SingleOrDefault(x => x.Index == declared.Index)
                    ?? throw new ArgumentException($"Challenged ballot {decrypted.BallotId}, contest {contest.ContestId}, releases no value for field {declared.Index} ({declared.Id}).", nameof(decrypted));
                if (field.Id != declared.Id)
                {
                    throw new ArgumentException($"Challenged ballot {decrypted.BallotId}, contest {contest.ContestId}, labels field {declared.Index} {field.Id}; the manifest's label is {declared.Id}.", nameof(decrypted));
                }

                entry.Fields.Add(new Pb.DecryptedField { Index = (uint)declared.Index, Label = field.Id, Value = (uint)field.Value, Nonce = Zq(field.EncryptionNonce) });
            }

            if (fields.Count != entry.Fields.Count)
            {
                throw new ArgumentException($"Challenged ballot {decrypted.BallotId}, contest {contest.ContestId}, releases fields the manifest does not declare.", nameof(decrypted));
            }

            if (contest.ContestData is { } data)
            {
                entry.ContestData = new Pb.ReleasedContestData { Nonce = Zq(data.EncryptionNonce), Data = Bytes(data.Data) };
            }

            item.Contests.Add(entry);
        }

        return new Pb.RecordItem { ChallengedBallotDecryption = item };
    }

    /// <summary>The H_I of <paramref name="ballot"/>, which the decryption naming <paramref name="ballotId"/> must be of.</summary>
    private static SelectionEncryptionIdentifierHash Decrypts(BallotEncryption.EncryptedBallot ballot, string ballotId)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        if (ballot.Id != ballotId)
        {
            throw new ArgumentException($"The decryption is of ballot {ballotId}, not of ballot {ballot.Id}.", nameof(ballot));
        }

        return ballot.SelectionEncryptionIdentifierHash;
    }

    /// <summary>
    /// A challenged ballot's decryption from its item, each contest and field under the index and the
    /// label the item states (design §4.6): the index drives Verification 13's ciphertext lookup, and
    /// Verification 14 compares the label with the manifest's label for that index. Each field goes
    /// to the option or supplemental list by its index in the manifest (an index the manifest lacks
    /// counts as an option). An index above 2^31 - 1 decodes as -1, which no manifest index is.
    /// </summary>
    public static RecordDecoded<DecryptedChallengedBallot> FromItem(Pb.ChallengedBallotDecryption item, RecordBallotIndex ballots, Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(ballots);
        ArgumentNullException.ThrowIfNull(manifest);
        var context = new RecordDecodeContext();
        string ballotId = ballots.Resolve(item.Ballot, item.HI, context, "13.structure");
        RequireAscending(item.Contests, x => x.Index, context, "13.structure", $"The contests of the decryption of challenged ballot {ballotId}");
        var contests = item.Contests.Select(contest =>
        {
            var manifestContest = manifest.Contests.SingleOrDefault(x => x.Index == contest.Index);
            string where = $"challenged ballot {ballotId}, contest {contest.Index} ({contest.Label})";
            var choices = new List<DecryptedChallengedField>();
            var supplemental = new List<DecryptedChallengedField>();
            foreach (var field in contest.Fields)
            {
                var decoded = new DecryptedChallengedField
                {
                    Index = WireIndex(field.Index),
                    Id = field.Label,
                    Value = (int)field.Value,
                    EncryptionNonce = context.Zq(Require(field.Nonce, 32, where + ": ξ"), RecordValueRanges.ChallengedNonce, $"{where}, field {field.Index} ({field.Label}): ξ"),
                };
                (manifestContest?.SupplementalFields.Any(x => x.Index == field.Index) == true ? supplemental : choices).Add(decoded);
            }

            return new DecryptedChallengedContest
            {
                Index = WireIndex(contest.Index),
                ContestId = contest.Label,
                Choices = choices,
                SupplementalFields = supplemental,
                ContestData = contest.ContestData is { } data ? new DecryptedChallengedContestData
                {
                    EncryptionNonce = context.Zq(Require(data.Nonce, 32, where + ": contest data ξ"), RecordValueRanges.ChallengedNonce, where + ": contest data ξ"),
                    Data = RequireArray(data.Data, 32, where + ": D", multiple: true),
                } : null,
            };
        }).ToList();

        return context.Result(new DecryptedChallengedBallot { BallotId = ballotId, Contests = contests });

        static int WireIndex(uint index) => index > int.MaxValue ? -1 : (int)index;
    }
}
