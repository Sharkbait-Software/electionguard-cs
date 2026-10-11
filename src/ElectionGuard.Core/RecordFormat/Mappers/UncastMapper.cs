using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using static ElectionGuard.Core.RecordFormat.Mappers.WireValues;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat.Mappers;

/// <summary>
/// An uncast pre-encrypted ballot (design §3.2) is split into two items in two phases: the printed
/// content in its device section (sealed) and its opening, an <c>uncast_nonce_release</c>, in the
/// final phase. Which printed form is used follows from what is released (user decision R-1,
/// "Whenever ξ_B is released"):
/// <list type="bullet">
/// <item>ξ_B released (<see cref="PreEncryptedUncastBallot.BallotNonce"/> set): the compact item
/// (<c>pre_encrypted_compact_uncast_ballot</c>: id_B, H_I, style, C_ξB, per contest index and χ,
/// H_C, B_C) and a release carrying ξ_B alone. Mandatory for a ballot printed and never returned
/// (NQ-2), which always releases ξ_B.</item>
/// <item>ξ_B not released: the full item (every vector, ψ, short code and label) and a release
/// carrying the ξ_i,j,k per contest, selection-major, aligned with the printed selections.</item>
/// </list>
/// <see cref="Join"/> rebuilds the domain object. For a compact item it regenerates the vectors, ψ
/// and short codes from ξ_B (<see cref="PreEncryptionPrimitives.GenerateContests"/>) and keeps the
/// item's own χ and H_C, so Verifications 16 and 18 compare the regenerated content with what was
/// sealed; the released nonces are the regenerated ones (eq. 121). A release whose form does not
/// match its item's, or whose H_I differs, is "18.structure"; a compact item that cannot be
/// regenerated (no Ω in the manifest, an unknown style) is "16.structure"; released nonces ≥ q are
/// "18.structure" and printed α, β ≥ p "6.A" (design §4.8). The schema's ascending order: printed
/// contests by index and a contest's vectors by selection index "16.structure", released contests
/// by index "18.structure".
/// </summary>
internal static class UncastMapper
{
    /// <summary>The printed item and the release of <paramref name="uncast"/>, at <paramref name="locator"/>.</summary>
    public static (Pb.RecordItem Printed, Pb.RecordItem Release) Split(PreEncryptedUncastBallot uncast, BallotLocator locator)
    {
        ArgumentNullException.ThrowIfNull(uncast);
        ArgumentNullException.ThrowIfNull(uncast.Ballot);
        var ballot = uncast.Ballot;
        bool compact = uncast.BallotNonce is not null;
        var release = new Pb.UncastNonceRelease
        {
            Ballot = DeviceMapper.ToItem(locator),
            HI = Bytes(ballot.SelectionEncryptionIdentifierHash),
        };

        if (compact)
        {
            byte[] nonce = uncast.BallotNonce!.Value;
            if (nonce is not { Length: 32 })
            {
                throw new ArgumentException($"Uncast ballot {ballot.Id}'s ξ_B is not 32 bytes.", nameof(uncast));
            }

            release.BallotNonce = Bytes(nonce);
        }
        else
        {
            foreach (var contest in ballot.Contests.OrderBy(x => x.ContestIndex))
            {
                var released = uncast.Contests.SingleOrDefault(x => x.ContestId == contest.ContestId)
                    ?? throw new ArgumentException($"Uncast ballot {ballot.Id} releases no nonces for contest {contest.ContestId}.", nameof(uncast));
                var nonces = contest.Selections.OrderBy(x => x.SelectionIndex).SelectMany(selection =>
                {
                    var row = released.Selections.SingleOrDefault(x => x.SelectionIndex == selection.SelectionIndex)
                        ?? throw new ArgumentException($"Uncast ballot {ballot.Id}, contest {contest.ContestId}, releases no nonces for vector {selection.SelectionIndex}.", nameof(uncast));
                    return row.Nonces.SelectMany(x => x.ToByteArray());
                }).ToArray();
                release.Contests.Add(new Pb.UncastContestNonces { Index = (uint)contest.ContestIndex, Nonces = Bytes(nonces) });
            }
        }

        return (ToPrintedItem(ballot, compact), new Pb.RecordItem { UncastNonceRelease = release });
    }

    /// <summary>The printed item of <paramref name="ballot"/>: compact (index and χ per contest) or full.</summary>
    public static Pb.RecordItem ToPrintedItem(PreEncryptedBallot ballot, bool compact)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        var contests = ballot.Contests.OrderBy(x => x.ContestIndex).ToList();
        if (compact)
        {
            var item = new Pb.PreEncryptedCompactUncastBallot
            {
                IdB = Bytes(ballot.SelectionEncryptionIdentifier),
                HI = Bytes(ballot.SelectionEncryptionIdentifierHash),
                BallotStyle = ballot.BallotStyleId,
                ConfirmationCode = Bytes(ballot.ConfirmationCode),
                ChainingField = Bytes(ballot.ChainingField),
                EncryptedBallotNonce = BallotNonce(ballot.EncryptedBallotNonce),
                BallotRef = ballot.Id,
            };
            item.Contests.AddRange(contests.Select(x => new Pb.CompactUncastContest { Index = (uint)x.ContestIndex, ContestHash = Bytes(x.ContestHash) }));
            return new Pb.RecordItem { PreEncryptedCompactUncastBallot = item };
        }

        var full = new Pb.PreEncryptedUncastBallot
        {
            IdB = Bytes(ballot.SelectionEncryptionIdentifier),
            HI = Bytes(ballot.SelectionEncryptionIdentifierHash),
            BallotStyle = ballot.BallotStyleId,
            ConfirmationCode = Bytes(ballot.ConfirmationCode),
            ChainingField = Bytes(ballot.ChainingField),
            EncryptedBallotNonce = BallotNonce(ballot.EncryptedBallotNonce),
            BallotRef = ballot.Id,
        };

        foreach (var contest in contests)
        {
            var item = new Pb.UncastContest { Index = (uint)contest.ContestIndex, Label = contest.ContestId, ContestHash = Bytes(contest.ContestHash) };
            item.Selections.AddRange(contest.Selections.OrderBy(x => x.SelectionIndex).Select(x => new Pb.UncastSelection
            {
                SelectionIndex = (uint)x.SelectionIndex,
                OptionLabel = x.ChoiceId ?? "",
                Vector = Vector(x.Vector),
                Psi = Bytes(x.SelectionHash),
                ShortCode = x.ShortCode.Value,
            }));
            full.Contests.Add(item);
        }

        return new Pb.RecordItem { PreEncryptedUncastBallot = full };
    }

    /// <summary>
    /// The domain uncast ballot from its printed item (full or compact) and its release, for the
    /// device <paramref name="deviceId"/> of the election <paramref name="record"/>.
    /// </summary>
    public static RecordDecoded<PreEncryptedUncastBallot> Join(Pb.RecordItem printed, Pb.RecordItem release, EncryptionRecord record, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(printed);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(record);
        if (release.ItemCase != Pb.RecordItem.ItemOneofCase.UncastNonceRelease)
        {
            throw new ArgumentException("The release is not an uncast_nonce_release item.", nameof(release));
        }

        var context = new RecordDecodeContext();
        var opening = release.UncastNonceRelease;
        return printed.ItemCase switch
        {
            Pb.RecordItem.ItemOneofCase.PreEncryptedUncastBallot => context.Result(JoinFull(printed.PreEncryptedUncastBallot, opening, deviceId, context)),
            Pb.RecordItem.ItemOneofCase.PreEncryptedCompactUncastBallot => context.Result(JoinCompact(printed.PreEncryptedCompactUncastBallot, opening, record, deviceId, context)),
            _ => throw new ArgumentException($"Item member {(int)printed.ItemCase} is not an uncast pre-encrypted ballot.", nameof(printed)),
        };
    }

    private static void RequireBinding(Google.Protobuf.ByteString printedIdentifierHash, Pb.UncastNonceRelease opening, string id, RecordDecodeContext context)
    {
        if (!opening.HI.Equals(printedIdentifierHash))
        {
            context.Add("18.structure", $"The release for uncast ballot {id} names H_I {Convert.ToHexStringLower(opening.HI.Span)}, not the ballot's.");
        }
    }

    /// <summary>
    /// The domain uncast ballot of a full printed item alone, before its release exists (a guardian
    /// run of the aggregated prefix) or when a final record lacks it: every vector, ψ, χ, short code
    /// and label is on the item, so Verifications 6 (6.A), 16 (16.A-16.C), 17 and 19 are checked on it
    /// at once. It carries no released nonces (<see cref="PreEncryptedUncastBallot.Contests"/> empty),
    /// so Verification 18 waits for the release. A compact item has no vectors until its ξ_B is
    /// released, so it has no counterpart.
    /// </summary>
    public static RecordDecoded<PreEncryptedUncastBallot> FromPrinted(Pb.PreEncryptedUncastBallot item, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(item);
        var context = new RecordDecodeContext();
        string id = BallotMapper.Id(item.BallotRef, item.IdB);
        RequirePrintedOrder(item, id, context);
        return context.Result(new PreEncryptedUncastBallot { Ballot = PrintedBallot(item, id, deviceId, context), BallotNonce = null, Contests = [] });
    }

    private static void RequirePrintedOrder(Pb.PreEncryptedUncastBallot item, string id, RecordDecodeContext context)
    {
        RequireAscending(item.Contests, x => x.Index, context, "16.structure", $"The contests of uncast ballot {id}");
        foreach (var contest in item.Contests)
        {
            RequireAscending(contest.Selections, x => x.SelectionIndex, context, "16.structure", $"The vectors of uncast ballot {id}, contest {contest.Index}");
        }
    }

    /// <summary>The printed content of a full uncast item as the domain ballot.</summary>
    private static PreEncryptedBallot PrintedBallot(Pb.PreEncryptedUncastBallot item, string id, string deviceId, RecordDecodeContext context) => new()
    {
        Id = id,
        BallotStyleId = item.BallotStyle,
        SelectionEncryptionIdentifier = SelectionEncryptionIdentifier.FromCanonicalBytes(Require(item.IdB, 32, "id_B")),
        SelectionEncryptionIdentifierHash = SelectionEncryptionIdentifierHash.FromCanonicalBytes(RequireArray(item.HI, 32, "H_I")),
        EncryptedBallotNonce = BallotNonce(item.EncryptedBallotNonce, context, $"uncast ballot {id}", RecordValueRanges.UncastBallotNonce),
        Contests = item.Contests.Select(contest => new PreEncryptedContest
        {
            ContestId = contest.Label,
            ContestIndex = (int)contest.Index,
            Selections = contest.Selections.Select(selection => new PreEncryptedSelection
            {
                SelectionIndex = (int)selection.SelectionIndex,
                ChoiceId = selection.OptionLabel.Length == 0 ? null : selection.OptionLabel,
                Vector = Vector(selection.Vector, context, $"uncast ballot {id}, contest {contest.Label}, vector {selection.SelectionIndex}"),
                SelectionHash = SelectionHash.FromCanonicalBytes(RequireArray(selection.Psi, 32, "ψ")),
                ShortCode = new ShortCode(selection.ShortCode),
            }).ToList(),
            ContestHash = ContestHash.FromCanonicalBytes(RequireArray(contest.ContestHash, 32, "χ")),
        }).ToList(),
        ChainingField = ChainingField.FromCanonicalBytes(Require(item.ChainingField, ChainingField.ByteLength, "B_C")),
        ConfirmationCode = ConfirmationCode.FromCanonicalBytes(RequireArray(item.ConfirmationCode, 32, "H_C")),
        DeviceId = deviceId,
    };

    private static PreEncryptedUncastBallot JoinFull(Pb.PreEncryptedUncastBallot item, Pb.UncastNonceRelease opening, string deviceId, RecordDecodeContext context)
    {
        string id = BallotMapper.Id(item.BallotRef, item.IdB);
        RequireBinding(item.HI, opening, id, context);
        if (!opening.BallotNonce.IsEmpty || opening.Contests.Count == 0)
        {
            context.Add("18.structure", $"Uncast ballot {id} is in the full form, so its release carries the nonces ξ_i,j,k and not ξ_B (user decision R-1).");
        }

        RequirePrintedOrder(item, id, context);
        RequireAscending(opening.Contests, x => x.Index, context, "18.structure", $"The released contests of uncast ballot {id}");
        var ballot = PrintedBallot(item, id, deviceId, context);
        var released = new List<PreEncryptedReleasedContest>();
        foreach (var contest in ballot.Contests)
        {
            var nonces = opening.Contests.Where(x => x.Index == contest.ContestIndex).ToList();
            if (nonces.Count != 1)
            {
                context.Add("18.structure", $"The release for uncast ballot {id} has {nonces.Count} entries for contest {contest.ContestIndex}, not one.");
                continue;
            }

            var values = Chunks(nonces[0].Nonces, 32, "ξ_i,j,k")
                .Select((x, n) => context.Zq(x, RecordValueRanges.UncastNonce, $"uncast ballot {id}, contest {contest.ContestIndex}: ξ #{n}"))
                .ToList();
            int m = contest.Selections.Count == 0 ? 0 : contest.Selections[0].Vector.Count;
            if (m == 0 || values.Count != m * contest.Selections.Count)
            {
                context.Add("18.structure", $"The release for uncast ballot {id}, contest {contest.ContestIndex}, has {values.Count} nonces, not {m} for each of its {contest.Selections.Count} vectors.");
                continue;
            }

            released.Add(new PreEncryptedReleasedContest
            {
                ContestId = contest.ContestId,
                Selections = contest.Selections.Select((selection, row) => new PreEncryptedReleasedSelection
                {
                    SelectionIndex = selection.SelectionIndex,
                    Nonces = values.Skip(row * m).Take(m).ToList(),
                }).ToList(),
            });
        }

        if (opening.Contests.Select(x => x.Index).Distinct().Count() != opening.Contests.Count
            || opening.Contests.Any(x => ballot.Contests.All(c => c.ContestIndex != x.Index)))
        {
            context.Add("18.structure", $"The release for uncast ballot {id} lists a contest twice or one the ballot does not have.");
        }

        return new PreEncryptedUncastBallot { Ballot = ballot, BallotNonce = null, Contests = released };
    }

    private static PreEncryptedUncastBallot JoinCompact(Pb.PreEncryptedCompactUncastBallot item, Pb.UncastNonceRelease opening, EncryptionRecord record, string deviceId, RecordDecodeContext context)
    {
        string id = BallotMapper.Id(item.BallotRef, item.IdB);
        RequireBinding(item.HI, opening, id, context);
        var identifierHash = SelectionEncryptionIdentifierHash.FromCanonicalBytes(RequireArray(item.HI, 32, "H_I"));
        var ballotNonce = new BallotNonce(opening.BallotNonce.ToByteArray());
        if (opening.BallotNonce.IsEmpty || opening.Contests.Count != 0)
        {
            context.Add("18.structure", $"Uncast ballot {id} is in the compact form, so its release carries ξ_B and nothing else (user decision R-1).");
        }

        RequireAscending(item.Contests, x => x.Index, context, "16.structure", $"The contests of uncast ballot {id}");

        List<PreEncryptedContest> regenerated = [];
        if (!opening.BallotNonce.IsEmpty)
        {
            try
            {
                regenerated = PreEncryptionPrimitives.GenerateContests(record, item.BallotStyle, identifierHash, ballotNonce);
            }
            catch (ArgumentException ex)
            {
                context.Add("16.structure", $"Uncast ballot {id} cannot be regenerated from its released ξ_B: {ex.Message}");
            }
        }

        // The regenerated vectors, ψ and short codes, under the item's own χ: V16.B recomputes χ from
        // the regenerated ψ and compares it with the sealed one, and V16.C then H_C.
        var contests = item.Contests.Select(contest =>
        {
            var match = regenerated.SingleOrDefault(x => x.ContestIndex == contest.Index);
            return new PreEncryptedContest
            {
                ContestId = match?.ContestId ?? UnknownLabel("contest", contest.Index),
                ContestIndex = (int)contest.Index,
                Selections = match?.Selections ?? [],
                ContestHash = ContestHash.FromCanonicalBytes(RequireArray(contest.ContestHash, 32, "χ")),
            };
        }).ToList();

        var ballot = new PreEncryptedBallot
        {
            Id = id,
            BallotStyleId = item.BallotStyle,
            SelectionEncryptionIdentifier = SelectionEncryptionIdentifier.FromCanonicalBytes(Require(item.IdB, 32, "id_B")),
            SelectionEncryptionIdentifierHash = identifierHash,
            EncryptedBallotNonce = BallotNonce(item.EncryptedBallotNonce, context, $"uncast ballot {id}", RecordValueRanges.UncastBallotNonce),
            Contests = contests,
            ChainingField = ChainingField.FromCanonicalBytes(Require(item.ChainingField, ChainingField.ByteLength, "B_C")),
            ConfirmationCode = ConfirmationCode.FromCanonicalBytes(RequireArray(item.ConfirmationCode, 32, "H_C")),
            DeviceId = deviceId,
        };

        return new PreEncryptedUncastBallot
        {
            Ballot = ballot,
            BallotNonce = opening.BallotNonce.IsEmpty ? null : ballotNonce,
            Contests = contests.Select(contest => new PreEncryptedReleasedContest
            {
                ContestId = contest.ContestId,
                Selections = contest.Selections.Select(selection => new PreEncryptedReleasedSelection
                {
                    SelectionIndex = selection.SelectionIndex,
                    Nonces = selection.Vector.Select(x => x.EncryptionNonce ?? new IntegerModQ(0)).ToList(),
                }).ToList(),
            }).ToList(),
        };
    }
}
