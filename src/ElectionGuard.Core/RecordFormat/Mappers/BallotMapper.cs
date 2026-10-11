using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using static ElectionGuard.Core.RecordFormat.Mappers.WireValues;
using DomainBallot = ElectionGuard.Core.BallotEncryption.EncryptedBallot;
using DomainContest = ElectionGuard.Core.BallotEncryption.EncryptedContest;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat.Mappers;

/// <summary>
/// A domain <see cref="DomainBallot"/> to and from its record item (design §3.1, §4.6): an
/// <c>encrypted_ballot</c> for a regular ballot, a <c>pre_encrypted_cast_ballot</c> for a cast
/// pre-encrypted one (<see cref="DomainBallot.IsPreEncrypted"/>; its status, CAST, is implied by the
/// type). Encrypted items carry indices, not labels: contests ascending by manifest index, each
/// contest's fields in manifest order (options, then supplemental fields), so the mapper takes the
/// manifest both ways. The device id is not on the ballot item (it is the section's
/// <see cref="DeviceHeader.DeviceId"/>), so decoding takes it.
///
/// The domain string id is the item's optional, unverified <c>ballot_ref</c> (follow-up #12); a
/// ballot decoded without one gets the lowercase hex of its id_B, which no hash binds either.
///
/// Decoding never fails on the manifest: a contest index the manifest lacks becomes a contest whose
/// id is not text (<see cref="WireValues.UnknownLabel"/>), and fields beyond the manifest's get such
/// ids too, so that <see cref="Verify.BallotStructure"/> reports them under the verification that
/// runs it, as it reports a JSON ballot's stray labels. Range findings: α and β 6.A, range proof c
/// 6.B and v 6.C, limit, undervote-difference and null-vote proofs 7.B and 7.C, contest data
/// 8.structure, the ballot nonce 13.structure. Contests out of ascending index order (the schema's
/// rule) are 8.structure on a regular ballot and 16.structure on a cast pre-encrypted one.
/// </summary>
internal static class BallotMapper
{
    public static Pb.RecordItem ToItem(DomainBallot ballot, Manifest manifest)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(manifest);
        if (ballot.Weight < 1)
        {
            throw new ArgumentException($"Ballot {ballot.Id} has weight {ballot.Weight}; a recorded ballot's weight is at least 1.", nameof(ballot));
        }

        var contests = ballot.Contests.Select(contest => (Manifest: ManifestContest(manifest, contest.Id, ballot.Id), Contest: contest)).OrderBy(x => x.Manifest.Index).ToList();
        var timestamp = ballot.EncryptionTimestamp is { } time ? Time(time, $"Ballot {ballot.Id}'s encryption timestamp") : null;

        if (ballot.IsPreEncrypted)
        {
            if (ballot.Status != BallotStatus.Cast)
            {
                throw new ArgumentException($"Pre-encrypted ballot {ballot.Id} is recorded as {ballot.Status}; a cast pre-encrypted record is always cast (its uncast form is a PreEncryptedUncastBallot).", nameof(ballot));
            }

            var item = new Pb.PreEncryptedCastBallot
            {
                IdB = Bytes(ballot.SelectionEncryptionIdentifier),
                HI = Bytes(ballot.SelectionEncryptionIdentifierHash),
                BallotStyle = ballot.BallotStyleId,
                Weight = (uint)ballot.Weight,
                EncryptedAt = timestamp,
                ConfirmationCode = Bytes(ballot.ConfirmationCode),
                ChainingField = Bytes(ballot.ChainingField),
                EncryptedBallotNonce = BallotNonce(ballot.EncryptedBallotNonce),
                BallotRef = ballot.Id,
            };

            foreach (var (manifestContest, contest) in contests)
            {
                var pre = ballot.PreEncryptedContests!.SingleOrDefault(x => x.ContestId == contest.Id)
                    ?? throw new ArgumentException($"Pre-encrypted ballot {ballot.Id} has no pre-encryption data for contest {contest.Id}.", nameof(ballot));
                var cast = new Pb.PreEncryptedCastContest
                {
                    Contest = ToItem(contest, manifestContest, ballot.Id),
                    SelectionHashes = Bytes(pre.SelectionHashes.SelectMany(x => (byte[])x).ToArray()),
                };

                cast.Selected.AddRange(pre.SelectedVectors.Select(x => new Pb.SelectedVector
                {
                    Vector = Vector(x.Vector),
                    Psi = Bytes(x.SelectionHash),
                    ShortCode = x.ShortCode.Value,
                }));
                item.Contests.Add(cast);
            }

            if (ballot.PreEncryptedContests!.Count != contests.Count)
            {
                throw new ArgumentException($"Pre-encrypted ballot {ballot.Id} has pre-encryption data for {ballot.PreEncryptedContests.Count} contests, not its {contests.Count}.", nameof(ballot));
            }

            return new Pb.RecordItem { PreEncryptedCastBallot = item };
        }

        if (ballot.Status is not (BallotStatus.Cast or BallotStatus.Challenged or BallotStatus.Spoiled))
        {
            throw new ArgumentException($"Ballot {ballot.Id} is recorded as {ballot.Status}; a ballot in the record is cast, challenged or spoiled.", nameof(ballot));
        }

        var regular = new Pb.EncryptedBallot
        {
            IdB = Bytes(ballot.SelectionEncryptionIdentifier),
            HI = Bytes(ballot.SelectionEncryptionIdentifierHash),
            BallotStyle = ballot.BallotStyleId,
            Status = (Pb.BallotStatus)(int)ballot.Status,
            Weight = (uint)ballot.Weight,
            EncryptedAt = timestamp,
            ConfirmationCode = Bytes(ballot.ConfirmationCode),
            ChainingField = Bytes(ballot.ChainingField),
            EncryptedBallotNonce = BallotNonce(ballot.EncryptedBallotNonce),
            BallotRef = ballot.Id,
        };
        regular.Contests.AddRange(contests.Select(x => ToItem(x.Contest, x.Manifest, ballot.Id)));
        return new Pb.RecordItem { EncryptedBallot = regular };
    }

    private static Contest ManifestContest(Manifest manifest, string contestId, string ballotId) =>
        manifest.Contests.SingleOrDefault(x => x.Id == contestId)
        ?? throw new ArgumentException($"Ballot {ballotId} lists contest {contestId}, which the manifest does not; the record carries contest indices.");

    private static Pb.EncryptedContest ToItem(DomainContest contest, Contest manifestContest, string ballotId)
    {
        var item = new Pb.EncryptedContest
        {
            Index = (uint)manifestContest.Index,
            LimitProof = Proofs(contest.Proofs),
            ContestHash = Bytes(contest.ContestHash),
        };

        int listed = contest.Choices.Count + contest.SupplementalFields.Count;
        foreach (var field in manifestContest.VerifiableFields())
        {
            EncryptedValueWithProofs? value = field is SupplementalField
                ? contest.SupplementalFields.SingleOrDefault(x => x.FieldId == field.Id)
                : contest.Choices.SingleOrDefault(x => x.ChoiceId == field.Id);
            if (value is null)
            {
                throw new ArgumentException($"Ballot {ballotId}, contest {contest.Id}, has no encryption of field {field.Id}; the record lists every field of a contest in manifest order.");
            }

            item.Fields.Add(new Pb.EncryptedField { Alpha = Zp(value.Alpha), Beta = Zp(value.Beta), RangeProof = Proofs(value.Proofs) });
        }

        if (listed != item.Fields.Count)
        {
            throw new ArgumentException($"Ballot {ballotId}, contest {contest.Id}, lists {listed} fields; the manifest declares {item.Fields.Count}.");
        }

        if (contest.UndervoteDifferenceProof is { } undervote)
        {
            item.UndervoteDifferenceProof = Proofs(undervote);
        }

        if (contest.NullVoteProof is { } nullVote)
        {
            item.NullVoteProof = Proofs(nullVote);
        }

        if (contest.ContestData is { } data)
        {
            item.ContestData = Hashed(data.C0, data.C1, data.Challenge, data.Response);
        }

        return item;
    }

    /// <summary>Decodes an <c>encrypted_ballot</c> or <c>pre_encrypted_cast_ballot</c> item of the device <paramref name="deviceId"/>.</summary>
    public static RecordDecoded<DomainBallot> FromItem(Pb.RecordItem item, Manifest manifest, string deviceId)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(manifest);
        var context = new RecordDecodeContext();
        DomainBallot ballot = item.ItemCase switch
        {
            Pb.RecordItem.ItemOneofCase.EncryptedBallot => Regular(item.EncryptedBallot, manifest, deviceId, context),
            Pb.RecordItem.ItemOneofCase.PreEncryptedCastBallot => PreEncrypted(item.PreEncryptedCastBallot, manifest, deviceId, context),
            _ => throw new ArgumentException($"Item member {(int)item.ItemCase} is not a ballot item.", nameof(item)),
        };

        return context.Result(ballot);
    }

    private static DomainBallot Regular(Pb.EncryptedBallot item, Manifest manifest, string deviceId, RecordDecodeContext context)
    {
        string id = Id(item.BallotRef, item.IdB);

        // Verification 8 hashes the contests into H_C in index order (eq. 59).
        RequireAscending(item.Contests, x => x.Index, context, "8.structure", $"The contests of ballot {id}");
        return new DomainBallot
        {
            Id = id,
            SelectionEncryptionIdentifier = SelectionEncryptionIdentifier.FromCanonicalBytes(Require(item.IdB, 32, "id_B")),
            SelectionEncryptionIdentifierHash = SelectionEncryptionIdentifierHash.FromCanonicalBytes(RequireArray(item.HI, 32, "H_I")),
            BallotStyleId = item.BallotStyle,
            Status = (BallotStatus)(int)item.Status,
            // D4 refuses a uint32 of 2^31 or more before the mapper runs; the clamp only guards a caller that skipped the check.
            Weight = (int)Math.Min(item.Weight, int.MaxValue),
            EncryptionTimestamp = item.EncryptedAt is { } time ? Time(time) : null,
            Contests = item.Contests.Select(x => Contest(x, manifest, id, context)).ToList(),
            ConfirmationCode = ConfirmationCode.FromCanonicalBytes(RequireArray(item.ConfirmationCode, 32, "H_C")),
            ChainingField = ChainingField.FromCanonicalBytes(Require(item.ChainingField, ChainingField.ByteLength, "B_C")),
            EncryptedBallotNonce = BallotNonce(item.EncryptedBallotNonce, context, $"ballot {id}"),
            DeviceId = deviceId,
        };
    }

    private static DomainBallot PreEncrypted(Pb.PreEncryptedCastBallot item, Manifest manifest, string deviceId, RecordDecodeContext context)
    {
        string id = Id(item.BallotRef, item.IdB);

        // Verification 16 hashes the contests' χ into H_C in index order (eq. 116); 8 does not apply (p.64).
        RequireAscending(item.Contests, x => x.Contest?.Index ?? 0, context, "16.structure", $"The contests of pre-encrypted ballot {id}");
        var contests = item.Contests.Select(x => Contest(x.Contest ?? new Pb.EncryptedContest(), manifest, id, context)).ToList();
        return new DomainBallot
        {
            Id = id,
            SelectionEncryptionIdentifier = SelectionEncryptionIdentifier.FromCanonicalBytes(Require(item.IdB, 32, "id_B")),
            SelectionEncryptionIdentifierHash = SelectionEncryptionIdentifierHash.FromCanonicalBytes(RequireArray(item.HI, 32, "H_I")),
            BallotStyleId = item.BallotStyle,
            Status = BallotStatus.Cast,
            // D4 refuses a uint32 of 2^31 or more before the mapper runs; the clamp only guards a caller that skipped the check.
            Weight = (int)Math.Min(item.Weight, int.MaxValue),
            EncryptionTimestamp = item.EncryptedAt is { } time ? Time(time) : null,
            Contests = contests,
            ConfirmationCode = ConfirmationCode.FromCanonicalBytes(RequireArray(item.ConfirmationCode, 32, "H_C")),
            ChainingField = ChainingField.FromCanonicalBytes(Require(item.ChainingField, ChainingField.ByteLength, "B_C")),
            EncryptedBallotNonce = BallotNonce(item.EncryptedBallotNonce, context, $"ballot {id}"),
            DeviceId = deviceId,
            PreEncryptedContests = item.Contests.Zip(contests).Select(x => new PreEncryptedCastContest
            {
                ContestId = x.Second.Id,
                SelectionHashes = x.First.SelectionHashes.IsEmpty ? [] : Chunks(x.First.SelectionHashes, 32, "ψ").Select(SelectionHash.FromCanonicalBytes).ToList(),
                SelectedVectors = x.First.Selected.Select(v => new PreEncryptedCastSelection
                {
                    Vector = Vector(v.Vector, context, $"ballot {id}, contest {x.Second.Id}, selected vector"),
                    SelectionHash = SelectionHash.FromCanonicalBytes(RequireArray(v.Psi, 32, "ψ")),
                    ShortCode = new ShortCode(v.ShortCode),
                }).ToList(),
            }).ToList(),
        };
    }

    internal static string Id(string ballotRef, Google.Protobuf.ByteString identifier) =>
        ballotRef.Length > 0 ? ballotRef : Convert.ToHexStringLower(identifier.Span);

    private static DomainContest Contest(Pb.EncryptedContest item, Manifest manifest, string ballotId, RecordDecodeContext context)
    {
        var manifestContest = manifest.Contests.SingleOrDefault(x => x.Index == item.Index);
        string contestId = manifestContest?.Id ?? UnknownLabel("contest", item.Index);
        string where = $"ballot {ballotId}, contest {contestId}";
        var declared = manifestContest?.VerifiableFields().ToList() ?? [];
        var choices = new List<EncryptedSelection>();
        var supplemental = new List<EncryptedSupplementalField>();
        for (int position = 0; position < item.Fields.Count; position++)
        {
            var field = item.Fields[position];
            var label = position < declared.Count ? declared[position] : null;
            string fieldId = label?.Id ?? UnknownLabel("field", position + 1);
            string at = $"{where}, field {fieldId}";
            var alpha = context.Zp(Require(field.Alpha, 512, at + ": α"), RecordValueRanges.SelectionCiphertext, at + ": α");
            var beta = context.Zp(Require(field.Beta, 512, at + ": β"), RecordValueRanges.SelectionCiphertext, at + ": β");
            var proofs = Proofs(field.RangeProof, context, RecordValueRanges.SelectionChallenge, RecordValueRanges.SelectionResponse, at + ": range proof");
            if (label is SupplementalField)
            {
                supplemental.Add(new EncryptedSupplementalField { FieldId = fieldId, Alpha = alpha, Beta = beta, Proofs = proofs });
            }
            else
            {
                choices.Add(new EncryptedSelection { ChoiceId = fieldId, Alpha = alpha, Beta = beta, Proofs = proofs });
            }
        }

        EncryptedContestData? data = null;
        if (item.ContestData is { } hashed)
        {
            var c2 = Require(hashed.C2, 64, where + ": contest data C_2");
            data = new EncryptedContestData
            {
                C0 = context.Zp(Require(hashed.C0, 512, where + ": contest data C_0"), RecordValueRanges.ContestData, where + ": contest data C_0"),
                C1 = RequireArray(hashed.C1, 32, where + ": contest data C_1", multiple: true),
                Challenge = context.Zq(c2[..32], RecordValueRanges.ContestData, where + ": contest data c"),
                Response = context.Zq(c2[32..], RecordValueRanges.ContestData, where + ": contest data v"),
            };
        }

        return new DomainContest
        {
            Id = contestId,
            Choices = choices,
            SupplementalFields = supplemental,
            Proofs = Proofs(item.LimitProof, context, RecordValueRanges.ContestChallenge, RecordValueRanges.ContestResponse, where + ": limit proof"),
            UndervoteDifferenceProof = item.UndervoteDifferenceProof.IsEmpty ? null : Proofs(item.UndervoteDifferenceProof, context, RecordValueRanges.ContestChallenge, RecordValueRanges.ContestResponse, where + ": undervote difference proof"),
            NullVoteProof = item.NullVoteProof.IsEmpty ? null : Proofs(item.NullVoteProof, context, RecordValueRanges.ContestChallenge, RecordValueRanges.ContestResponse, where + ": null-vote proof"),
            ContestData = data,
            ContestHash = ContestHash.FromCanonicalBytes(RequireArray(item.ContestHash, 32, where + ": χ")),
        };
    }
}
