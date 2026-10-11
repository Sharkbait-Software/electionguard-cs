using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;
using Google.Protobuf;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordTamper;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-9: one targeted failure per verification and per join rule, each reported under its
/// sub-section at its item while every other verification still runs (design §6.9: findings are
/// collected, not stop-on-first). Each tamper keeps the item canonical and rewrites the claimed TOC, so
/// the check it targets catches it, not <c>R.root</c>. Every report is the same single-threaded (one
/// item per batch) and in parallel (the default batch bound: a whole device section per batch, its
/// items verified concurrently).
/// </summary>
public class ElectionRecordVerifierFailureTests
{
    public ElectionRecordVerifierFailureTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    // The regular test election: device-1 holds ballot-1 (cast), ballot-2 (cast, weight 2),
    // ballot-3 (spoiled), ballot-4 (challenged) at positions 1-4; device-2 holds ballot-5 (cast).
    // Contest data is requested and decrypted for ballot-1 and ballot-5; ballot-4 is decrypted.
    public static TheoryData<string, string, ushort, long?> RegularRows => new()
    {
        // Verification, the setup.
        { "a guardian's vote proof response changed", "2.C", 0x0004, 0 },
        // Verifications 5-8 on one ballot item.
        { "a selection range proof's response changed", "6.D", 0x0101, 2 },
        { "a contest's limit proof changed", "7.D", 0x0101, 1 },
        { "a contest hash changed", "8.A", 0x0101, 2 },
        { "a ballot's chaining field changed", "8.B", 0x0101, 2 },
        { "the spoiled ballot's id_B made the first cast ballot's", "5.A", 0x0101, 3 },
        { "the challenged ballot's id_B made the first cast ballot's", "5.A", 0x0101, 4 },
        // The once-per-device chain checks, reported at the header or the close (design §6.2).
        { "the S_device in device-1's header changed", "8.C", 0x0101, 0 },
        { "the initial hash in device-1's header changed", "8.F", 0x0101, 0 },
        { "the closing hash in device-1's close changed", "8.G", 0x0101, 5 },
        // The tally.
        { "an aggregate A changed", "9.A", 0x0201, 0 },
        { "the tally header's ballot count changed", RecordCodes.Summary, 0x0201, 0 },
        { "a decrypted count's proof response changed", "10.B", 0x0301, 0 },
        { "a decrypted tally option label changed", "11.B", 0x0301, 0 },
        // The join sections.
        { "the challenged ballot's decryption removed", "13.structure", 0x0101, 4 },
        { "a challenged decryption's nonce changed", "13.B", 0x0302, 0 },
        { "a challenged decryption moved to the cast ballot-1", "13.structure", 0x0302, 0 },
        { "a challenged decryption moved to the spoiled ballot-3", "13.structure", 0x0302, 0 },
        { "two labels of a challenged decryption swapped", "14.structure", 0x0302, 0 },
        { "a contest-data decryption's proof changed", "12.B", 0x0303, 0 },
        { "a contest-data request removed", "12.structure", 0x0303, 0 },
        { "a contest-data decryption removed", "12.structure", 0x0202, 0 },
        { "the contest-data requests swapped", RecordCodes.Order, 0x0202, 1 },
        // Device sections.
        { "an item type of a newer minor in a device section, in a newer-minor record", RecordCodes.Version, 0x0101, 1 },
        { "a device close that counts one ballot too many", "8.structure", 0x0101, 2 },
        { "a device header naming the other device kind", "8.structure", 0x0101, 0 },
    };

    [Theory]
    [MemberData(nameof(RegularRows))]
    public async Task AFailureInTheRegularRecord_IsReportedAtItsItem_AndEveryVerificationStillRuns(string tamper, string code, ushort section, long? ordinal)
    {
        string directory = TempDirectory("verify-fail");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var devices = await DevicesAsync(directory);
        var one = SectionKey.Device(devices["device-1"]);
        var two = SectionKey.Device(devices["device-2"]);
        await TamperRegular(directory, tamper, one, two);
        await ReTocAsync(directory);

        var report = await VerifyAsync(directory, 1);
        var parallel = await VerifyAsync(directory, -1);
        Assert.Equal(ElectionRecordVerifierTests.Canonical(report), ElectionRecordVerifierTests.Canonical(parallel));
        Assert.Equal(ElectionRecordVerifierTests.Canonical(report), ElectionRecordVerifierTests.Canonical(await VerifyAsync(directory, 4)));

        Assert.False(report.Passed);
        var deviceOf = section == 0x0101 ? (tamper.Contains("newer minor") || tamper.Contains("too many") || tamper.Contains("device header") ? two : one) : default;
        Assert.Equal(!tamper.Contains("newer-minor record"), report.Complete);
        Assert.True(report.Findings.Any(x => x.SubSection == code && (ushort)x.Section!.Value.Type == section
                && (ordinal is null || x.Ordinal == ordinal)
                && (section != 0x0101 || x.Section.Value == deviceOf)),
            $"{tamper}: no {code} at 0x{section:x4}#{ordinal}.\n{ElectionRecordVerifierTests.Describe(report)}");
        Assert.DoesNotContain(report.Findings, x => x.Message.Contains("could not be evaluated on a malformed item"));
        Assert.DoesNotContain(report.Findings, x => x.SubSection == RecordCodes.Root);
        if (tamper == "a ballot's chaining field changed")
        {
            // The device walk sees the same change: B_C,2 is no longer 0x00000001 || H_1.
            Assert.Contains(report.Findings, x => x.SubSection == "8.E" && x.Section == one && x.Ordinal == 2);
        }

        foreach (var v in Enumerable.Range(1, 14))
        {
            Assert.True(report.Verifications[v] is not VerificationOutcome.NotRun && (report.Verifications[v] != VerificationOutcome.NotApplicable || v is 13 or 14), $"{tamper}: V{v} {report.Verifications[v]}");
        }

        // Collected, not stop-on-first: Verification 1 still passed after a later failure.
        Assert.Equal(VerificationOutcome.Passed, report.Verifications[1]);
        int verification = code.StartsWith("R.") ? 0 : int.Parse(code[..code.IndexOf('.')]);
        if (verification > 0)
        {
            Assert.Equal(VerificationOutcome.Failed, report.Verifications[verification]);
        }
    }

    private static async Task TamperRegular(string directory, string tamper, SectionKey one, SectionKey two)
    {
        switch (tamper)
        {
            case "a guardian's vote proof response changed":
                Edit(directory, RecordSectionType.Guardians, items => items[0].GuardianPublicKey.VoteProof = Flip(items[0].GuardianPublicKey.VoteProof));
                break;
            case "a selection range proof's response changed":
                Edit(directory, one, items => { var f = items[2].EncryptedBallot.Contests[0].Fields[0]; f.RangeProof = Flip(f.RangeProof); });
                break;
            case "a contest's limit proof changed":
                Edit(directory, one, items => { var c = items[1].EncryptedBallot.Contests[0]; c.LimitProof = Flip(c.LimitProof); });
                break;
            case "a contest hash changed":
                Edit(directory, one, items => { var c = items[2].EncryptedBallot.Contests[0]; c.ContestHash = Flip(c.ContestHash); });
                break;
            case "a ballot's chaining field changed":
                // B_C enters H_C (8.B), and the chain walk (8.E) then fails at this ballot too.
                Edit(directory, one, items => items[2].EncryptedBallot.ChainingField = Flip(items[2].EncryptedBallot.ChainingField));
                break;
            case "the spoiled ballot's id_B made the first cast ballot's":
                Edit(directory, one, items => items[3].EncryptedBallot.IdB = items[1].EncryptedBallot.IdB);
                break;
            case "the challenged ballot's id_B made the first cast ballot's":
                Edit(directory, one, items => items[4].EncryptedBallot.IdB = items[1].EncryptedBallot.IdB);
                break;
            case "the S_device in device-1's header changed":
                Edit(directory, one, items => items[0].DeviceHeader.DeviceId += "-renamed");
                break;
            case "the initial hash in device-1's header changed":
                Edit(directory, one, items => items[0].DeviceHeader.InitialHash = Flip(items[0].DeviceHeader.InitialHash));
                break;
            case "the closing hash in device-1's close changed":
                Edit(directory, one, items => items[^1].DeviceClose.ClosingHash = Flip(items[^1].DeviceClose.ClosingHash));
                break;
            case "an aggregate A changed":
                Edit(directory, RecordSectionType.EncryptedTally, items => items[1].EncryptedTallyContest.Fields = Flip(items[1].EncryptedTallyContest.Fields, 513));
                break;
            case "the tally header's ballot count changed":
                Edit(directory, RecordSectionType.EncryptedTally, items => items[0].EncryptedTallyHeader.CastBallotCount++);
                break;
            case "a decrypted count's proof response changed":
                Edit(directory, RecordSectionType.DecryptedTally, items => items[0].DecryptedTallyContest.Fields[0].Proof = Flip(items[0].DecryptedTallyContest.Fields[0].Proof));
                break;
            case "a decrypted tally option label changed":
                Edit(directory, RecordSectionType.DecryptedTally, items => items[0].DecryptedTallyContest.Fields[0].Label += "-relabelled");
                break;
            case "the challenged ballot's decryption removed":
                Edit(directory, RecordSectionType.ChallengedBallotDecryptions, items => items.RemoveAt(0));
                break;
            case "a challenged decryption's nonce changed":
                Edit(directory, RecordSectionType.ChallengedBallotDecryptions, items => { var f = items[0].ChallengedBallotDecryption.Contests[0].Fields[0]; f.Nonce = Flip(f.Nonce); });
                break;
            case "a challenged decryption moved to the cast ballot-1":
            case "a challenged decryption moved to the spoiled ballot-3":
                ulong position = tamper.Contains("ballot-1") ? 1UL : 3UL;
                byte[] hI = [];
                Edit(directory, one, items => hI = items[(int)position].EncryptedBallot.HI.ToByteArray());
                Edit(directory, RecordSectionType.ChallengedBallotDecryptions, items =>
                {
                    items[0].ChallengedBallotDecryption.Ballot.Position = position;
                    items[0].ChallengedBallotDecryption.HI = ByteString.CopyFrom(hI);
                });
                break;
            case "two labels of a challenged decryption swapped":
                Edit(directory, RecordSectionType.ChallengedBallotDecryptions, items =>
                {
                    var fields = items[0].ChallengedBallotDecryption.Contests[0].Fields;
                    (fields[0].Label, fields[1].Label) = (fields[1].Label, fields[0].Label);
                });
                break;
            case "a contest-data decryption's proof changed":
                Edit(directory, RecordSectionType.ContestDataDecryptions, items => items[0].ContestDataDecryption.Proof = Flip(items[0].ContestDataDecryption.Proof));
                break;
            case "a contest-data request removed":
                // Its decryption is then one nothing requested (follow-up #10).
                Edit(directory, RecordSectionType.ContestDataRequests, items => items.RemoveAt(0));
                break;
            case "a contest-data decryption removed":
                Edit(directory, RecordSectionType.ContestDataDecryptions, items => items.RemoveAt(0));
                break;
            case "the contest-data requests swapped":
                Edit(directory, RecordSectionType.ContestDataRequests, items => (items[0], items[1]) = (items[1], items[0]));
                break;
            case "an item type of a newer minor in a device section, in a newer-minor record":
                // RecordItem member 60, which a later minor may add, before device-2's ballot. At the
                // record's own minor it would be R.encoding (W6); in a minor-1 record it is canonical
                // content this reader cannot verify, in a section that must verify (design §7).
                Edit(directory, RecordSectionType.Header, items => items[0].RecordHeader.FormatMinor = 1);
                Edit(directory, two, items => items.Insert(1, Pb.RecordItem.Parser.ParseFrom([0xE2, 0x03, 0x02, 0x08, 0x05])));
                break;
            case "a device header naming the other device kind":
                // Not the section's key: the device's chain cannot be walked (V8 not evaluable on it), its
                // ballots are still verified one by one.
                Edit(directory, two, items => items[0].DeviceHeader.Kind = Pb.DeviceKind.PreEncrypting);
                break;
            case "a device close that counts one ballot too many":
                Edit(directory, two, items => items[^1].DeviceClose.BallotCount++);
                break;
            default:
                throw new ArgumentException(tamper);
        }

        await Task.CompletedTask;
    }

    // The pre-encrypted test election: one pre-encrypting device holding, in print order, a cast
    // ballot (1), an uncast ballot in full (2), a never-returned compact one (3), a returned compact
    // one whose ξ_B was released (4) and a cast ballot (5).
    public static TheoryData<string, string, ushort, long?> PreEncryptedRows => new()
    {
        { "a full uncast ballot's short code changed", "17.A", 0x0101, 2 },
        { "a full uncast ballot's option label changed", "19.C", 0x0101, 2 },
        { "a full uncast release's nonce changed", "18.A", 0x0304, 0 },
        { "a compact uncast ballot's contest hash changed", "16.B", 0x0101, 3 },
        { "a compact uncast release's ξ_B changed", "16.B", 0x0101, 4 },
        { "an uncast release removed", "18.structure", 0x0101, 2 },
        // Without its release a full uncast item is still checked from its printed content.
        { "an uncast release removed and the full ballot's selection hash changed", "16.A", 0x0101, 2 },
        { "an uncast release removed and the full ballot's short code changed", "17.A", 0x0101, 2 },
        { "an uncast release removed and the full ballot's option label changed", "19.C", 0x0101, 2 },
        // Without its release a compact item has no vectors: 6, 16.A-B, 17 and 19 are not evaluable
        // on it, but its 16.C runs on the printed χ, B_C and H_C.
        { "the returned compact ballot's release removed", "18.structure", 0x0101, 4 },
        { "the returned compact ballot's release removed and its confirmation code changed", "16.C", 0x0101, 4 },
        { "an uncast release moved to a cast ballot", "18.structure", 0x0304, 0 },
        { "a cast ballot's selection hash changed", "16.A", 0x0101, 5 },
        { "a cast ballot's combined vector changed", "15.A", 0x0101, 1 },
        // 5.A covers uncast ballots too (§4.5 p.64: "the full set of ballots").
        { "the never-returned compact ballot's id_B made the cast ballot's", "5.A", 0x0101, 3 },
        // The once-per-device chain checks of a pre-encrypting device.
        { "the device header's initial hash changed", "16.G", 0x0101, 0 },
        { "the device close's closing hash changed", "16.H", 0x0101, 6 },
        { "the S_device in the pre-encrypting header changed", "16.D", 0x0101, 0 },
        // The link the walk checks (16.F); the ballot's own H_C (16.C) is recomputed from it too.
        { "a pre-encrypted ballot's chaining field changed", "16.F", 0x0101, 5 },
    };

    [Theory]
    [MemberData(nameof(PreEncryptedRows))]
    public async Task AFailureInThePreEncryptedRecord_IsReportedAtItsItem(string tamper, string code, ushort section, long? ordinal)
    {
        string directory = TempDirectory("verify-fail-pre");
        await WriteAsync(PreEncryptedRecord.Value, directory, RecordEncoding.Protobuf);
        var device = SectionKey.Device((await DevicesAsync(directory)).Values.Single());
        switch (tamper)
        {
            case "a full uncast ballot's short code changed":
                Edit(directory, device, items =>
                {
                    var selection = items[2].PreEncryptedUncastBallot.Contests[0].Selections[0];
                    selection.ShortCode = selection.ShortCode == "AA" ? "AB" : "AA";
                });
                break;
            case "a full uncast ballot's option label changed":
                Edit(directory, device, items => items[2].PreEncryptedUncastBallot.Contests[0].Selections[0].OptionLabel += "-relabelled");
                break;
            case "a full uncast release's nonce changed":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items[0].UncastNonceRelease.Contests[0].Nonces = Flip(items[0].UncastNonceRelease.Contests[0].Nonces));
                break;
            case "a compact uncast ballot's contest hash changed":
                Edit(directory, device, items => items[3].PreEncryptedCompactUncastBallot.Contests[0].ContestHash = Flip(items[3].PreEncryptedCompactUncastBallot.Contests[0].ContestHash));
                break;
            case "a compact uncast release's ξ_B changed":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items[2].UncastNonceRelease.BallotNonce = Flip(items[2].UncastNonceRelease.BallotNonce));
                break;
            case "an uncast release removed":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items.RemoveAt(0));
                break;
            case "an uncast release removed and the full ballot's selection hash changed":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items.RemoveAt(0));
                Edit(directory, device, items => { var s = items[2].PreEncryptedUncastBallot.Contests[0].Selections[0]; s.Psi = Flip(s.Psi); });
                break;
            case "an uncast release removed and the full ballot's short code changed":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items.RemoveAt(0));
                Edit(directory, device, items =>
                {
                    var selection = items[2].PreEncryptedUncastBallot.Contests[0].Selections[0];
                    selection.ShortCode = selection.ShortCode == "AA" ? "AB" : "AA";
                });
                break;
            case "an uncast release removed and the full ballot's option label changed":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items.RemoveAt(0));
                Edit(directory, device, items => items[2].PreEncryptedUncastBallot.Contests[0].Selections[0].OptionLabel += "-relabelled");
                break;
            case "the returned compact ballot's release removed":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items.RemoveAt(2));
                break;
            case "the returned compact ballot's release removed and its confirmation code changed":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items.RemoveAt(2));
                Edit(directory, device, items => items[4].PreEncryptedCompactUncastBallot.ConfirmationCode = Flip(items[4].PreEncryptedCompactUncastBallot.ConfirmationCode));
                break;
            case "an uncast release moved to a cast ballot":
                Edit(directory, RecordSectionType.UncastNonceReleases, items => items[0].UncastNonceRelease.Ballot.Position = 1);
                break;
            case "a cast ballot's combined vector changed":
                Edit(directory, device, items =>
                {
                    var field = items[1].PreEncryptedCastBallot.Contests[0].Contest.Fields[0];
                    field.Alpha = Flip(field.Alpha);
                });
                break;
            case "a cast ballot's selection hash changed":
                Edit(directory, device, items =>
                {
                    var selected = items[5].PreEncryptedCastBallot.Contests[0].Selected[0];
                    selected.Psi = Flip(selected.Psi);
                });
                break;
            case "the never-returned compact ballot's id_B made the cast ballot's":
                Edit(directory, device, items => items[3].PreEncryptedCompactUncastBallot.IdB = items[1].PreEncryptedCastBallot.IdB);
                break;
            case "the device header's initial hash changed":
                Edit(directory, device, items => items[0].DeviceHeader.InitialHash = Flip(items[0].DeviceHeader.InitialHash));
                break;
            case "the device close's closing hash changed":
                Edit(directory, device, items => items[^1].DeviceClose.ClosingHash = Flip(items[^1].DeviceClose.ClosingHash));
                break;
            case "the S_device in the pre-encrypting header changed":
                Edit(directory, device, items => items[0].DeviceHeader.DeviceId += "-renamed");
                break;
            case "a pre-encrypted ballot's chaining field changed":
                Edit(directory, device, items => items[5].PreEncryptedCastBallot.ChainingField = Flip(items[5].PreEncryptedCastBallot.ChainingField));
                break;
            default:
                throw new ArgumentException(tamper);
        }

        await ReTocAsync(directory);
        var report = await VerifyAsync(directory, 1);
        Assert.Equal(ElectionRecordVerifierTests.Canonical(report), ElectionRecordVerifierTests.Canonical(await VerifyAsync(directory, -1)));
        Assert.Equal(ElectionRecordVerifierTests.Canonical(report), ElectionRecordVerifierTests.Canonical(await VerifyAsync(directory, 4)));
        Assert.False(report.Passed);
        Assert.True(report.Findings.Any(x => x.SubSection == code && (ushort)x.Section!.Value.Type == section && (ordinal is null || x.Ordinal == ordinal)),
            $"{tamper}: no {code} at 0x{section:x4}#{ordinal}.\n{ElectionRecordVerifierTests.Describe(report)}");
        Assert.DoesNotContain(report.Findings, x => x.Message.Contains("could not be evaluated on a malformed item"));
        Assert.DoesNotContain(report.Findings, x => x.SubSection == RecordCodes.Root);
        if (tamper == "a pre-encrypted ballot's chaining field changed")
        {
            Assert.Contains(report.Findings, x => x.SubSection == "16.C" && x.Section == device && x.Ordinal == 5);
        }

        if (tamper == "the returned compact ballot's release removed")
        {
            // Never Passed over an item they did not run on; 16.C ran on it and held.
            foreach (var v in new[] { 6, 16, 17, 19 })
            {
                Assert.True(report.Verifications[v] == VerificationOutcome.NotEvaluable, $"V{v} {report.Verifications[v]}\n{ElectionRecordVerifierTests.Describe(report)}");
            }

            Assert.DoesNotContain(report.Findings, x => x.SubSection.StartsWith("16.", StringComparison.Ordinal));
        }

        // Collected, not stop-on-first: every verification that applies to this record still ran.
        Assert.Equal(VerificationOutcome.Passed, report.Verifications[1]);
        foreach (var v in new[] { 5, 6, 7, 9, 10, 11, 15, 16, 17, 18, 19 })
        {
            Assert.True(report.Verifications[v] is not (VerificationOutcome.NotRun or VerificationOutcome.NotApplicable), $"{tamper}: V{v} {report.Verifications[v]}");
        }

        int verification = code.StartsWith("R.") ? 0 : int.Parse(code[..code.IndexOf('.')]);
        if (verification > 0)
        {
            Assert.Equal(VerificationOutcome.Failed, report.Verifications[verification]);
        }
    }

    /// <summary>
    /// 5.A covers every submitted ballot whatever its status (§4.5 p.64): a spoiled ballot sharing
    /// id_B with a cast one fails 5.A naming both locators, and is still in 11.D and out of V9.
    /// </summary>
    [Fact]
    public async Task ASpoiledBallotSharingIdBWithACastOne_Fails5A_NamingBoth_AndStaysOutOfTheTally()
    {
        string directory = TempDirectory("verify-5a");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var one = SectionKey.Device((await DevicesAsync(directory))["device-1"]);
        Edit(directory, one, items => items[3].EncryptedBallot.IdB = items[1].EncryptedBallot.IdB);
        await ReTocAsync(directory);

        var report = await VerifyAsync(directory, -1);
        var duplicate = Assert.Single(report.Findings, x => x.SubSection == "5.A");
        Assert.Equal((one, 3L), (duplicate.Section!.Value, duplicate.Ordinal!.Value));
        Assert.Contains("position 1 of device", duplicate.Message);
        Assert.Contains("position 3 of device", duplicate.Message);
        Assert.Contains(report.Findings, x => x.SubSection == "5.B" && x.Ordinal == 3);
        Assert.Equal(VerificationOutcome.Passed, report.Verifications[9]);
        Assert.Equal(VerificationOutcome.Passed, report.Verifications[11]);
    }

    /// <summary>
    /// Design §6.1 step B: a Verification 1 failure (H_P changed) or a Verification 4 failure (K
    /// changed: 3.A, and H_E no longer hashes it, 4.A) stops all cryptography: Verifications 5-19 are
    /// not evaluable, while 2-4 are reported and the roots are still checked.
    /// </summary>
    [Theory]
    [InlineData("H_P", "1.E")]
    [InlineData("K", "3.A")]
    public async Task ASetupFailure_StopsTheCryptography_AndIsReportedUnderItsCode(string value, string code)
    {
        string directory = TempDirectory("verify-setup");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        if (value == "H_P")
        {
            Edit(directory, RecordSectionType.Parameters, items => items[0].Parameters.HP = Flip(items[0].Parameters.HP));
        }
        else
        {
            Edit(directory, RecordSectionType.ElectionKeys, items => items[0].ElectionKeys.K = Flip(items[0].ElectionKeys.K));
        }

        await ReTocAsync(directory);
        var report = await VerifyAsync(directory, -1);
        Assert.Contains(report.Findings, x => x.SubSection == code);
        if (value == "K")
        {
            Assert.Contains(report.Findings, x => x.SubSection == "4.A");
            Assert.Equal(VerificationOutcome.Passed, report.Verifications[1]);
        }

        Assert.True(report.RootsMatchClaimedToc);
        foreach (var v in Enumerable.Range(5, 15))
        {
            Assert.True(report.Verifications[v] is VerificationOutcome.NotEvaluable, $"V{v} {report.Verifications[v]}");
        }
    }

    /// <summary>A record whose stored manifest is not a manifest: a report (no exception), 1.structure, and every later verification not evaluable while the roots are still checked.</summary>
    [Fact]
    public async Task AManifestThatDoesNotParse_StopsTheCryptography_ButNotTheRun()
    {
        string directory = TempDirectory("verify-manifest");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf, new ElectionRecordWriterOptions { WriteManifestCopy = false });
        Edit(directory, RecordSectionType.Manifest, items => items[0].ManifestFile.Content = ByteString.CopyFromUtf8("{}"));
        await ReTocAsync(directory);

        var report = await VerifyAsync(directory, -1);
        Assert.Contains(report.Findings, x => x.SubSection == "1.structure");
        Assert.True(report.RootsMatchClaimedToc);
        foreach (var v in Enumerable.Range(5, 15))
        {
            Assert.True(report.Verifications[v] is VerificationOutcome.NotEvaluable, $"V{v} {report.Verifications[v]}");
        }
    }

    /// <summary>
    /// Single-threaded with one item per batch (1); in parallel with the default batch bound (-1),
    /// which holds a whole test device section in one batch, so its items' workers run concurrently;
    /// or with that many workers and one item per batch (any other value), which runs the read-ahead:
    /// the next batch is read while the workers verify the current one (S10b-F review round 1).
    /// </summary>
    internal static async Task<VerificationReport> VerifyAsync(string directory, int parallelism)
    {
        await using var reader = await ElectionRecord.OpenAsync(directory);
        return await ElectionRecordVerifier.VerifyAllAsync(reader, parallelism switch
        {
            1 => new VerifyAllOptions { MaxDegreeOfParallelism = 1, BatchBytes = 1 },
            -1 => new VerifyAllOptions { MaxDegreeOfParallelism = -1 },
            _ => new VerifyAllOptions { MaxDegreeOfParallelism = parallelism, BatchBytes = 1 },
        });
    }
}
