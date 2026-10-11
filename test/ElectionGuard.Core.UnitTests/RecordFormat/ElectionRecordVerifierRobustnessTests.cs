using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;
using Google.Protobuf;
using System.Runtime.CompilerServices;
using static ElectionGuard.Core.UnitTests.RecordFormat.ElectionRecordVerifierTests;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordTamper;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-D review round 1: the record verifier reports, never throws, on what a record's publisher
/// controls (a torn join section, a non-canonical identifier in 5.A's confirmation pass, an
/// unreadable signature file, a status of a newer minor); the guardian profile on pre-encrypted
/// ballots; the guardians' view read twice; the options; and parallel batches compared with
/// single-threaded ones over a record with several findings in one section.
/// </summary>
public class ElectionRecordVerifierRobustnessTests
{
    public ElectionRecordVerifierRobustnessTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static Task<VerificationReport> VerifyAsync(string directory, int parallelism) => ElectionRecordVerifierFailureTests.VerifyAsync(directory, parallelism);

    private static async Task<VerificationReport> VerifyAsync(string directory, VerifyAllOptions options)
    {
        await using var reader = await ElectionRecord.OpenAsync(directory);
        return await ElectionRecordVerifier.VerifyAllAsync(reader, options);
    }

    private static async Task<(VerificationReport Report, VerifiedAggregate? Aggregate)> VerifyAggregatedAsync(string directory)
    {
        await using var reader = await ElectionRecord.OpenAsync(directory);
        return await ElectionRecordVerifier.VerifyAggregatedAsync(reader, new VerifyAllOptions());
    }

    // ---- 5.A's confirmation pass ---------------------------------------------------------------

    /// <summary>
    /// A planted duplicate id_B forces 5.A's confirmation pass, which re-reads every device section.
    /// Beside it, a non-canonical ballot item whose id_b is 65 bytes (a width violation, never added
    /// to the set), or another device section cut mid-frame: the report holds 5.A and the R-code,
    /// and the run does not throw.
    /// </summary>
    [Theory]
    [InlineData("a 65-byte id_b on a non-canonical item", RecordCodes.Encoding)]
    [InlineData("another device section cut mid-frame", RecordCodes.Container)]
    public async Task TheConfirmationPass_ReportsBesideARecordFault_InsteadOfThrowing(string fault, string code)
    {
        string directory = TempDirectory("verify-5a-fault");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var devices = await DevicesAsync(directory);
        var one = SectionKey.Device(devices["device-1"]);
        var two = SectionKey.Device(devices["device-2"]);
        Edit(directory, one, items => items[3].EncryptedBallot.IdB = items[1].EncryptedBallot.IdB);
        if (fault.StartsWith("a 65-byte"))
        {
            Edit(directory, one, items => items[2].EncryptedBallot.IdB = ByteString.CopyFrom(new byte[65]));
        }

        await ReTocAsync(directory);
        if (fault.StartsWith("another"))
        {
            string segment = PathOf(directory, two);
            File.WriteAllBytes(segment, File.ReadAllBytes(segment)[..^7]);
        }

        var report = await VerifyAsync(directory, -1);
        var duplicate = Assert.Single(report.Findings, x => x.SubSection == "5.A");
        Assert.Equal((one, 3L), (duplicate.Section!.Value, duplicate.Ordinal!.Value));
        Assert.Contains(report.Findings, x => x.SubSection == code && x.Section == (code == RecordCodes.Encoding ? one : two));
        Assert.Equal(Canonical(report), Canonical(await VerifyAsync(directory, 1)));
    }

    // ---- join sections that cannot be read to their end ----------------------------------------

    /// <summary>
    /// A carrier or line failure in a join section (a JSON line cut in half, which the JSON lines
    /// rule makes <c>R.encoding</c>; a torn protobuf frame, <c>R.container</c>) is reported at the
    /// section, which then has no root (<c>R.root</c> against the claimed TOC), and every other
    /// verification still runs. A ballot joined after the failure has its join items unknown: its
    /// verifications on them are not evaluable, not a "missing" finding.
    /// </summary>
    [Theory]
    [InlineData("challenged decryptions, last JSON line cut in half", RecordCodes.Encoding)]
    [InlineData("contest-data requests, last frame torn", RecordCodes.Container)]
    [InlineData("uncast nonce releases, last frame torn", RecordCodes.Container)]
    public async Task AJoinSectionThatCannotBeReadToItsEnd_IsAFinding_AndTheRunGoesOn(string fault, string code)
    {
        string directory = TempDirectory("verify-torn-join");
        bool json = fault.Contains("JSON");
        bool pre = fault.StartsWith("uncast");
        if (pre)
        {
            await WriteAsync(PreEncryptedRecord.Value, directory, RecordEncoding.Protobuf);
        }
        else
        {
            await WriteAsync(RegularElection.Value, directory, json ? RecordEncoding.Json : RecordEncoding.Protobuf);
        }

        var section = SectionKey.Of(fault.StartsWith("challenged") ? RecordSectionType.ChallengedBallotDecryptions
            : fault.StartsWith("contest") ? RecordSectionType.ContestDataRequests
            : RecordSectionType.UncastNonceReleases);
        string path = Path.Combine(directory, RecordLayout.SegmentPath(section, 0, json ? RecordEncoding.Json : RecordEncoding.Protobuf));
        byte[] bytes = File.ReadAllBytes(path);
        if (json)
        {
            int end = bytes[^1] == (byte)'\n' ? bytes.Length - 1 : bytes.Length;
            int start = Array.LastIndexOf(bytes, (byte)'\n', end - 1) + 1;
            File.WriteAllBytes(path, bytes[..(start + (end - start) / 2)]);
        }
        else
        {
            File.WriteAllBytes(path, bytes[..^7]);
        }

        var report = await VerifyAsync(directory, -1);
        Assert.Equal(Canonical(report), Canonical(await VerifyAsync(directory, 1)));
        Assert.False(report.Passed);
        // Reported once: the drain notes the section unreadable, so step F does not digest it again.
        Assert.Single(report.Findings, x => x.SubSection == code && x.Section == section);
        Assert.Contains(report.Findings, x => x.SubSection == RecordCodes.Root && x.Section == section);
        Assert.Equal(VerificationOutcome.Passed, report.Verifications[1]);
        Assert.DoesNotContain(report.Findings, x => x.Message.Contains("has no decryption") || x.Message.Contains("has no nonce release") || x.Message.Contains("has no request"));
        foreach (var v in pre ? new[] { 5, 7, 9, 15 } : new[] { 5, 6, 7, 8, 9, 10, 11 })
        {
            Assert.True(report.Verifications[v] == VerificationOutcome.Passed, $"V{v} {report.Verifications[v]}\n{Describe(report)}");
        }

        int unknown = fault.StartsWith("challenged") ? 13 : fault.StartsWith("contest") ? 12 : 18;
        Assert.Equal(VerificationOutcome.NotEvaluable, report.Verifications[unknown]);
    }

    // ---- an enum value of a newer minor ---------------------------------------------------------

    /// <summary>
    /// Design §7, "Enum value": a regular ballot recorded with a status a newer minor added (4) is
    /// content this reader does not understand. It is R.version at the item, Verification 9 (it may be
    /// cast), 12 (its request) and 13/14 (it may be a challenged ballot without its decryption) are not
    /// evaluable, never passed, and the record is incomplete;
    /// Verifications 5-8, which do not read the status, still pass.
    /// </summary>
    [Fact]
    public async Task ABallotStatusOfANewerMinor_IsRVersion_AndLeavesTheChecksThatDependOnItNotEvaluable()
    {
        string directory = TempDirectory("verify-status");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var one = SectionKey.Device((await DevicesAsync(directory))["device-1"]);
        Edit(directory, RecordSectionType.Header, items => items[0].RecordHeader.FormatMinor = 1);
        Edit(directory, one, items => items[1].EncryptedBallot.Status = (Pb.BallotStatus)4);
        await ReTocAsync(directory);

        var report = await VerifyAsync(directory, -1);
        Assert.Equal(Canonical(report), Canonical(await VerifyAsync(directory, 1)));
        Assert.False(report.Passed);
        Assert.False(report.Complete);
        var finding = Assert.Single(report.Findings);
        Assert.Equal((RecordCodes.Version, one, 1L), (finding.SubSection, finding.Section!.Value, finding.Ordinal!.Value));
        Assert.Contains("status 4", finding.Message);
        // 13 and 14: whether every challenged ballot was decrypted (#8) cannot be decided either.
        foreach (var v in new[] { 9, 12, 13, 14 })
        {
            Assert.Equal(VerificationOutcome.NotEvaluable, report.Verifications[v]);
        }

        foreach (var v in new[] { 5, 6, 7, 8, 10, 11 })
        {
            Assert.True(report.Verifications[v] == VerificationOutcome.Passed, $"V{v} {report.Verifications[v]}\n{Describe(report)}");
        }

        var (_, aggregate) = await VerifyAggregatedAsync(directory);
        Assert.Null(aggregate);
    }

    /// <summary>
    /// User decision NQ-9 ("DeviceKind closed, others open", 2026-10-10): <c>DeviceKind</c> is closed
    /// like <c>SectionType</c>, so kind 3 is D2 wherever it occurs, in a record of any minor (here a
    /// newer one, where an open enum's value would be content not understood). The item is not
    /// canonical: R.encoding at that item, its leaf still digested (the TOC rewritten over it agrees),
    /// the record incomplete (minor 1), and nothing throws. A join item that is not canonical joins
    /// nothing, so the ballot whose item it was has none (its structure code); a device header that is
    /// not canonical leaves the chain unwalked. (Until S10b-E, kind 3 in a join item was R.version and
    /// a header of kind 3 was the device's 8.structure.)
    /// </summary>
    [Theory]
    [InlineData("device-1's header")]
    [InlineData("the challenged ballot's decryption")]
    [InlineData("the full uncast ballot's release")]
    public async Task AnUndeclaredDeviceKind_IsD2_InARecordOfANewerMinor_AndNeverThrows(string where)
    {
        string directory = TempDirectory("verify-device-kind");
        SectionKey section;
        DeviceKey? deviceKey = null;
        if (where == "the full uncast ballot's release")
        {
            await WriteAsync(PreEncryptedRecord.Value, directory, RecordEncoding.Protobuf);
            section = SectionKey.Of(RecordSectionType.UncastNonceReleases);
            Edit(directory, section, items => items[0].UncastNonceRelease.Ballot.Kind = (Pb.DeviceKind)3);
        }
        else
        {
            await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
            if (where == "device-1's header")
            {
                deviceKey = (await DevicesAsync(directory))["device-1"];
                section = SectionKey.Device(deviceKey.Value);
                Edit(directory, section, items => items[0].DeviceHeader.Kind = (Pb.DeviceKind)3);
            }
            else
            {
                section = SectionKey.Of(RecordSectionType.ChallengedBallotDecryptions);
                Edit(directory, section, items => items[0].ChallengedBallotDecryption.Ballot.Kind = (Pb.DeviceKind)3);
            }
        }

        Edit(directory, RecordSectionType.Header, items => items[0].RecordHeader.FormatMinor = 1);
        await ReTocAsync(directory);

        var report = await VerifyAsync(directory, -1);
        Assert.Equal(Canonical(report), Canonical(await VerifyAsync(directory, 1)));
        Assert.False(report.Passed);
        // A record of minor 1 is incomplete for this minor-0 reader whatever it holds.
        Assert.False(report.Complete);
        Assert.True(report.RootsMatchClaimedToc);
        Assert.Contains(report.Findings, x => x.SubSection == RecordCodes.Encoding && x.Section == section && x.Ordinal == 0 && x.Message.Contains("D2"));
        Assert.DoesNotContain(report.Findings, x => x.SubSection == RecordCodes.Version);
        switch (where)
        {
            case "device-1's header":
                // The header is opaque, so the chain is not walked: no lettered 8.x is reported, and
                // Verification 8 is not evaluable (its close finds no header taken), never Passed.
                Assert.DoesNotContain(report.Findings, x => x.SubSection.StartsWith("8.", StringComparison.Ordinal) && x.SubSection != "8.structure");
                Assert.Equal(VerificationOutcome.NotEvaluable, report.Verifications[8]);

                // The public reader refuses the header the same way, and never throws anything else.
                await using (var reader = await ElectionRecord.OpenAsync(directory))
                {
                    var failure = await Assert.ThrowsAsync<VerificationFailedException>(() => reader.OpenDevice(deviceKey!.Value).ReadHeaderAsync().AsTask());
                    Assert.Equal(RecordCodes.Encoding, failure.SubSection);
                }

                break;
            case "the challenged ballot's decryption":
                Assert.Contains(report.Findings, x => x.SubSection == "13.structure");
                break;
            default:
                Assert.Contains(report.Findings, x => x.SubSection == "18.structure" && x.Ordinal == 2);
                break;
        }
    }

    /// <summary>
    /// Design §4.8 and §6.9: a structure finding is reported under its code whatever the profile, and
    /// fails the run, but a verification outside the profile stays NotRun even when a finding names it.
    /// Here a custom profile of 5 alone over a record whose device-1 close counts one ballot too many.
    /// </summary>
    [Fact]
    public async Task AFindingUnderAVerificationOutsideTheProfile_FailsTheRun_AndLeavesItNotRun()
    {
        string directory = TempDirectory("verify-outside-profile");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var one = SectionKey.Device((await DevicesAsync(directory))["device-1"]);
        Edit(directory, one, items => items[^1].DeviceClose.BallotCount += 1);
        await ReTocAsync(directory);

        var report = await VerifyAsync(directory, new VerifyAllOptions { Profile = VerificationProfile.Custom, Verifications = new HashSet<int> { 5 } });
        Assert.False(report.Passed);
        Assert.Contains(report.Findings, x => x.SubSection == "8.structure" && x.Section == one && x.Message.Contains("counts"));
        Assert.Equal(VerificationOutcome.NotRun, report.Verifications[8]);
        Assert.Equal(VerificationOutcome.Passed, report.Verifications[5]);
    }

    // ---- the options ------------------------------------------------------------------------------

    /// <summary>A regular record with several findings in device-1: two range proofs (6.D) and an H_I (5.B, and 8.B and the chain through it).</summary>
    private static async Task<string> SeveralFindingsAsync()
    {
        string directory = TempDirectory("verify-several");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var one = SectionKey.Device((await DevicesAsync(directory))["device-1"]);
        Edit(directory, one, items =>
        {
            foreach (int i in new[] { 1, 2 })
            {
                var field = items[i].EncryptedBallot.Contests[0].Fields[0];
                field.RangeProof = Flip(field.RangeProof);
            }

            items[3].EncryptedBallot.HI = Flip(items[3].EncryptedBallot.HI);
        });
        await ReTocAsync(directory);
        return directory;
    }

    /// <summary>
    /// Findings from several items of one device section, verified by concurrent workers (the default
    /// batch bound holds the whole section), give the same report as a single-threaded run, with one
    /// item or a whole section per batch.
    /// </summary>
    [Fact]
    public async Task SeveralFindingsInOneSection_GiveTheSameReport_WhateverTheParallelismOrBatch()
    {
        string directory = await SeveralFindingsAsync();
        var parallel = await VerifyAsync(directory, new VerifyAllOptions { MaxDegreeOfParallelism = -1 });
        Assert.True(parallel.Findings.Count(x => x.SubSection == "6.D") >= 2, Describe(parallel));
        Assert.Contains(parallel.Findings, x => x.SubSection == "5.B" && x.Ordinal == 3);
        foreach (var options in new[] { new VerifyAllOptions { MaxDegreeOfParallelism = 1 }, new VerifyAllOptions { MaxDegreeOfParallelism = 1, BatchBytes = 1 }, new VerifyAllOptions { MaxDegreeOfParallelism = 4, BatchBytes = 1 } })
        {
            Assert.Equal(Canonical(parallel), Canonical(await VerifyAsync(directory, options)));
        }
    }

    /// <summary>
    /// <see cref="VerifyAllOptions.MaxFindings"/> keeps the first findings in the report's order and
    /// flags the report truncated, which fails it; <see cref="VerifyAllOptions.StopOnFirstFailure"/>
    /// stops early, flagged truncated. A phase root obtained out of band that differs is R.root.
    /// </summary>
    [Fact]
    public async Task TheOptions_CapStopAndPinTheRoots()
    {
        string directory = await SeveralFindingsAsync();
        var all = await VerifyAsync(directory, new VerifyAllOptions());
        Assert.True(all.Findings.Count >= 3);
        Assert.False(all.Truncated);

        var capped = await VerifyAsync(directory, new VerifyAllOptions { MaxFindings = 1 });
        Assert.False(capped.Passed);
        Assert.True(capped.Truncated);
        Assert.Equal(all.Findings[0], Assert.Single(capped.Findings));

        var stopped = await VerifyAsync(directory, new VerifyAllOptions { StopOnFirstFailure = true, BatchBytes = 1, MaxDegreeOfParallelism = 1 });
        Assert.False(stopped.Passed);
        Assert.True(stopped.Truncated);
        Assert.NotEmpty(stopped.Findings);
        Assert.True(stopped.Findings.Count < all.Findings.Count, Describe(stopped));

        string clean = TempDirectory("verify-roots");
        var tocs = await WriteAsync(RegularElection.Value, clean, RecordEncoding.Protobuf);
        var pinned = await VerifyAsync(clean, new VerifyAllOptions
        {
            ExpectedSetupRoot = tocs[RecordPhase.Setup].Root,
            ExpectedSealedRoot = tocs[RecordPhase.Sealed].Root,
            ExpectedAggregatedRoot = tocs[RecordPhase.Aggregated].Root,
            ExpectedFinalRoot = tocs[RecordPhase.Final].Root,
        });
        Assert.True(pinned.Passed, Describe(pinned));

        foreach (var phase in new[] { RecordPhase.Setup, RecordPhase.Sealed, RecordPhase.Final })
        {
            var other = Sha256Digest.Of([(byte)phase]);
            var wrong = await VerifyAsync(clean, phase switch
            {
                RecordPhase.Setup => new VerifyAllOptions { ExpectedSetupRoot = other },
                RecordPhase.Sealed => new VerifyAllOptions { ExpectedSealedRoot = other },
                _ => new VerifyAllOptions { ExpectedFinalRoot = other },
            });
            var finding = Assert.Single(wrong.Findings);
            Assert.Equal(RecordCodes.Root, finding.SubSection);
            Assert.Contains($"{phase} root", finding.Message);
            Assert.Contains("obtained out of band", finding.Message);
        }
    }

    // ---- removed vendor sections and signature files ---------------------------------------------

    /// <summary>
    /// Vendor sections are removed (user decision "Remove them", 2026-10-10; vendors extend only the
    /// manifest, NQ-1): a claimed TOC entry naming a former vendor type is R.version like any section
    /// kind v2 does not define (NQ-7), refused when the record is opened, before any section is read.
    /// </summary>
    [Fact]
    public async Task AFormerVendorSectionType_InTheClaimedToc_IsRVersion()
    {
        string directory = TempDirectory("verify-vendor");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        RecordDirectoryCarrierTests.RewriteToc(directory, entries => entries.Add(new Pb.TocEntry { SectionType = (Pb.SectionType)0x8001, Critical = false, ItemCount = 1, Root = ByteString.CopyFrom(new byte[32]) }));

        var failure = await Assert.ThrowsAsync<VerificationFailedException>(async () => await VerifyAsync(directory, new VerifyAllOptions()));
        Assert.Equal(RecordCodes.Version, failure.SubSection);
    }

    /// <summary>
    /// The signature files are outside every root, so anyone can add one: an unreadable file is
    /// R.signature for that file, and a valid signature in a later file is still found, so
    /// RequireValid does not also report "no valid signature".
    /// </summary>
    [Fact]
    public async Task AnUnreadableSignatureFile_DoesNotHideAValidSignatureAfterIt()
    {
        using var signer = EcdsaP256Sha256Signer.Generate();
        string directory = TempDirectory("verify-signature-files");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf, signer: signer);
        string bad = Path.Combine(directory, "signatures", $"final-{new string('0', 64)}.binpb");
        File.WriteAllBytes(bad, [0x01, 0x02, 0x03]);

        await using var reader = await ElectionRecord.OpenAsync(directory);
        Assert.Equal(2, reader.SignatureFiles.Count);
        Assert.Contains("final-0000", reader.SignatureFiles[0]);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions
        {
            SignaturePolicy = SignaturePolicy.RequireValid,
            SignatureVerifiers = [new EcdsaP256Sha256Verifier([signer.SubjectPublicKeyInfo])],
        });
        var finding = Assert.Single(report.Findings);
        Assert.Equal(RecordCodes.Signature, finding.SubSection);
        Assert.Contains("could not be read", finding.Message);
        var signature = Assert.Single(report.Signatures);
        Assert.Equal(SignatureStatus.Valid, signature.Signature.Status);
    }

    // ---- the guardian profile ---------------------------------------------------------------------

    /// <summary>
    /// §3.6.1 with spec p.64: on pre-encrypted ballots the guardians' Verifications 7 and 8 are 15 and
    /// 16, so the guardian profile runs both. The pre-encrypted record's aggregated prefix passes them
    /// and yields the aggregate; a cast ballot's selection hash (16.A), its accumulated vector (15.A) or
    /// the device's closing hash (16.H, the device walk) changed fails it, with no aggregate. Before
    /// the releases, the full uncast item (#2) is checked from its printed content alone: its selection
    /// hash (16.A) or a vector entry (6.A, a non-member) changed fails the run too. The two compact
    /// uncast items (#3, #4) have no vectors until their ξ_B is released, so V6 and V16 are not
    /// evaluable on them and are never reported Passed (spec p.64: V6 "on all ballots", p.65: V16
    /// "for each pre-encrypted ballot"); but each prints H_I, χ, B_C and H_C, so its 16.C runs, and a
    /// changed confirmation code fails the run (review round 3).
    /// </summary>
    [Theory]
    [InlineData("none", null, null)]
    [InlineData("a cast ballot's selection hash changed", "16.A", 5L)]
    [InlineData("a cast ballot's combined vector changed", "15.A", 1L)]
    [InlineData("the device close's closing hash changed", "16.H", 6L)]
    [InlineData("the full uncast ballot's selection hash changed", "16.A", 2L)]
    [InlineData("the full uncast ballot's vector changed", "6.A", 2L)]
    [InlineData("the never-returned compact ballot's confirmation code changed", "16.C", 3L)]
    public async Task GuardianPreliminary_OnPreEncryptedBallots_RunsVerifications15And16(string tamper, string? code, long? ordinal)
    {
        string directory = TempDirectory("verify-guardian-pre");
        await WriteAsync(PreEncryptedRecord.Value, directory, RecordEncoding.Protobuf);
        var device = SectionKey.Device((await DevicesAsync(directory)).Values.Single());
        switch (tamper)
        {
            case "a cast ballot's selection hash changed":
                Edit(directory, device, items => { var s = items[5].PreEncryptedCastBallot.Contests[0].Selected[0]; s.Psi = Flip(s.Psi); });
                break;
            case "a cast ballot's combined vector changed":
                Edit(directory, device, items => { var f = items[1].PreEncryptedCastBallot.Contests[0].Contest.Fields[0]; f.Alpha = Flip(f.Alpha); });
                break;
            case "the device close's closing hash changed":
                Edit(directory, device, items => items[^1].DeviceClose.ClosingHash = Flip(items[^1].DeviceClose.ClosingHash));
                break;
            case "the full uncast ballot's selection hash changed":
                Edit(directory, device, items => { var s = items[2].PreEncryptedUncastBallot.Contests[0].Selections[0]; s.Psi = Flip(s.Psi); });
                break;
            case "the full uncast ballot's vector changed":
                Edit(directory, device, items => { var s = items[2].PreEncryptedUncastBallot.Contests[0].Selections[0]; s.Vector = Flip(s.Vector); });
                break;
            case "the never-returned compact ballot's confirmation code changed":
                Edit(directory, device, items => items[3].PreEncryptedCompactUncastBallot.ConfirmationCode = Flip(items[3].PreEncryptedCompactUncastBallot.ConfirmationCode));
                break;
        }

        await ReTocAsync(directory);
        var (report, aggregate) = await VerifyAggregatedAsync(directory);
        Assert.Equal(VerificationOutcome.NotRun, report.Verifications[17]);
        Assert.Equal(VerificationOutcome.NotRun, report.Verifications[18]);
        if (code is null)
        {
            Assert.True(report.Passed, Describe(report));
            Assert.Equal(VerificationOutcome.Passed, report.Verifications[15]);
            Assert.Equal(VerificationOutcome.NotEvaluable, report.Verifications[6]);
            Assert.Equal(VerificationOutcome.NotEvaluable, report.Verifications[16]);
            Assert.Equal(3, report.UncastBallotsToRelease.Count);
            Assert.NotNull(aggregate);
            return;
        }

        Assert.False(report.Passed);
        Assert.Contains(report.Findings, x => x.SubSection == code && x.Section == device && x.Ordinal == ordinal);
        Assert.Equal(VerificationOutcome.Failed, report.Verifications[int.Parse(code[..code.IndexOf('.')])]);
        Assert.Null(aggregate);
    }

    /// <summary>The aggregate exists only when Verification 9 passed: a changed aggregate (9.A) or a cast ballot out of range (6.A, V9 not evaluable) yields none.</summary>
    [Theory]
    [InlineData("an aggregate A changed")]
    [InlineData("a cast ballot's alpha out of range")]
    public async Task VerifyAggregated_YieldsNoAggregate_WithoutAPassedVerification9(string tamper)
    {
        string directory = TempDirectory("verify-aggregate-refused");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        if (tamper.StartsWith("an aggregate"))
        {
            Edit(directory, RecordSectionType.EncryptedTally, items => items[1].EncryptedTallyContest.Fields = Flip(items[1].EncryptedTallyContest.Fields, 513));
        }
        else
        {
            var one = SectionKey.Device((await DevicesAsync(directory))["device-1"]);
            Edit(directory, one, items => items[1].EncryptedBallot.Contests[0].Fields[0].Alpha = ByteString.CopyFrom(Enumerable.Repeat((byte)0xFF, 512).ToArray()));
        }

        await ReTocAsync(directory);
        var (report, aggregate) = await VerifyAggregatedAsync(directory);
        Assert.False(report.Passed);
        Assert.Equal(tamper.StartsWith("an aggregate") ? VerificationOutcome.Failed : VerificationOutcome.NotEvaluable, report.Verifications[9]);
        Assert.Null(aggregate);
    }

    /// <summary>
    /// Q31/Q36: the guardians' view of the cast and spoiled ballots comes from a second read of the
    /// device sections, which must give the roots the run verified. A record that changes in between
    /// (here the spoiled ballot relabelled challenged on the second read, which would let a guardian
    /// open it) is R.root, and no aggregate is returned.
    /// </summary>
    [Fact]
    public async Task VerifyAggregated_RefusesARecordThatChangesAfterItWasVerified()
    {
        string directory = TempDirectory("verify-aggregate-changed");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf);
        var one = SectionKey.Device((await DevicesAsync(directory))["device-1"]);
        await using var inner = await ElectionRecord.OpenAsync(directory);
        var (report, aggregate) = await ElectionRecordVerifier.VerifyAggregatedAsync(new SecondReadChanges(inner, one), new VerifyAllOptions());
        Assert.False(report.Passed);
        var finding = Assert.Single(report.Findings);
        Assert.Equal((RecordCodes.Root, one), (finding.SubSection, finding.Section!.Value));
        Assert.Contains("changed after verification", finding.Message);
        Assert.Null(aggregate);
    }

    /// <summary>A reader whose device section <paramref name="changed"/> reads the spoiled ballot-3 as challenged from its second read on.</summary>
    private sealed class SecondReadChanges(IElectionRecordReader inner, SectionKey changed) : IElectionRecordReader
    {
        private int _reads;

        public RecordEncoding Encoding => inner.Encoding;

        public RecordCarrier Carrier => inner.Carrier;

        public RecordFormatVersion Format => inner.Format;

        public RecordPhase Phase => inner.Phase;

        public TableOfContents? ClaimedToc => inner.ClaimedToc;

        public IReadOnlyList<SectionKey> Sections => inner.Sections;

        public IReadOnlyList<DeviceKey> Devices => inner.Devices;

        public IReadOnlyList<string> SignatureFiles => inner.SignatureFiles;

        public ValueTask<RecordSetup> ReadSetupAsync(CancellationToken ct = default) => inner.ReadSetupAsync(ct);

        public IDeviceSectionReader OpenDevice(DeviceKey device) => inner.OpenDevice(device);

        public IAsyncEnumerable<RecordItemBytes> ReadSectionAsync(SectionKey section, long fromOrdinal = 0, CancellationToken ct = default) =>
            section == changed && Interlocked.Increment(ref _reads) > 1 ? Relabelled(inner.ReadSectionAsync(section, fromOrdinal, ct), ct) : inner.ReadSectionAsync(section, fromOrdinal, ct);

        public IAsyncEnumerable<RecordItemBytes> ReadSignaturesAsync(CancellationToken ct = default) => inner.ReadSignaturesAsync(ct);

        public IAsyncEnumerable<RecordItemBytes> ReadSignatureFileAsync(string file, CancellationToken ct = default) => inner.ReadSignatureFileAsync(file, ct);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private static async IAsyncEnumerable<RecordItemBytes> Relabelled(IAsyncEnumerable<RecordItemBytes> items, [EnumeratorCancellation] CancellationToken ct)
        {
            await foreach (var raw in items.WithCancellation(ct))
            {
                if (raw.Ordinal == 3)
                {
                    var item = Pb.RecordItem.Parser.ParseFrom(raw.Bytes.Span);
                    item.EncryptedBallot.Status = Pb.BallotStatus.Challenged;
                    yield return raw with { Bytes = item.ToByteArray() };
                }
                else
                {
                    yield return raw;
                }
            }
        }
    }

    /// <summary>
    /// The ballot correctness profile runs Verification 15 on a chosen cast pre-encrypted ballot: the
    /// published selection vector must be the product of the pre-encryptions the voter selected.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BallotCorrectness_OnACastPreEncryptedBallot_RunsVerification15(bool tampered)
    {
        string directory = TempDirectory("verify-ballots-pre");
        await WriteAsync(PreEncryptedRecord.Value, directory, RecordEncoding.Protobuf);
        var device = SectionKey.Device((await DevicesAsync(directory)).Values.Single());
        if (tampered)
        {
            Edit(directory, device, items => { var f = items[1].PreEncryptedCastBallot.Contests[0].Contest.Fields[0]; f.Alpha = Flip(f.Alpha); });
            await ReTocAsync(directory);
        }

        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions
        {
            Profile = VerificationProfile.BallotCorrectness,
            Ballots = [new BallotLocator(reader.Devices.Single(), 1)],
        });
        Assert.Equal(tampered ? VerificationOutcome.Failed : VerificationOutcome.Passed, report.Verifications[15]);
        Assert.Equal(!tampered, report.Passed);
        if (tampered)
        {
            Assert.Contains(report.Findings, x => x.SubSection == "15.A" && x.Ordinal == 1);
        }
    }
}
