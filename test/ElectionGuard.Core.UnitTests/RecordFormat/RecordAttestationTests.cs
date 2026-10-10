using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Verify;
using ElectionGuard.Testing.Common;
using Google.Protobuf;
using System.Security.Cryptography;
using static ElectionGuard.Core.UnitTests.RecordFormat.ElectionRecordVerifierTests;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordCarrierElections;
using static ElectionGuard.Core.UnitTests.RecordFormat.RecordTamper;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.UnitTests.RecordFormat;

/// <summary>
/// S10b-11 (design §4.9, user decision #7): device attestations (the chain close over codes_root, the
/// section seal) and detached record signatures, signed with generated <c>ecdsa-p256-sha256</c> keys;
/// statement contents always checked (<c>R.attestation</c>, <c>R.signature</c>), signatures under the
/// policy (Report by default, RequireValid strict).
/// </summary>
public class RecordAttestationTests
{
    public RecordAttestationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static async Task<(string Directory, EcdsaP256Sha256Signer Signer)> SignedRecordAsync()
    {
        var signer = EcdsaP256Sha256Signer.Generate();
        string directory = TempDirectory("signed");
        await WriteAsync(RegularElection.Value, directory, RecordEncoding.Protobuf, signer: signer);
        return (directory, signer);
    }

    private static async Task<VerificationReport> VerifyAsync(string directory, SignaturePolicy policy, params ISignatureVerifier[] verifiers)
    {
        await using var reader = await ElectionRecord.OpenAsync(directory);
        return await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { SignaturePolicy = policy, SignatureVerifiers = verifiers });
    }

    [Fact]
    public async Task ASignedRecord_PassesRequireValid_UnderItsTrustedKey()
    {
        var (directory, signer) = await SignedRecordAsync();
        var report = await VerifyAsync(directory, SignaturePolicy.RequireValid, new EcdsaP256Sha256Verifier([signer.SubjectPublicKeyInfo]));
        Assert.True(report.Passed, Describe(report));
        Assert.Equal(4, report.Attestations.Count);
        Assert.All(report.Attestations, x => Assert.True(x.Present && x.ContentsMatch && x.Signature!.Status == SignatureStatus.Valid, x.Message));
        Assert.Equal(2, report.Attestations.Count(x => x.Kind == AttestationKind.ChainClose));
        var signature = Assert.Single(report.Signatures);
        Assert.Equal((RecordPhase.Final, "administrator", SignatureStatus.Valid, true), (signature.Phase!.Value, signature.SignerRole, signature.Signature.Status, signature.ContentsMatch));
        Assert.Equal(ClosedAt.AddHours(1), signature.SignedAt);

        // The record is also written and read in JSON, the attestations and signature included.
        string json = TempDirectory("signed-json");
        await using (var source = await ElectionRecord.OpenAsync(directory))
        {
            await ElectionRecord.ConvertAsync(source, json, RecordEncoding.Json, RecordCarrier.Directory);
        }

        var fromJson = await VerifyAsync(json, SignaturePolicy.RequireValid, new EcdsaP256Sha256Verifier([signer.SubjectPublicKeyInfo]));
        Assert.Equal(Canonical(report), Canonical(fromJson));
    }

    /// <summary>
    /// Under Report (the default) a signature no configured key can check is "present, not checked"
    /// and the record passes; under RequireValid it fails, as do an unknown key and a signature that
    /// does not verify. A device with no attestation at all is reported, and fails only RequireValid.
    /// </summary>
    [Fact]
    public async Task MissingOrInvalidSignatures_AreReported_AndFailOnlyRequireValid()
    {
        var (directory, signer) = await SignedRecordAsync();
        var unchecked_ = await VerifyAsync(directory, SignaturePolicy.Report);
        Assert.True(unchecked_.Passed, Describe(unchecked_));
        Assert.All(unchecked_.Attestations, x => Assert.Equal(SignatureStatus.NotChecked, x.Signature!.Status));

        var strict = await VerifyAsync(directory, SignaturePolicy.RequireValid);
        Assert.False(strict.Passed);
        Assert.Contains(strict.Findings, x => x.SubSection == RecordCodes.Attestation);
        Assert.Contains(strict.Findings, x => x.SubSection == RecordCodes.Signature);

        using var stranger = EcdsaP256Sha256Signer.Generate();
        var otherKey = await VerifyAsync(directory, SignaturePolicy.RequireValid, new EcdsaP256Sha256Verifier([stranger.SubjectPublicKeyInfo]));
        Assert.False(otherKey.Passed);
        Assert.All(otherKey.Attestations, x => Assert.Equal(SignatureStatus.NotChecked, x.Signature!.Status));

        var ignored = await VerifyAsync(directory, SignaturePolicy.Ignore);
        Assert.True(ignored.Passed);
        Assert.All(ignored.Attestations, x => Assert.Equal(SignatureStatus.Ignored, x.Signature!.Status));

        // A signature byte flipped: Invalid; reported under Report, a failure under RequireValid. The
        // attestations are inside R_sealed, so the record signature over the final root no longer
        // matches either (R.signature whatever the policy): that is the only finding under Report.
        Edit(directory, RecordSectionType.DeviceAttestations, items => items[0].DeviceAttestation.Signature = Flip(items[0].DeviceAttestation.Signature, 3));
        await ReTocAsync(directory);
        var trusted = new EcdsaP256Sha256Verifier([signer.SubjectPublicKeyInfo]);
        var reported = await VerifyAsync(directory, SignaturePolicy.Report, trusted);
        var moved = Assert.Single(reported.Findings);
        Assert.Equal(RecordCodes.Signature, moved.SubSection);
        Assert.Contains("the Final root differ", moved.Message);
        Assert.Single(reported.Attestations, x => x.Signature!.Status == SignatureStatus.Invalid);
        var refused = await VerifyAsync(directory, SignaturePolicy.RequireValid, trusted);
        Assert.Contains(refused.Findings, x => x.SubSection == RecordCodes.Attestation && x.Message.Contains("no valid signature"));

        // A record written without attestations: each device's missing chain close is reported.
        string bare = TempDirectory("unsigned");
        await WriteAsync(RegularElection.Value, bare, RecordEncoding.Protobuf);
        var plain = await VerifyAsync(bare, SignaturePolicy.Report, trusted);
        Assert.True(plain.Passed);
        Assert.Equal(2, plain.Attestations.Count(x => !x.Present && x.Kind == AttestationKind.ChainClose));
        var required = await VerifyAsync(bare, SignaturePolicy.RequireValid, trusted);
        Assert.Equal(2, required.Findings.Count(x => x.SubSection == RecordCodes.Attestation));
        Assert.Contains(required.Findings, x => x.SubSection == RecordCodes.Signature && x.Message.Contains("no valid signature over its Final root"));
    }

    /// <summary>
    /// Design §4.9, §6.6: what only the attestations protect. A spoiled ballot relabelled cast (status
    /// is no input to H_C) passes every numbered verification once the TOC is rewritten, but its
    /// section seal no longer matches; a dropped last ballot with a recomputed close passes 8.G, but the
    /// chain close's count and codes root no longer match. Both are R.attestation whatever the policy.
    /// </summary>
    [Fact]
    public async Task ARelabelledStatusOrADroppedLastBallot_IsCaughtByTheAttestations()
    {
        var (directory, signer) = await SignedRecordAsync();
        var one = SectionKey.Device((await DevicesAsync(directory))["device-1"]);
        Edit(directory, one, items => items[3].EncryptedBallot.Status = Pb.BallotStatus.Cast);
        await ReTocAsync(directory);
        var relabelled = await VerifyAsync(directory, SignaturePolicy.Report);
        Assert.Contains(relabelled.Findings, x => x.SubSection == RecordCodes.Attestation && x.Message.Contains("section root"));
        Assert.DoesNotContain(relabelled.Findings, x => x.SubSection == RecordCodes.Root);

        (directory, _) = await SignedRecordAsync();
        var election = RegularElection.Value;
        Edit(directory, one, items =>
        {
            // ballot-4 (the last) dropped; the close recomputed over ballot-3's code (eqs. 77/78).
            items.RemoveAt(4);
            var last = ConfirmationCode.FromCanonicalBytes(items[3].EncryptedBallot.ConfirmationCode.ToByteArray());
            var deviceHash = new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "device-1");
            var closing = ChainingField.Closing(deviceHash, election.Record.ExtendedBaseHash, last);
            items[^1].DeviceClose.BallotCount = 3;
            items[^1].DeviceClose.ClosingChainingField = ByteString.CopyFrom((byte[])closing);
            items[^1].DeviceClose.ClosingHash = ByteString.CopyFrom((byte[])ChainingField.ClosingHash(closing, election.Record.ExtendedBaseHash));
        });
        Edit(directory, RecordSectionType.ChallengedBallotDecryptions, items => items.Clear());
        await ReTocAsync(directory);
        var dropped = await VerifyAsync(directory, SignaturePolicy.Report);
        Assert.DoesNotContain(dropped.Findings, x => x.SubSection is "8.G" or RecordCodes.Root);
        var mismatch = Assert.Single(dropped.Findings, x => x.SubSection == RecordCodes.Attestation && x.Message.Contains("The ChainClose attestation"));
        Assert.Contains("ballot count", mismatch.Message);
        Assert.Contains("codes_root", mismatch.Message);
    }

    /// <summary>
    /// The same truncation under no chaining (S8b: there nothing in the ballots binds the order or the
    /// count): only the chain-close attestation's codes root and count catch it.
    /// </summary>
    [Fact]
    public async Task UnderNoChaining_ADroppedLastBallot_IsCaughtOnlyByTheChainClose()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "scanner");
        using var signer = EcdsaP256Sha256Signer.Generate();
        string directory = TempDirectory("no-chaining");
        await using (var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf))
        {
            await writer.WriteSetupAsync(record);
            await using var device = await writer.OpenDeviceAsync("scanner", DeviceChainBallotKind.Encrypted);
            for (int i = 0; i < 3; i++)
            {
                await device.AppendAsync(RecordDirectoryCarrierTests.Copy(ElectionFixtureBuilder.CreateEncryptedBallot(record, "scanner", deviceHash,
                    ElectionFixtureBuilder.CreateBallot(manifest, $"b-{i}", new Dictionary<string, int> { ["choice-1"] = 1 })), BallotStatus.Spoiled));
            }

            var seal = await device.CloseAsync(ClosedAt);
            await writer.AddAttestationAsync(await signer.SignAsync(seal!.ChainCloseStatement(record.ExtendedBaseHash)));
            await writer.SealVotingAsync();
        }

        var device1 = SectionKey.Device((await DevicesAsync(directory))["scanner"]);
        var trusted = new EcdsaP256Sha256Verifier([signer.SubjectPublicKeyInfo]);
        Assert.True((await VerifyCustomAsync(directory, trusted)).Passed);

        Edit(directory, device1, items =>
        {
            items.RemoveAt(3);
            items[^1].DeviceClose.BallotCount = 2;
        });
        await ReTocAsync(directory);
        var report = await VerifyCustomAsync(directory, trusted);
        var finding = Assert.Single(report.Findings);
        Assert.Equal(RecordCodes.Attestation, finding.SubSection);
        Assert.Contains("ballot count", finding.Message);

        static async Task<VerificationReport> VerifyCustomAsync(string directory, ISignatureVerifier trusted)
        {
            await using var reader = await ElectionRecord.OpenAsync(directory);
            return await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { Profile = VerificationProfile.Custom, Verifications = new HashSet<int>(Enumerable.Range(1, 8)), SignatureVerifiers = [trusted] });
        }
    }

    /// <summary>
    /// Design §4.9: a prefix-checkpoint attestation (a mid-election commitment to a device's first
    /// codes) taken after two ballots matches the record; once the second ballot's confirmation code
    /// is changed (TOC rewritten), its codes_root no longer does, which is R.attestation whatever the
    /// policy.
    /// </summary>
    [Fact]
    public async Task APrefixCheckpointAttestation_Matches_UntilACodeInItsPrefixChanges()
    {
        using var signer = EcdsaP256Sha256Signer.Generate();
        var election = RegularElection.Value;
        string directory = TempDirectory("prefix-checkpoint");
        await using (var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf))
        {
            await writer.WriteSetupAsync(election.Record);
            foreach (var (deviceId, ballots) in election.Devices)
            {
                await using var device = await writer.OpenDeviceAsync(deviceId, DeviceChainBallotKind.Encrypted);
                for (int i = 0; i < ballots.Count; i++)
                {
                    await device.AppendAsync(ballots[i]);
                    if (deviceId == "device-1" && i == 1)
                    {
                        await device.FlushAsync(durable: true);
                        await writer.AddAttestationAsync(await signer.SignAsync(device.PrefixCheckpointStatement(election.Record.ExtendedBaseHash, ClosedAt.AddHours(-2))));
                    }
                }

                await device.CloseAsync(ClosedAt);
            }

            await writer.SealVotingAsync();
        }

        var trusted = new EcdsaP256Sha256Verifier([signer.SubjectPublicKeyInfo]);
        var report = await VerifySealedAsync(directory, trusted);
        Assert.True(report.Passed, Describe(report));
        var prefix = Assert.Single(report.Attestations, x => x.Kind == AttestationKind.PrefixCheckpoint);
        Assert.True(prefix.ContentsMatch, prefix.Message);
        Assert.Equal(SignatureStatus.Valid, prefix.Signature!.Status);

        var one = SectionKey.Device((await DevicesAsync(directory))["device-1"]);
        Edit(directory, one, items => items[2].EncryptedBallot.ConfirmationCode = Flip(items[2].EncryptedBallot.ConfirmationCode));
        await ReTocAsync(directory);
        var changed = await VerifySealedAsync(directory, trusted);
        var mismatch = Assert.Single(changed.Findings, x => x.SubSection == RecordCodes.Attestation);
        Assert.Contains("PrefixCheckpoint", mismatch.Message);
        Assert.Contains("codes_root over the first 2 confirmation codes", mismatch.Message);
        Assert.False(Assert.Single(changed.Attestations, x => x.Kind == AttestationKind.PrefixCheckpoint).ContentsMatch);

        static async Task<VerificationReport> VerifySealedAsync(string directory, ISignatureVerifier trusted)
        {
            await using var reader = await ElectionRecord.OpenAsync(directory);
            return await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { Profile = VerificationProfile.Custom, Verifications = new HashSet<int>(Enumerable.Range(1, 8)), SignatureVerifiers = [trusted] });
        }
    }

    /// <summary>A record signature over another root, or another election's H_E, is R.signature whatever the policy; the writer refuses both up front.</summary>
    [Fact]
    public async Task ARecordSignatureOverAnotherRoot_IsRSignature_AndTheWriterRefusesIt()
    {
        var (directory, signer) = await SignedRecordAsync();
        string file = Directory.EnumerateFiles(Path.Combine(directory, "signatures")).Single();
        var frames = RecordDirectoryCarrierTests.Frames(File.ReadAllBytes(file));
        var item = Pb.RecordItem.Parser.ParseFrom(RecordDirectoryCarrierTests.Payload(frames[1]));
        var statement = Pb.RecordItem.Parser.ParseFrom(item.RecordSignature.Statement);
        statement.RecordStatement.Root = Flip(statement.RecordStatement.Root);
        var resigned = await signer.SignAsync(statement.ToByteArray());
        File.WriteAllBytes(file, RecordDirectoryCarrierTests.Join([frames[0], RecordDirectoryCarrierTests.Frame(resigned.ToRecordSignatureItem())]));
        var report = await VerifyAsync(directory, SignaturePolicy.Ignore);
        Assert.Contains(report.Findings, x => x.SubSection == RecordCodes.Signature && x.Message.Contains("does not match the record"));

        string again = TempDirectory("signed-refused");
        await using var writer = ElectionRecord.Create(again, RecordEncoding.Protobuf);
        var setup = await writer.WriteSetupAsync(RegularElection.Value.Record);
        await Assert.ThrowsAsync<ArgumentException>(() => writer.AddRecordSignatureAsync(resigned).AsTask());
        var wrongElection = await signer.SignAsync(RecordStatements.Record(RecordPhase.Setup, setup.Root, PreEncryptedRecord.Value.Record.ExtendedBaseHash, ClosedAt, "administrator"));
        await Assert.ThrowsAsync<ArgumentException>(() => writer.AddRecordSignatureAsync(wrongElection).AsTask());
        await writer.AddRecordSignatureAsync(await signer.SignAsync(RecordStatements.Record(RecordPhase.Setup, setup.Root, RegularElection.Value.Record.ExtendedBaseHash, ClosedAt, "administrator")));
    }

    /// <summary>The writer takes attestations only canonical, of a statement type, under this H_E, for a device it opened, once, and before voting is sealed.</summary>
    [Fact]
    public async Task TheWriter_RefusesAttestationsItCannotHold()
    {
        using var signer = EcdsaP256Sha256Signer.Generate();
        var election = RegularElection.Value;
        await using var writer = ElectionRecord.Create(TempDirectory("attest-refused"), RecordEncoding.Protobuf);
        await writer.WriteSetupAsync(election.Record);
        await using var device = await writer.OpenDeviceAsync("device-2", DeviceChainBallotKind.Encrypted);
        await device.AppendAsync(election.Devices[1].Ballots[0]);
        var seal = (await device.CloseAsync(ClosedAt))!;
        var good = await signer.SignAsync(seal.ChainCloseStatement(election.Record.ExtendedBaseHash));
        await writer.AddAttestationAsync(good);
        await Assert.ThrowsAsync<ArgumentException>(() => writer.AddAttestationAsync(good).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(async () => await writer.AddAttestationAsync(await signer.SignAsync(seal.ChainCloseStatement(PreEncryptedRecord.Value.Record.ExtendedBaseHash))));
        await Assert.ThrowsAsync<ArgumentException>(async () => await writer.AddAttestationAsync(await signer.SignAsync(RecordStatements.Record(RecordPhase.Setup, seal.SectionRoot, election.Record.ExtendedBaseHash, ClosedAt, "x"))));
        var unknownDevice = seal with { Key = new DeviceKey(DeviceChainBallotKind.Encrypted, new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "nobody")) };
        await Assert.ThrowsAsync<ArgumentException>(async () => await writer.AddAttestationAsync(await signer.SignAsync(unknownDevice.SectionSealStatement(election.Record.ExtendedBaseHash))));
        await writer.SealVotingAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await writer.AddAttestationAsync(await signer.SignAsync(seal.SectionSealStatement(election.Record.ExtendedBaseHash))));
    }

    /// <summary>
    /// Q25 and design §4.9: a device that closes with no ballots has no section, so an attestation
    /// added while it was open (a prefix checkpoint at count 0) is dropped when it closes, and voting
    /// can still be sealed; the other device's attestation is written and verifies.
    /// </summary>
    [Fact]
    public async Task AnAttestationOfADeviceThatClosesEmpty_IsDropped_AndVotingStillSeals()
    {
        using var signer = EcdsaP256Sha256Signer.Generate();
        var election = RegularElection.Value;
        string directory = TempDirectory("attest-empty-device");
        await using (var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf))
        {
            await writer.WriteSetupAsync(election.Record);
            await using (var empty = await writer.OpenDeviceAsync("device-2", DeviceChainBallotKind.Encrypted))
            {
                await writer.AddAttestationAsync(await signer.SignAsync(empty.PrefixCheckpointStatement(election.Record.ExtendedBaseHash, ClosedAt.AddHours(-2))));
                Assert.Null(await empty.CloseAsync(ClosedAt));
            }

            await using var device = await writer.OpenDeviceAsync("device-1", DeviceChainBallotKind.Encrypted);
            foreach (var ballot in election.Devices[0].Ballots)
            {
                await device.AppendAsync(ballot);
            }

            var seal = (await device.CloseAsync(ClosedAt))!;
            await writer.AddAttestationAsync(await signer.SignAsync(seal.ChainCloseStatement(election.Record.ExtendedBaseHash)));
            await writer.SealVotingAsync();
        }

        await using var reader = await ElectionRecord.OpenAsync(directory);
        var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { Profile = VerificationProfile.Custom, Verifications = new HashSet<int>(Enumerable.Range(1, 8)), SignatureVerifiers = [new EcdsaP256Sha256Verifier([signer.SubjectPublicKeyInfo])] });
        Assert.True(report.Passed, Describe(report));
        var attestation = Assert.Single(report.Attestations);
        Assert.Equal(AttestationKind.ChainClose, attestation.Kind);
        Assert.True(attestation.ContentsMatch, attestation.Message);
    }

    /// <summary>
    /// Design §4.9: another signer of the same statement joins its signatures file. Adds through one
    /// writer are serialized, so concurrent co-signers all land in the file and none fails on the
    /// shared temporary file.
    /// </summary>
    [Fact]
    public async Task ConcurrentCoSignersOfOneStatement_AllJoinItsFile()
    {
        var election = RegularElection.Value;
        string directory = TempDirectory("co-signers");
        var signers = Enumerable.Range(0, 8).Select(_ => EcdsaP256Sha256Signer.Generate()).ToList();
        try
        {
            await using (var writer = ElectionRecord.Create(directory, RecordEncoding.Protobuf))
            {
                var setup = await writer.WriteSetupAsync(election.Record);
                byte[] statement = RecordStatements.Record(RecordPhase.Setup, setup.Root, election.Record.ExtendedBaseHash, ClosedAt, "guardian");
                var signatures = await Task.WhenAll(signers.Select(x => x.SignAsync(statement).AsTask()));
                await Task.WhenAll(signatures.Select(x => Task.Run(async () => await writer.AddRecordSignatureAsync(x))));
            }

            string file = Assert.Single(Directory.EnumerateFiles(Path.Combine(directory, "signatures")));
            Assert.Equal(1 + signers.Count, RecordDirectoryCarrierTests.Frames(File.ReadAllBytes(file)).Count);
            await using var reader = await ElectionRecord.OpenAsync(directory);
            var report = await ElectionRecordVerifier.VerifyAllAsync(reader, new VerifyAllOptions { SignatureVerifiers = [new EcdsaP256Sha256Verifier(signers.Select(x => (ReadOnlyMemory<byte>)x.SubjectPublicKeyInfo))] });
            Assert.Equal(signers.Count, report.Signatures.Count);
            Assert.All(report.Signatures, x => Assert.Equal(SignatureStatus.Valid, x.Signature.Status));
        }
        finally
        {
            signers.ForEach(x => x.Dispose());
        }
    }

    /// <summary>
    /// Design §4.5 and §4.9 at verifier level: a statement the attestations section or a signatures
    /// file cannot hold is reported under R.attestation or R.signature at its item, never thrown. The
    /// orphan row matters most: a device section dropped whole, with the TOC rewritten, leaves its
    /// attestations naming a device with no section, and that is what reports it (RequireValid checks
    /// only the devices present).
    /// </summary>
    [Theory]
    [InlineData("device-2's section removed", "R.attestation", "has no section in the record")]
    [InlineData("a record signature in the attestations section", "R.attestation", "not a device_attestation")]
    [InlineData("an attestation's statement made non-canonical", "R.attestation", "not a canonical device attestation")]
    [InlineData("an attestation naming a device key of no kind", "R.attestation", "names a device key that is no device's")]
    [InlineData("a device attestation in a signatures file", "R.signature", "not a record_signature")]
    public async Task AStatementASectionCannotHold_IsReportedAtItsItem(string tamper, string code, string message)
    {
        var (directory, signer) = await SignedRecordAsync();
        signer.Dispose();
        var attestations = SectionKey.Of(RecordSectionType.DeviceAttestations);
        string signatures = Directory.EnumerateFiles(Path.Combine(directory, "signatures")).Single();
        var signatureFrames = RecordDirectoryCarrierTests.Frames(File.ReadAllBytes(signatures));
        var recordSignature = Pb.RecordItem.Parser.ParseFrom(RecordDirectoryCarrierTests.Payload(signatureFrames[1]));
        var two = (await DevicesAsync(directory))["device-2"];
        var expectedOrdinals = new List<long>();
        switch (tamper)
        {
            case "device-2's section removed":
                Edit(directory, attestations, items =>
                {
                    for (int i = 0; i < items.Count; i++)
                    {
                        var statement = Pb.RecordItem.Parser.ParseFrom(items[i].DeviceAttestation.Statement);
                        var key = statement.ChainCloseStatement?.DeviceKey ?? statement.SectionSealStatement?.DeviceKey ?? statement.PrefixCheckpointStatement.DeviceKey;
                        if (key.Span.SequenceEqual(two.ToBytes()))
                        {
                            expectedOrdinals.Add(i);
                        }
                    }
                });
                Directory.Delete(Path.GetDirectoryName(PathOf(directory, SectionKey.Device(two)))!, recursive: true);
                break;
            case "a record signature in the attestations section":
                Edit(directory, attestations, items => items[0] = recordSignature);
                expectedOrdinals.Add(0);
                break;
            case "an attestation's statement made non-canonical":
                // An unknown field (127) in a record of the library's own minor.
                Edit(directory, attestations, items => items[0].DeviceAttestation.Statement = ByteString.CopyFrom([.. items[0].DeviceAttestation.Statement.Span, 0xF8, 0x07, 0x01]));
                expectedOrdinals.Add(0);
                break;
            case "an attestation naming a device key of no kind":
                Edit(directory, attestations, items =>
                {
                    var statement = Pb.RecordItem.Parser.ParseFrom(items[0].DeviceAttestation.Statement);
                    var close = statement.ChainCloseStatement ?? throw new InvalidOperationException("The first attestation is a chain close (statement type 40 sorts first).");
                    byte[] key = close.DeviceKey.ToByteArray();
                    key[0] = 3;
                    close.DeviceKey = ByteString.CopyFrom(key);
                    items[0].DeviceAttestation.Statement = statement.ToByteString();
                });
                expectedOrdinals.Add(0);
                break;
            case "a device attestation in a signatures file":
                Edit(directory, attestations, items => File.WriteAllBytes(signatures, RecordDirectoryCarrierTests.Join([signatureFrames[0], RecordDirectoryCarrierTests.Frame(items[0].ToByteArray())])));
                break;
        }

        await ReTocAsync(directory);
        var report = await VerifyAsync(directory, SignaturePolicy.Report);
        Assert.False(report.Passed);
        var found = report.Findings.Where(x => x.SubSection == code && x.Message.Contains(message)).ToList();
        Assert.True(found.Count > 0, $"{tamper}: no {code} \"{message}\".\n{Describe(report)}");
        if (code == RecordCodes.Attestation)
        {
            Assert.Equal(expectedOrdinals, found.Select(x => x.Ordinal!.Value).Order().ToList());
            Assert.All(found, x => Assert.Equal(attestations, x.Section));
        }
    }

    /// <summary><c>ecdsa-p256-sha256</c> is P-256 only: neither the signer nor the verifier takes a key of another curve.</summary>
    [Fact]
    public void EcdsaP256Sha256_RefusesAKeyOfAnotherCurve()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<ArgumentException>(() => new EcdsaP256Sha256Signer(p384));
        Assert.Throws<ArgumentException>(() => new EcdsaP256Sha256Verifier([p384.ExportSubjectPublicKeyInfo()]));
    }
}
