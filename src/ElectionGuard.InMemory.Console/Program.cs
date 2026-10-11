// We're going to assume 2/3 guardians for now.
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using System.Text.Json;

var jsonOptions = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
};

CryptographicParameters cryptographicParameters = new CryptographicParameters();
GuardianParameters guardianParameters = new GuardianParameters();
EGParameters.Init(cryptographicParameters, guardianParameters);

// Assume the following directory for writing out the encryption package.
string inputDirectory = @"c:\temp\eg\data\1";
//string inputDirectory = @"../../../../../test/data/famous-names";
string outputDirectory = @"c:\temp\eg\data\1";
//string outputDirectory = @"c:\temp\eg\";

// The election record (EGRF v2, docs/spec-compliance/2026-10-08-election-record-design.md): one
// directory of protobuf segments, written phase by phase through ElectionRecordWriter, and a copy
// converted to the JSON representation in a .zip. Everything after the setup is checked against
// what was read back from the record, not against the objects that produced it.
string recordDirectory = Path.Combine(outputDirectory, "record");
string jsonRecord = Path.Combine(outputDirectory, "record-json.zip");

// Times in the record are UTC to the millisecond (design §4.6).
static DateTimeOffset Now()
{
    var now = DateTimeOffset.UtcNow;
    return now.AddTicks(-(now.Ticks % TimeSpan.TicksPerMillisecond));
}

static void Require(VerificationReport report, string what)
{
    Console.WriteLine($"{what}: {(report.Passed ? "passed" : "FAILED")}, phase {report.Phase}, {report.Statistics.BallotItems} ballot items on {report.Statistics.Devices} device(s), in {report.Elapsed.TotalMilliseconds:F0} ms.");
    Console.WriteLine($"  Verifications: {string.Join(", ", report.Verifications.OrderBy(x => x.Key).Select(x => $"{x.Key} {x.Value}"))}.");
    foreach (var (phase, root) in report.PhaseRoots.OrderBy(x => x.Key))
    {
        Console.WriteLine($"  R_{phase.ToString().ToLowerInvariant()} = {root}");
    }

    if (!report.Passed)
    {
        foreach (var finding in report.Findings)
        {
            Console.WriteLine($"  {finding.SubSection}: {finding.Message}");
        }

        throw new InvalidOperationException($"{what} failed.");
    }
}

// The ballots of a record's device sections, read back through the item codec, with their locators.
static async Task<List<(BallotLocator Locator, EncryptedBallot Ballot)>> ReadBallotsAsync(IElectionRecordReader reader, Manifest manifest)
{
    var ballots = new List<(BallotLocator, EncryptedBallot)>();
    foreach (var key in reader.Devices)
    {
        var section = reader.OpenDevice(key);
        var header = await section.ReadHeaderAsync();
        await foreach (var item in section.ReadEntriesAsync())
        {
            ballots.Add((new BallotLocator(key, item.Ordinal), RecordItemCodec.DecodeBallot(item.Bytes.Span, manifest, header.DeviceId)));
        }
    }

    return ballots;
}

try
{
    if (Directory.Exists(recordDirectory))
    {
        Directory.Delete(recordDirectory, recursive: true);
    }

    File.Delete(jsonRecord);

    // The manifest file. H_B = H(H_P; 0x01, manifest) (eq. 5) is part of the guardian record: each
    // guardian checks it by performing Verification 1 and keys its comparison hash H_G with it
    // (§3.2.2 step 1). The same bytes go into the record's setup (§3.7), stored as given, which
    // parses its manifest from them (ManifestSerializer, the library's one manifest format).
    var manifestBytes = File.ReadAllBytes(Path.Combine(inputDirectory, "manifest.json"));
    var manifestFile = new ManifestFile
    {
        Bytes = manifestBytes
    };
    var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);

    List<Guardian> guardians = new List<Guardian>();
    for (int i = 1; i <= guardianParameters.N; i++)
    {
        guardians.Add(new Guardian(new GuardianIndex(i)));
    }

    List<GuardianPublicView> guardianKeys = new List<GuardianPublicView>();
    foreach (var guardian in guardians)
    {
        var keys = guardian.GenerateKeys();
        guardianKeys.Add(keys.ToPublicView());
    }

    List<GuardianEncryptedShare> guardianEncryptedShares = new List<GuardianEncryptedShare>();
    foreach (var guardian in guardians)
    {
        var encryptedShares = guardian.EncryptShares(guardianKeys.Where(x => x.Index != guardian.Index).ToList());
        guardianEncryptedShares.AddRange(encryptedShares);
    }

    Dictionary<GuardianIndex, GuardianSecretShares> guardianSecretShares = new Dictionary<GuardianIndex, GuardianSecretShares>();
    foreach (var guardian in guardians)
    {
        var secretShares = guardian.DecryptShares(guardianEncryptedShares.Where(x => x.DestinationIndex == guardian.Index).ToList());
        guardianSecretShares[guardian.Index] = secretShares;
    }

    var electionPublicKeys = new ElectionPublicKeys(
        guardianKeys.Select(x => x.VoteEncryptionCommitments[0]),
        guardianKeys.Select(x => x.OtherBallotDataEncryptionCommitments[0]));

    // Combine with manifest
    var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, electionPublicKeys);

    // The record's setup phase (§3.7): parameters, manifest, guardian keys, election keys and H_E.
    // It is read back, every guardian checks the guardian record the copy holds (§3.2.2), and the
    // device encrypts against the copy.
    Console.WriteLine($"Writing the election record to {recordDirectory}.");
    var writer = ElectionRecord.Create(recordDirectory, RecordEncoding.Protobuf);
    EncryptionRecord encryptionRecord;
    Sha256Digest aggregatedRoot;
    var ballotFiles = Directory.GetFiles(Path.Combine(inputDirectory, "ballots")).OrderBy(x => x, StringComparer.Ordinal).ToArray();
    await using (writer)
    {
        var setupToc = await writer.WriteSetupAsync(new EncryptionRecord
        {
            CryptographicParameters = cryptographicParameters,
            GuardianParameters = guardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = guardianKeys,
            ElectionPublicKeys = electionPublicKeys,
            ExtendedBaseHash = extendedBaseHash,
        });
        Console.WriteLine($"Setup written: R_setup = {setupToc.Root}.");

        await using (var setupReader = await ElectionRecord.OpenAsync(recordDirectory))
        {
            var setup = await setupReader.ReadSetupAsync();
            foreach (var guardian in guardians)
            {
                guardian.Verify(setup.ToGuardianRecord(), manifestFile);
            }

            encryptionRecord = setup.ToEncryptionRecord();
        }

        var manifest = encryptionRecord.Manifest;

        // Encrypt a ballot
        string deviceId = "Device 1";
        var deviceHash = new VotingDeviceInformationHash(encryptionRecord.ExtendedBaseHash, deviceId);

        // Note 3.5: every exponentiation performed while encrypting and proving ballot components has a
        // base of g, K or K-hat, so build tables of their powers once before encrypting anything. This
        // is opt-in in the library because it costs memory and a moment of setup; a process about to
        // encrypt a directory full of ballots is exactly the case where it pays for itself.
        BallotEncryptor.PrecomputePowerTables(encryptionRecord);

        // The device's section of the record (§3.4.4, §3.7: "Ordered lists of the ballots encrypted
        // by each device"). Every ballot it encrypts, cast or challenged, is appended in the order
        // processed, here file name order; the section is closed when voting ends, with the chain's
        // close. Under simple chaining each ballot chains from the previous one's confirmation code,
        // so the device encrypts one at a time; under no chaining the ballots are independent and are
        // encrypted in parallel, then appended in file order.
        await using (var device = await writer.OpenDeviceAsync(deviceId, DeviceChainBallotKind.Encrypted))
        {
            EncryptedBallot EncryptBallotFile(string ballotFile, ConfirmationCode? previousConfirmationCode, Func<Ballot, Ballot>? change = null)
            {
                var ballot = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes(ballotFile), jsonOptions)!;
                return new BallotEncryptor(encryptionRecord, deviceId, deviceHash).Encrypt(change is null ? ballot : change(ballot), previousConfirmationCode);
            }

            // The voter sees the confirmation code and then casts or challenges the ballot (§3.7);
            // every ballot file here is cast. The status is recorded before the ballot is appended.
            if (manifest.ChainingMode == ChainingMode.None)
            {
                var encrypted = new EncryptedBallot[ballotFiles.Length];
                Parallel.For(0, ballotFiles.Length, i => encrypted[i] = EncryptBallotFile(ballotFiles[i], null));
                foreach (var ballot in encrypted)
                {
                    ballot.RecordStatus(BallotStatus.Cast);
                    await device.AppendAsync(ballot);
                }
            }
            else
            {
                foreach (var ballotFile in ballotFiles)
                {
                    var ballot = EncryptBallotFile(ballotFile, device.PreviousConfirmationCode);
                    ballot.RecordStatus(BallotStatus.Cast);
                    await device.AppendAsync(ballot);
                }
            }

            // Cast or challenge (§3.6.7, §3.7): a voter who challenges a ballot has it opened to check
            // that the device encrypted what they chose, and then votes again. The first ballot is
            // encrypted a second time, as a separate ballot with a fresh id_B and ballot nonce, and
            // that copy is challenged: it is never tallied, so the tally still counts the three cast
            // ballots.
            var challenged = EncryptBallotFile(ballotFiles[0], device.PreviousConfirmationCode, x => x with { Id = $"{x.Id}-challenged" });
            challenged.RecordStatus(BallotStatus.Challenged);
            await device.AppendAsync(challenged);

            // A ballot that is neither cast nor challenged, such as one the voter walked away from, is
            // recorded as spoiled (S10b #4). It was submitted: it stays in the device's chain and gets
            // Verifications 5 to 8 like any ballot, and its contests count for 11.D, but it is never
            // tallied and never decrypted. Here the first ballot is encrypted a third time and spoiled.
            var spoiled = EncryptBallotFile(ballotFiles[0], device.PreviousConfirmationCode, x => x with { Id = $"{x.Id}-spoiled" });
            spoiled.RecordStatus(BallotStatus.Spoiled);
            await device.AppendAsync(spoiled);

            // End of voting: the device closes its section with the chain's close (§3.4.4 eqs. 77/78
            // under simple chaining).
            var seal = (await device.CloseAsync(Now()))!;
            Console.WriteLine($"Device {seal.DeviceId}: {seal.BallotCount} ballots, chaining mode {seal.ChainingMode}{(seal.ClosingHash is { } closingHash ? $", closing hash {closingHash}" : "")}, section root {seal.SectionRoot}.");
        }

        Console.WriteLine($"Voting sealed: R_sealed = {(await writer.SealVotingAsync()).Root}.");

        // The administrator aggregates the cast ballots as the sealed record holds them; challenged and
        // spoiled ones are skipped here and in Verification 9. Every contest-data field of a cast
        // ballot is requested for decryption (§3.6.6: a real election requests only the fields it
        // needs, through a mixnet when the ballots are cast, p.49).
        List<(BallotLocator Locator, EncryptedBallot Ballot)> sealedBallots;
        await using (var sealedReader = await ElectionRecord.OpenAsync(recordDirectory))
        {
            sealedBallots = await ReadBallotsAsync(sealedReader, manifest);
        }

        var aggregated = new EncryptedTally(manifest);
        aggregated.AddBallots(sealedBallots.Select(x => x.Ballot));
        var requests = sealedBallots
            .Where(x => x.Ballot.Status == BallotStatus.Cast)
            .SelectMany(x => x.Ballot.Contests
                .Where(contest => contest.ContestData is not null)
                .Select(contest => new ContestDataRequest(x.Locator, x.Ballot.SelectionEncryptionIdentifierHash, manifest.Contests.Single(c => c.Id == contest.Id).Index)))
            .ToList();
        aggregatedRoot = (await writer.SealAggregatedAsync(aggregated, requests)).Root;
        Console.WriteLine($"Aggregate sealed: R_aggregated = {aggregatedRoot}, {requests.Count} contest-data request(s).");
    }

    // §3.6.1: before they decrypt anything, the guardians verify the aggregated record (Verifications
    // 1-9, 15 and 16) and decrypt exactly the encrypted tally that passed Verification 9, of the record
    // whose root they obtained out of band (Q36). VerifyAggregatedAsync also gives the guardians' view
    // of the sealed record's cast and spoiled ballots, which they check every challenged-ballot
    // request against (user decision Q31; spoiled ballots too, 2026-10-09).
    VerifiedAggregate aggregate;
    List<(BallotLocator Locator, EncryptedBallot Ballot)> ballots;
    VerificationReport preliminary;
    await using (var aggregatedReader = await ElectionRecord.OpenAsync(recordDirectory))
    {
        (preliminary, var verified) = await ElectionRecordVerifier.VerifyAggregatedAsync(aggregatedReader, new VerifyAllOptions { ExpectedAggregatedRoot = aggregatedRoot });
        Require(preliminary, "Guardians' preliminary verification of the aggregated record");
        aggregate = verified ?? throw new InvalidOperationException("The aggregated record yielded no verified aggregate.");
        ballots = await ReadBallotsAsync(aggregatedReader, aggregate.EncryptionRecord.Manifest);
    }

    var tallyGuardians = guardians
        .Select(guardian => new TallyGuardian(guardian.Index, guardianSecretShares[guardian.Index]))
        .ToList();
    var tallyAdmin = new TallyAdmin();

    // Verifiable decryption (§3.6.5) by every guardian, of the verified aggregate. TallyAdmin.Decrypt
    // mediates the three rounds: each guardian sends M_i with its commitment hash d_i, then reveals
    // (a_i, b_i) once it holds every d_j, then checks every d_j, computes the challenge itself and
    // responds with v_i. The administrator combines them into T and the proof (c, v), and checks the
    // proof before publishing it.
    var decryptedTally = tallyAdmin.Decrypt(tallyGuardians, aggregate);

    // Contest data (§3.6.6): every ballot carries an encrypted contest data field in each contest
    // whose manifest entry declares one (b_Λ >= 1), empty or not, so its write-in text can only be
    // found by decrypting it. The guardians decrypt each requested field with the same three rounds
    // as the tally, using their ballot data key shares; each guardian first checks the field's
    // Schnorr proof (eq. 69). The administrator publishes β, the proof (c, v) and the data D, which
    // Verification 12 checks.
    var ballotsByLocator = ballots.ToDictionary(x => x.Locator, x => x.Ballot);
    var contestData = ballots
        .Where(x => x.Ballot.Status == BallotStatus.Cast)
        .SelectMany(x => x.Ballot.Contests
            .Where(contest => contest.ContestData is not null)
            .Select(contest => (x.Ballot, Data: tallyAdmin.DecryptContestData(tallyGuardians, x.Ballot, contest.Id, aggregate.EncryptionRecord))))
        .ToList();

    // Challenged ballots (§3.6.7), the ones the preliminary verification listed. Each guardian
    // checks the ballot's encrypted nonce C_ξB (C_ξB,0 in Z_p^r and the eq. (38) Schnorr proof) and
    // sends m_i = C_ξB,0^ẑ_i; the administrator combines them into ξ_B, derives every encryption
    // nonce ξ_{i,j} (eq. 33) and contest data nonce ξ (eq. 64), and publishes those with the
    // plaintext selections and contest data, never ξ_B itself. The guardians refuse any nonce whose
    // id_B, H_I or C_ξB,0 matches a cast or spoiled ballot of the sealed record: a ballot's status is
    // only the requester's claim. Here every guardian is in-process, so the one view the verified
    // aggregate holds stands in for each guardian's own copy.
    var challengedBallots = preliminary.BallotsToOpen
        .Select(locator => ballotsByLocator[locator])
        .Select(ballot => (Ballot: ballot, Decrypted: tallyAdmin.DecryptChallengedBallot(tallyGuardians, ballot, aggregate.EncryptionRecord, aggregate.PublishedBallots)))
        .ToList();

    // The final phase (§3.7): the decryptions, then the decrypted tally. The writer was stopped after
    // the aggregate seal, as an administrator's process would be while the guardians work, and is
    // resumed from the record on disk.
    await using (var finalWriter = await ElectionRecord.ResumeAsync(recordDirectory))
    {
        foreach (var (ballot, data) in contestData)
        {
            await finalWriter.AddContestDataDecryptionAsync(ballot, data);
        }

        foreach (var (ballot, decrypted) in challengedBallots)
        {
            await finalWriter.AddChallengedDecryptionAsync(ballot, decrypted);
        }

        Console.WriteLine($"Record complete: R_final = {(await finalWriter.CompleteAsync(decryptedTally)).Root}.");
    }

    // Verify everything (design §6): Verifications 1-19 and every record-level rule, over the record
    // as it is on disk.
    TableOfContents protobufToc;
    await using (var finalReader = await ElectionRecord.OpenAsync(recordDirectory))
    {
        Require(await ElectionRecordVerifier.VerifyAllAsync(finalReader), "Full verification of the protobuf record");
        protobufToc = await ElectionRecord.ConvertAsync(finalReader, jsonRecord, RecordEncoding.Json, RecordCarrier.Zip);
    }

    // The same record in its JSON representation (the proto3 JSON mapping, design §5.5) in a .zip: a
    // conversion is correct exactly when it keeps every root (§5.1), and the copy verifies the same.
    await using (var jsonReader = await ElectionRecord.OpenAsync(jsonRecord))
    {
        var jsonToc = await ElectionRecord.ComputeTocAsync(jsonReader);
        if (jsonToc.Root != protobufToc.Root)
        {
            throw new InvalidOperationException($"The JSON copy's root {jsonToc.Root} is not the protobuf record's {protobufToc.Root}.");
        }

        Require(await ElectionRecordVerifier.VerifyAllAsync(jsonReader), $"Full verification of the JSON copy ({jsonRecord})");
    }

    foreach (var (_, data) in contestData)
    {
        var text = data.DecodeText();
        if (text.Length > 0)
        {
            Console.WriteLine($"Ballot {data.BallotId}, contest {data.ContestId}: contest data \"{text}\".");
        }
    }

    foreach (var (_, decrypted) in challengedBallots)
    {
        foreach (var contest in decrypted.Contests)
        {
            var selections = string.Join(", ", contest.Choices.Select(x => $"{x.Id}={x.Value}"));
            var text = contest.ContestData?.DecodeText();
            Console.WriteLine($"Challenged ballot {decrypted.BallotId}, contest {contest.ContestId}: {selections}{(string.IsNullOrEmpty(text) ? "" : $", contest data \"{text}\"")}.");
        }
    }

    foreach (var (contestId, contest) in decryptedTally.Contests)
    {
        Console.WriteLine($"Tally, contest {contestId}: {string.Join(", ", contest.Choices.Select(x => $"{x.Key}={x.Value.VoteCount}"))}.");
    }

    // A readable copy of the decrypted tally, outside the record (a derived view, design §5.6): per
    // contest label, its index, and per option and supplemental field its index, count t, T and the
    // proof (c, v), the values base64 of their fixed-width bytes. The record's decrypted_tally section
    // is the published form.
    using (var stream = File.Create(Path.Combine(outputDirectory, "tally.json")))
    using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
    {
        json.WriteStartObject();
        json.WriteStartObject("contests");
        foreach (var (contestId, contest) in decryptedTally.Contests)
        {
            json.WriteStartObject(contestId);
            json.WriteNumber("contestIndex", contest.ContestIndex);
            json.WriteStartObject("choices");
            foreach (var (choiceId, choice) in contest.Choices)
            {
                json.WriteStartObject(choiceId);
                json.WriteNumber("choiceIndex", choice.ChoiceIndex);
                json.WriteNumber("voteCount", choice.VoteCount);
                json.WriteBase64String("t", choice.T.ToByteArray());
                json.WriteBase64String("challenge", choice.Challenge.ToByteArray());
                json.WriteBase64String("response", choice.Response.ToByteArray());
                json.WriteEndObject();
            }

            json.WriteEndObject();
            json.WriteEndObject();
        }

        json.WriteEndObject();
        json.WriteEndObject();
    }

    Console.WriteLine("Done.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}

Console.ReadKey();
