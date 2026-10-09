// We're going to assume 2/3 guardians for now.
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.KeyGeneration;
using ElectionGuard.Core.Verify.Tally;
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

// Every record item is written out and read back before anything is checked against it, and the
// checks run on the copies read back: the pipeline below verifies the published record, not the
// objects that produced it (S10a).
var recordSerializer = new JsonElectionRecordSerializer();
var jsonBallotSerializer = new JsonEncryptedBallotSerializer();

T Publish<T>(string fileName, Action<Stream> write, Func<Stream, T> read)
{
    string path = Path.Combine(outputDirectory, fileName);
    using (var stream = File.Create(path))
    {
        write(stream);
    }

    using (var stream = File.OpenRead(path))
    {
        return read(stream);
    }
}

try
{
    // The manifest file. H_B = H(H_P; 0x01, manifest) (eq. 5) is part of the guardian record: each
    // guardian checks it by performing Verification 1 and keys its comparison hash H_G with it
    // (§3.2.2 step 1). The same bytes go into the encryption record (§3.7), which parses its
    // manifest from them (ManifestSerializer, the library's one manifest format).
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

    // The guardian record, written out and read back; every guardian checks the copy read back.
    Console.WriteLine("Writing out guardian record.");
    var guardianRecord = Publish("guardian-record.json",
        stream => recordSerializer.Serialize(stream, new GuardianRecord
        {
            CryptographicParameters = cryptographicParameters,
            GuardianParameters = guardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = guardianKeys,
            ElectionPublicKeys = electionPublicKeys,
        }),
        recordSerializer.DeserializeGuardianRecord);

    foreach (var guardian in guardians)
    {
        guardian.Verify(guardianRecord, manifestFile);
    }

    // Combine with manifest
    var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, electionPublicKeys);

    // The encryption record, written out and read back. Everything after this point, the device
    // included, uses the copy read back.
    Console.WriteLine("Writing out encryption record.");
    var encryptionRecord = Publish("encryption-record.json",
        stream => recordSerializer.Serialize(stream, new EncryptionRecord
        {
            CryptographicParameters = cryptographicParameters,
            GuardianParameters = guardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = guardianKeys,
            ElectionPublicKeys = electionPublicKeys,
            ExtendedBaseHash = extendedBaseHash,
        }),
        recordSerializer.DeserializeEncryptionRecord);
    var manifest = encryptionRecord.Manifest;

    // Encrypt a ballot
    string deviceId = "Device 1";
    var deviceHash = new VotingDeviceInformationHash(encryptionRecord.ExtendedBaseHash, deviceId);

    // In file name order, which is the order the device processes them in (§3.7: "Ordered lists of
    // the ballots encrypted by each device").
    var ballots = Directory.GetFiles(Path.Combine(inputDirectory, "ballots")).OrderBy(x => x, StringComparer.Ordinal).ToArray();

    // Note 3.5: every exponentiation performed while encrypting and proving ballot components has a
    // base of g, K or K-hat, so build tables of their powers once before encrypting anything. This
    // is opt-in in the library because it costs memory and a moment of setup; a process about to
    // encrypt a directory full of ballots is exactly the case where it pays for itself.
    BallotEncryptor.PrecomputePowerTables(encryptionRecord);

    // The device's confirmation code chain (§3.4.4). Every ballot it encrypts, cast or challenged, is
    // appended in the order processed; the chain is closed when voting ends and published as the
    // device's ordered ballot list. Under simple chaining each ballot chains from the previous one's
    // confirmation code, so the device encrypts one at a time; under no chaining the ballots are
    // independent and are encrypted in parallel, then appended in file order.
    var deviceChain = new DeviceChain(encryptionRecord, deviceId);
    var encryptedInOrder = new EncryptedBallot[ballots.Length];
    var publishedBallotFiles = new List<string>();

    void EncryptBallotFile(int i, ConfirmationCode? previousConfirmationCode)
    {
        var ballotFile = ballots[i];
        var ballot = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes(ballotFile), jsonOptions)!;
        var ballotEncryptor = new BallotEncryptor(encryptionRecord, deviceId, deviceHash);
        var encryptedBallot = ballotEncryptor.Encrypt(ballot, previousConfirmationCode);

        // The voter sees the confirmation code and then casts or challenges the ballot (§3.7); every
        // ballot here is cast. The status is recorded with the ballot, so it is written out with it.
        encryptedBallot.RecordStatus(BallotStatus.Cast);
        encryptedInOrder[i] = encryptedBallot;
        using (var jsonFileStream = File.Create(Path.Combine(outputDirectory, "encrypted-json-ballots", Path.GetFileName(ballotFile))))
        {
            jsonBallotSerializer.Serialize(jsonFileStream, encryptedBallot);
        }
    }

    if (manifest.ChainingMode == ChainingMode.None)
    {
        Parallel.For(0, ballots.Length, i => EncryptBallotFile(i, null));
        foreach (var encryptedBallot in encryptedInOrder)
        {
            deviceChain.Append(encryptedBallot);
        }
    }
    else
    {
        for (int i = 0; i < ballots.Length; i++)
        {
            EncryptBallotFile(i, deviceChain.PreviousConfirmationCode);
            deviceChain.Append(encryptedInOrder[i]);
        }
    }

    publishedBallotFiles.AddRange(ballots.Select(x => Path.Combine(outputDirectory, "encrypted-json-ballots", Path.GetFileName(x))));

    // Cast or challenge (§3.6.7, §3.7): a voter who challenges a ballot has it opened to check that the
    // device encrypted what they chose, and then votes again. The first ballot is encrypted a second
    // time, as a separate ballot with a fresh id_B and ballot nonce, and that copy is challenged: it is
    // never tallied, so the tally still counts the three cast ballots.
    var challengedSource = ballots.OrderBy(x => x, StringComparer.Ordinal).First();
    var challengedPlaintext = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes(challengedSource), jsonOptions)!;
    challengedPlaintext = challengedPlaintext with { Id = $"{challengedPlaintext.Id}-challenged" };
    var challengedBallot = new BallotEncryptor(encryptionRecord, deviceId, deviceHash).EncryptNext(challengedPlaintext, deviceChain);
    challengedBallot.RecordStatus(BallotStatus.Challenged);
    var challengedFile = Path.Combine(outputDirectory, "encrypted-json-ballots", $"{challengedPlaintext.Id}.json");
    using (var jsonFileStream = File.Create(challengedFile))
    {
        jsonBallotSerializer.Serialize(jsonFileStream, challengedBallot);
    }

    publishedBallotFiles.Add(challengedFile);

    // End of voting: the device closes its confirmation code chain (§3.4.4 eqs. 77/78 under simple
    // chaining) and publishes its ordered list of ballots with the closing hash (§3.7), read back
    // like every other record item.
    var deviceChainRecords = Publish("device-chains.json",
        stream => new JsonDeviceChainRecordSerializer().Serialize(stream, [deviceChain.Close()]),
        stream => new JsonDeviceChainRecordSerializer().Deserialize(stream)!);
    var deviceChainRecord = deviceChainRecords.Single();

    Console.WriteLine($"Device {deviceChainRecord.DeviceId}: {deviceChainRecord.ConfirmationCodes.Count} ballots, chaining mode {deviceChainRecord.ChainingMode}{(deviceChainRecord.ClosingHash is { } closingHash ? $", closing hash {closingHash}" : "")}.");

    // The published ballots, read back from the files the device wrote. Every check below, and the
    // tally, uses these.
    var encryptedBallots = publishedBallotFiles.Select(path =>
    {
        using var stream = File.OpenRead(path);
        return jsonBallotSerializer.Deserialize(stream)!;
    }).ToList();

    // Verification 1 (1.A-1.F, H_B included) on the encryption record
    var parameterVerification = new ParameterVerification();
    parameterVerification.Verify(encryptionRecord);

    // Verification 2
    var guardianPublicKeyVerification = new GuardianPublicKeyVerification();
    guardianPublicKeyVerification.Verify(encryptionRecord.Guardians);

    // Verification 3
    var electionPublicKeyVerification = new ElectionPublicKeyVerification();
    electionPublicKeyVerification.Verify(encryptionRecord.Guardians, encryptionRecord.ElectionPublicKeys);

    // Verification 4
    var extendedBaseHashVerification = new ExtendedBaseHashVerification();
    extendedBaseHashVerification.Verify(encryptionRecord.ExtendedBaseHash, encryptionRecord.ElectionBaseHash, encryptionRecord.ElectionPublicKeys);

    // Verification 5.A, over the identifiers of every submitted ballot at once: a list per ballot
    // would check nothing.
    var selectionEncryptionIdentifierVerification = new SelectionEncryptionIdentifierVerification();
    selectionEncryptionIdentifierVerification.Verify(encryptedBallots.Select(x => x.SelectionEncryptionIdentifier).ToList());

    Parallel.ForEach(encryptedBallots, encryptedBallot =>
    {
        // Verification 5.B
        selectionEncryptionIdentifierVerification.Verify(encryptedBallot.SelectionEncryptionIdentifier, encryptedBallot.SelectionEncryptionIdentifierHash, encryptionRecord.ExtendedBaseHash);

        // Verification 6
        var selectionEncryptionsWellFormedVerification = new SelectionEncryptionsWellFormedVerification();
        selectionEncryptionsWellFormedVerification.Verify(encryptedBallot, encryptionRecord);

        // Verification 7
        var adherenceToVoteLimitsVerification = new AdherenceToVoteLimitsVerification();
        adherenceToVoteLimitsVerification.Verify(encryptedBallot, encryptionRecord);

        // Verification 8, per ballot: 8.A, 8.B over the ballot's chaining field, 8.D (no chaining).
        var confirmationCodeVerification = new ConfirmationCodeVerification();
        confirmationCodeVerification.Verify(encryptedBallot, encryptionRecord);
    });

    // Verification 8, per device: every ballot on exactly one device's list, 8.C, and in list order
    // 8.D/8.E, then 8.F and 8.G under simple chaining.
    new ConfirmationCodeVerification().VerifyDevices(deviceChainRecords, encryptedBallots, encryptionRecord);

    // Only cast ballots are aggregated; a challenged one would be skipped here and in Verification 9.
    // The encrypted tally is published and read back; the copy read back restores each option's
    // decryption bound from its contest's published cast weight.
    var aggregated = new EncryptedTally(manifest);
    aggregated.AddBallots(encryptedBallots);
    var encryptedTally = Publish("encrypted-tally.json",
        stream => recordSerializer.Serialize(stream, aggregated),
        stream => recordSerializer.DeserializeEncryptedTally(stream, manifest));

    // Verification 9, which also checks the published cast weights and ballot count.
    var ballotAggregationVerification = new BallotAggregationVerification();
    ballotAggregationVerification.Verify(encryptedBallots, manifest, encryptedTally);

    // Verifiable decryption (§3.6.5) by every guardian, of the tally as read back. TallyAdmin.Decrypt
    // mediates the three rounds: each guardian sends M_i with its commitment hash d_i, then reveals
    // (a_i, b_i) once it holds every d_j, then checks every d_j, computes the challenge itself and
    // responds with v_i. The administrator combines them into T and the proof (c, v), and checks the
    // proof before publishing it.
    var tallyGuardians = guardians
        .Select(guardian => new TallyGuardian(guardian.Index, guardianSecretShares[guardian.Index]))
        .ToList();
    var tallyAdmin = new TallyAdmin();

    // T, c and v are published with each count (§3.7), with the contest and option indices.
    var decryptedTally = Publish("tally.json",
        stream => recordSerializer.Serialize(stream, tallyAdmin.Decrypt(tallyGuardians, encryptedTally, encryptionRecord)),
        recordSerializer.DeserializeDecryptedTally);

    // Verification 10
    var tallyDecryptionVerification = new TallyDecryptionVerification();
    tallyDecryptionVerification.Verify(encryptionRecord, encryptedTally, decryptedTally);

    // Verification 11, with 11.D over every submitted ballot (cast or challenged).
    var tallyContentsVerification = new TallyContentsVerification();
    tallyContentsVerification.Verify(manifest, decryptedTally, encryptedBallots);

    // Contest data (§3.6.6): every ballot carries an encrypted contest data field in each contest
    // whose manifest entry declares one (b_Λ >= 1), empty or not, so its write-in text can only be
    // found by decrypting it. The guardians decrypt each field with the same three rounds as the
    // tally, using their ballot data key shares; each guardian first checks the field's Schnorr
    // proof (eq. 69). The administrator publishes β, the proof (c, v) and the data D, which
    // Verification 12 checks. A real election would decrypt only the fields it needs, through a
    // mixnet when the ballots are cast (§3.6.6 p.49); here every field of every ballot is decrypted.
    var castInOrder = encryptedBallots.Where(x => x.Status == BallotStatus.Cast).OrderBy(x => x.Id, StringComparer.Ordinal).ToList();
    var decryptedContestData = Publish("contest-data.json",
        stream => recordSerializer.Serialize(stream, castInOrder
            .SelectMany(ballot => ballot.Contests
                .Where(x => x.ContestData is not null)
                .Select(contest => tallyAdmin.DecryptContestData(tallyGuardians, ballot, contest.Id, encryptionRecord)))
            .ToList()),
        recordSerializer.DeserializeDecryptedContestData);

    var contestDataDecryptionVerification = new ContestDataDecryptionVerification();
    var ballotsById = encryptedBallots.ToDictionary(x => x.Id, StringComparer.Ordinal);
    foreach (var decrypted in decryptedContestData)
    {
        // Verification 12
        contestDataDecryptionVerification.Verify(encryptionRecord, ballotsById[decrypted.BallotId], decrypted);

        var text = decrypted.DecodeText();
        if (text.Length > 0)
        {
            Console.WriteLine($"Ballot {decrypted.BallotId}, contest {decrypted.ContestId}: contest data \"{text}\".");
        }
    }

    // Challenged ballots (§3.6.7). Each guardian checks the ballot's encrypted nonce C_ξB (C_ξB,0 in
    // Z_p^r and the eq. (38) Schnorr proof) and sends m_i = C_ξB,0^ẑ_i; the administrator combines them
    // into ξ_B, derives every encryption nonce ξ_{i,j} (eq. 33) and contest data nonce ξ (eq. 64), and
    // publishes those with the plaintext selections and contest data, never ξ_B itself. Verification
    // 13 recomputes the ballot's ciphertexts and confirmation code from them, and Verification 14
    // checks the labels and selection ranges against the manifest.
    //
    // The guardians refuse any nonce whose id_B, H_I or C_ξB,0 matches a cast ballot of the
    // published record (user decision Q31): a ballot's status is only the requester's claim. Here
    // every guardian is in-process, so one view of the record's cast ballots stands in for each
    // guardian's own copy.
    var castBallots = PublishedCastBallots.FromRecord(encryptionRecord.ExtendedBaseHash, encryptedBallots);
    var challengedInOrder = encryptedBallots.Where(x => x.Status == BallotStatus.Challenged).OrderBy(x => x.Id, StringComparer.Ordinal).ToList();
    var decryptedChallengedBallots = Publish("challenged-ballots.json",
        stream => recordSerializer.Serialize(stream, challengedInOrder
            .Select(ballot => tallyAdmin.DecryptChallengedBallot(tallyGuardians, ballot, encryptionRecord, castBallots))
            .ToList()),
        recordSerializer.DeserializeDecryptedChallengedBallots);

    var challengedBallotDecryptionVerification = new ChallengedBallotDecryptionVerification();
    var challengedBallotWellFormednessVerification = new ChallengedBallotWellFormednessVerification();
    foreach (var decrypted in decryptedChallengedBallots)
    {
        var encryptedBallot = ballotsById[decrypted.BallotId];

        // Verification 13
        challengedBallotDecryptionVerification.Verify(encryptionRecord, encryptedBallot, decrypted);

        // Verification 14
        challengedBallotWellFormednessVerification.Verify(manifest, encryptedBallot, decrypted);

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

    Console.WriteLine("Done.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}

Console.ReadKey();
