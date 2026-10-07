// We're going to assume 2/3 guardians for now.
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Serialization.Converters;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.KeyGeneration;
using ElectionGuard.Core.Verify.Tally;
using System.Collections.Concurrent;
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

try
{
    // The manifest file. H_B = H(H_P; 0x01, manifest) (eq. 5) is part of the guardian record: each
    // guardian checks it by performing Verification 1 and keys its comparison hash H_G with it
    // (§3.2.2 step 1). The same bytes go into the encryption record (§3.7).
    var manifestBytes = File.ReadAllBytes(Path.Combine(inputDirectory, "manifest.json"));
    var manifestFile = new ManifestFile
    {
        Bytes = manifestBytes
    };
    var manifest = JsonSerializer.Deserialize<Manifest>(manifestBytes, jsonOptions)!;
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

    var guardianRecord = new GuardianRecord()
    {
        CryptographicParameters = cryptographicParameters,
        GuardianParameters = guardianParameters,
        ParameterBaseHash = EGParameters.ParameterBaseHash,
        ManifestFile = manifestFile,
        ElectionBaseHash = electionBaseHash,
        Guardians = guardianKeys,
        ElectionPublicKeys = electionPublicKeys,
    };

    foreach (var guardian in guardians)
    {
        guardian.Verify(guardianRecord, manifestFile);
    }

    // Write out guardian record
    Console.WriteLine("Writing out guardian record.");
    var serializedGuardianRecord = JsonSerializer.Serialize(guardianRecord, jsonOptions);
    File.WriteAllBytes(Path.Combine(outputDirectory, "guardian-record.json"), System.Text.Encoding.UTF8.GetBytes(serializedGuardianRecord));

    // Combine with manifest
    var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, electionPublicKeys);

    // Write out encryption record
    Console.WriteLine("Writing out encryption record.");
    var encryptionRecord = new EncryptionRecord
    {
        CryptographicParameters = cryptographicParameters,
        GuardianParameters = guardianParameters,
        ParameterBaseHash = EGParameters.ParameterBaseHash,
        ManifestFile = manifestFile,
        ElectionBaseHash = electionBaseHash,
        Guardians = guardianKeys,
        ElectionPublicKeys = electionPublicKeys,
        ExtendedBaseHash = extendedBaseHash,
        Manifest = manifest,
    };
    var serializedEncryptionRecord = JsonSerializer.Serialize(encryptionRecord, jsonOptions);
    File.WriteAllBytes(Path.Combine(outputDirectory, "encryption-record.json"), System.Text.Encoding.UTF8.GetBytes(serializedEncryptionRecord));


    var jsonBallotSerializer = new JsonEncryptedBallotSerializer();
    var protobufBallotSerializer = new ProtobufEncryptedBallotSerializer();
    // Encrypt a ballot
    string deviceId = "Device 1";
    var deviceHash = new VotingDeviceInformationHash(extendedBaseHash, deviceId);

    var ballots = Directory.GetFiles(Path.Combine(inputDirectory, "ballots"));

    // Note 3.5: every exponentiation performed while encrypting and proving ballot components has a
    // base of g, K or K-hat, so build tables of their powers once before encrypting anything. This
    // is opt-in in the library because it costs memory and a moment of setup; a process about to
    // encrypt a directory full of ballots is exactly the case where it pays for itself.
    BallotEncryptor.PrecomputePowerTables(encryptionRecord);

    ConcurrentBag<EncryptedBallot> encryptedBallots = new ConcurrentBag<EncryptedBallot>();

    Parallel.ForEach(ballots, ballotFile =>
    {
        var ballot = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes(ballotFile), jsonOptions)!;
        var ballotEncryptor = new BallotEncryptor(encryptionRecord, deviceId, deviceHash);
        var encryptedBallot = ballotEncryptor.Encrypt(ballot, null);

        // The voter sees the confirmation code and then casts or challenges the ballot (§3.7); every
        // ballot here is cast. The status is recorded with the ballot, so it is written out with it.
        encryptedBallot.RecordStatus(BallotStatus.Cast);
        encryptedBallots.Add(encryptedBallot);
        using (var jsonFileStream = File.OpenWrite(Path.Combine(outputDirectory, "encrypted-json-ballots", Path.GetFileName(ballotFile))))
        {
            jsonBallotSerializer.Serialize(jsonFileStream, encryptedBallot);
        }
        //using (var protobufFileStream = File.OpenWrite(Path.Combine(outputDirectory, "encrypted-protobuf-ballots", Path.GetFileNameWithoutExtension(ballotFile) + ".protobuf")))
        //{
        //    protobufBallotSerializer.Serialize(protobufFileStream, encryptedBallot);
        //}
    });

    // Cast or challenge (§3.6.7, §3.7): a voter who challenges a ballot has it opened to check that the
    // device encrypted what they chose, and then votes again. The first ballot is encrypted a second
    // time, as a separate ballot with a fresh id_B and ballot nonce, and that copy is challenged: it is
    // never tallied, so the tally still counts the three cast ballots.
    var challengedSource = ballots.OrderBy(x => x, StringComparer.Ordinal).First();
    var challengedPlaintext = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes(challengedSource), jsonOptions)!;
    challengedPlaintext = challengedPlaintext with { Id = $"{challengedPlaintext.Id}-challenged" };
    var challengedBallot = new BallotEncryptor(encryptionRecord, deviceId, deviceHash).Encrypt(challengedPlaintext, null);
    challengedBallot.RecordStatus(BallotStatus.Challenged);
    encryptedBallots.Add(challengedBallot);
    using (var jsonFileStream = File.Create(Path.Combine(outputDirectory, "encrypted-json-ballots", $"{challengedPlaintext.Id}.json")))
    {
        jsonBallotSerializer.Serialize(jsonFileStream, challengedBallot);
    }

    //BallotEncryptor ballotEncryptor = new BallotEncryptor(encryptionRecord, deviceId, deviceHash);
    //var ballot = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes("../../../../../test/data/famous-names/ballots/1.json"), jsonOptions)!;
    //var encryptedBallot = ballotEncryptor.Encrypt(ballot, null);

    //using (var jsonFileStream = File.OpenWrite(Path.Combine(outputDirectory, "encrypted-ballots", "1.json")))
    //{
    //    jsonBallotSerializer.Serialize(jsonFileStream, encryptedBallot);
    //}
    //using (var protobufFileStream = File.OpenWrite(Path.Combine(outputDirectory, "encrypted-ballots", "1.protobuf")))
    //{
    //    protobufBallotSerializer.Serialize(protobufFileStream, encryptedBallot);
    //}

    //var ballot2 = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes("../../../../../test/data/famous-names/ballots/2.json"), jsonOptions)!;
    //var encryptedBallot2 = ballotEncryptor.Encrypt(ballot2, encryptedBallot.ConfirmationCode);

    //using (var jsonFileStream = File.OpenWrite(Path.Combine(outputDirectory, "encrypted-ballots", "2.json")))
    //{
    //    jsonBallotSerializer.Serialize(jsonFileStream, encryptedBallot2);
    //}
    //using (var protobufFileStream = File.OpenWrite(Path.Combine(outputDirectory, "encrypted-ballots", "2.protobuf")))
    //{
    //    protobufBallotSerializer.Serialize(protobufFileStream, encryptedBallot2);
    //}

    //    TODO: SOMEWHERE NEEDS TO BE AN 'END OF ELECTION' FUNCTION(MAYBE TALLY ?) WHERE WE CLOSE THE CONFIRMATION CODE CHAIN.

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

        // Verificaiton 8
        var confirmationCodeVerification = new ConfirmationCodeVerification();
        confirmationCodeVerification.Verify(encryptedBallot, deviceHash, encryptionRecord, null);
    });

    // Only cast ballots are aggregated; a challenged one would be skipped here and in Verification 9.
    var encryptedTally = new EncryptedTally(manifest);
    foreach (var encryptedBallot in encryptedBallots)
    {
        encryptedTally.AddBallot(encryptedBallot);
    }

    // Verification 9
    var ballotAggregationVerification = new BallotAggregationVerification();
    ballotAggregationVerification.Verify(encryptedBallots.ToList(), manifest, encryptedTally);

    // Verifiable decryption (§3.6.5) by every guardian. TallyAdmin.Decrypt mediates the three rounds:
    // each guardian sends M_i with its commitment hash d_i, then reveals (a_i, b_i) once it holds
    // every d_j, then checks every d_j, computes the challenge itself and responds with v_i. The
    // administrator combines them into T and the proof (c, v), and checks the proof before
    // publishing it.
    var tallyGuardians = guardians
        .Select(guardian => new TallyGuardian(guardian.Index, guardianSecretShares[guardian.Index]))
        .ToList();
    var tallyAdmin = new TallyAdmin();
    var decryptedTally = tallyAdmin.Decrypt(tallyGuardians, encryptedTally, encryptionRecord);

    // Verification 10
    var tallyDecryptionVerification = new TallyDecryptionVerification();
    tallyDecryptionVerification.Verify(encryptionRecord, encryptedTally, decryptedTally);

    // Verification 11, with 11.D over every submitted ballot (cast or challenged).
    var tallyContentsVerification = new TallyContentsVerification();
    tallyContentsVerification.Verify(manifest, decryptedTally, encryptedBallots);

    // T, c and v are published with each count, hex-encoded like the ballots' values.
    var tallyJsonOptions = new JsonSerializerOptions
    {
        Converters =
        {
            new IntegerModPJsonConverter(),
            new IntegerModQJsonConverter(),
        },
    };
    var serializedDecryptedTally = JsonSerializer.Serialize(decryptedTally, tallyJsonOptions);
    File.WriteAllBytes(Path.Combine(outputDirectory, "tally.json"), System.Text.Encoding.UTF8.GetBytes(serializedDecryptedTally));

    // Contest data (§3.6.6): every ballot carries an encrypted contest data field in each contest
    // whose manifest entry declares one (b_Λ >= 1), empty or not, so its write-in text can only be
    // found by decrypting it. The guardians decrypt each field with the same three rounds as the
    // tally, using their ballot data key shares; each guardian first checks the field's Schnorr
    // proof (eq. 69). The administrator publishes β, the proof (c, v) and the data D, which
    // Verification 12 checks. A real election would decrypt only the fields it needs, through a
    // mixnet when the ballots are cast (§3.6.6 p.49); here every field of every ballot is decrypted.
    var contestDataDecryptionVerification = new ContestDataDecryptionVerification();
    var decryptedContestData = new List<object>();
    foreach (var encryptedBallot in encryptedBallots.Where(x => x.Status == BallotStatus.Cast).OrderBy(x => x.Id, StringComparer.Ordinal))
    {
        foreach (var contest in encryptedBallot.Contests.Where(x => x.ContestData is not null))
        {
            var decrypted = tallyAdmin.DecryptContestData(tallyGuardians, encryptedBallot, contest.Id, encryptionRecord);

            // Verification 12
            contestDataDecryptionVerification.Verify(encryptionRecord, encryptedBallot, decrypted);

            var text = decrypted.DecodeText();
            if (text.Length > 0)
            {
                Console.WriteLine($"Ballot {decrypted.BallotId}, contest {decrypted.ContestId}: contest data \"{text}\".");
            }

            decryptedContestData.Add(new
            {
                decrypted.BallotId,
                decrypted.ContestId,
                decrypted.ContestIndex,
                decrypted.Beta,
                decrypted.Challenge,
                decrypted.Response,
                Data = Convert.ToHexString(decrypted.Data),
                Text = text,
            });
        }
    }

    File.WriteAllBytes(Path.Combine(outputDirectory, "contest-data.json"), JsonSerializer.SerializeToUtf8Bytes(decryptedContestData, tallyJsonOptions));

    // Challenged ballots (§3.6.7). Each guardian checks the ballot's encrypted nonce C_ξB (C_ξB,0 in
    // Z_p^r and the eq. (38) Schnorr proof) and sends m_i = C_ξB,0^ẑ_i; the administrator combines them
    // into ξ_B, derives every encryption nonce ξ_{i,j} (eq. 33) and contest data nonce ξ (eq. 64), and
    // publishes those with the plaintext selections and contest data, never ξ_B itself. Verification
    // 13 recomputes the ballot's ciphertexts and confirmation code from them, and Verification 14
    // checks the labels and selection ranges against the manifest.
    var challengedBallotDecryptionVerification = new ChallengedBallotDecryptionVerification();
    var challengedBallotWellFormednessVerification = new ChallengedBallotWellFormednessVerification();
    var decryptedChallengedBallots = new List<DecryptedChallengedBallot>();
    foreach (var encryptedBallot in encryptedBallots.Where(x => x.Status == BallotStatus.Challenged).OrderBy(x => x.Id, StringComparer.Ordinal))
    {
        var decrypted = tallyAdmin.DecryptChallengedBallot(tallyGuardians, encryptedBallot, encryptionRecord);

        // Verification 13
        challengedBallotDecryptionVerification.Verify(encryptionRecord, encryptedBallot, decrypted, deviceHash, null);

        // Verification 14
        challengedBallotWellFormednessVerification.Verify(manifest, encryptedBallot, decrypted);

        foreach (var contest in decrypted.Contests)
        {
            var selections = string.Join(", ", contest.Choices.Select(x => $"{x.Id}={x.Value}"));
            var text = contest.ContestData?.DecodeText();
            Console.WriteLine($"Challenged ballot {decrypted.BallotId}, contest {contest.ContestId}: {selections}{(string.IsNullOrEmpty(text) ? "" : $", contest data \"{text}\"")}.");
        }

        decryptedChallengedBallots.Add(decrypted);
    }

    File.WriteAllBytes(Path.Combine(outputDirectory, "challenged-ballots.json"), JsonSerializer.SerializeToUtf8Bytes(decryptedChallengedBallots, tallyJsonOptions));

    Console.WriteLine("Done.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}

Console.ReadKey();
