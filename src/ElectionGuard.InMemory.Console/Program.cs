// We're going to assume 2/3 guardians for now.
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
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

    // Verification 5
    Parallel.ForEach(encryptedBallots, encryptedBallot =>
    {
        var selectionEncryptionIdentifierVerification = new SelectionEncryptionIdentifierVerification();
        var selectionEncryptionIdentifiers = new List<SelectionEncryptionIdentifier>();
        selectionEncryptionIdentifiers.Add(encryptedBallot.SelectionEncryptionIdentifier);
        selectionEncryptionIdentifierVerification.Verify(selectionEncryptionIdentifiers);

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

    var encryptedTally = new EncryptedTally(manifest);
    foreach (var encryptedBallot in encryptedBallots)
    {
        encryptedTally.AddBallot(encryptedBallot);
    }

    // Verification 9
    var ballotAggregationVerification = new BallotAggregationVerification();
    ballotAggregationVerification.Verify(encryptedBallots.ToList(), manifest, encryptedTally);

    List<PartialTallyDecryption> partialTallyDecryptions = new List<PartialTallyDecryption>();
    foreach(var guardian in guardians)
    {
        var tallyGuardian = new TallyGuardian(guardian.Index, guardianSecretShares[guardian.Index]);
        var partialDecryption = tallyGuardian.Decrypt(encryptedTally);
        partialTallyDecryptions.Add(partialDecryption);
    }

    var tallyAdmin = new TallyAdmin();
    var decryptedTally = tallyAdmin.Decrypt(partialTallyDecryptions, encryptedTally, electionPublicKeys);
    var serializedDecryptedTally = JsonSerializer.Serialize(decryptedTally);
    File.WriteAllBytes(Path.Combine(outputDirectory, "tally.json"), System.Text.Encoding.UTF8.GetBytes(serializedDecryptedTally));

    Console.WriteLine("Done.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}

Console.ReadKey();
