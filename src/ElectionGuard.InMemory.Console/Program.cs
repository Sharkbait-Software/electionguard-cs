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

try
{
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

    List<GuardianSecretShares> guardianSecretShares = new List<GuardianSecretShares>();
    foreach (var guardian in guardians)
    {
        var secretShares = guardian.DecryptShares(guardianEncryptedShares.Where(x => x.DestinationIndex == guardian.Index).ToList());
        guardianSecretShares.Add(secretShares);
    }

    var electionPublicKeys = new ElectionPublicKeys(
        guardianKeys.SelectMany(x => x.VoteEncryptionCommitments),
        guardianKeys.SelectMany(x => x.OtherBallotDataEncryptionCommitments));

    var guardianRecord = new GuardianRecord()
    {
        CryptographicParameters = cryptographicParameters,
        GuardianParameters = guardianParameters,
        ParameterBaseHash = EGParameters.ParameterBaseHash,
        Guardians = guardianKeys,
        ElectionPublicKeys = electionPublicKeys,
    };

    foreach (var guardian in guardians)
    {
        guardian.Verify(guardianRecord);
    }

    // Write out guardian record
    Console.WriteLine("Writing out guardian record.");
    var serializedGuardianRecord = JsonSerializer.Serialize(guardianRecord, jsonOptions);
    File.WriteAllBytes(Path.Combine(outputDirectory, "guardian-record.json"), System.Text.Encoding.UTF8.GetBytes(serializedGuardianRecord));

    // Combine with manifest
    var manifestBytes = File.ReadAllBytes(Path.Combine(inputDirectory, "manifest.json"));
    var manifestFile = new ManifestFile
    {
        Bytes = manifestBytes
    };
    var manifest = JsonSerializer.Deserialize<Manifest>(manifestBytes, jsonOptions)!;
    var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
    var extendedBaseHash = new ExtendedBaseHash(electionBaseHash, electionPublicKeys);

    // Write out encryption record
    Console.WriteLine("Writing out encryption record.");
    var encryptionRecord = new EncryptionRecord
    {
        CryptographicParameters = cryptographicParameters,
        GuardianParameters = guardianParameters,
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

    Parallel.ForEach(ballots, ballotFile =>
    {
        var ballot = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes(ballotFile), jsonOptions)!;
        var ballotEncryptor = new BallotEncryptor(encryptionRecord, deviceId, deviceHash);
        var encryptedBallot = ballotEncryptor.Encrypt(ballot, null);
        using (var jsonFileStream = File.OpenWrite(Path.Combine(outputDirectory, "encrypted-json-ballots", Path.GetFileName(ballotFile))))
        {
            jsonBallotSerializer.Serialize(jsonFileStream, encryptedBallot);
        }
        using (var protobufFileStream = File.OpenWrite(Path.Combine(outputDirectory, "encrypted-protobuf-ballots", Path.GetFileNameWithoutExtension(ballotFile) + ".protobuf")))
        {
            protobufBallotSerializer.Serialize(protobufFileStream, encryptedBallot);
        }
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

    // TODO: SOMEWHERE NEEDS TO BE AN 'END OF ELECTION' FUNCTION (MAYBE TALLY?) WHERE WE CLOSE THE CONFIRMATION CODE CHAIN.

    // Verification 4
    //var extendedBaseHashVerification = new ExtendedBaseHashVerification();
    //extendedBaseHashVerification.Verify(extendedBaseHash, electionBaseHash, electionPublicKeys);
    
    //// Verification 5
    //var selectionEncryptionIdentifierVerification = new SelectionEncryptionIdentifierVerification();
    //var selectionEncryptionIdentifiers = new List<SelectionEncryptionIdentifier>();
    //selectionEncryptionIdentifiers.Add(encryptedBallot.SelectionEncryptionIdentifier);
    //selectionEncryptionIdentifiers.Add(encryptedBallot2.SelectionEncryptionIdentifier);
    //selectionEncryptionIdentifierVerification.Verify(selectionEncryptionIdentifiers);

    //// Verification 6
    //var selectionEncryptionsWellFormedVerification = new SelectionEncryptionsWellFormedVerification();
    //selectionEncryptionsWellFormedVerification.Verify(encryptedBallot, encryptionRecord);
    //selectionEncryptionsWellFormedVerification.Verify(encryptedBallot2, encryptionRecord);

    //// Verification 7
    //var adherenceToVoteLimitsVerification = new AdherenceToVoteLimitsVerification();
    //adherenceToVoteLimitsVerification.Verify(encryptedBallot, encryptionRecord);
    //adherenceToVoteLimitsVerification.Verify(encryptedBallot2, encryptionRecord);

    //// Verificaiton 8
    //var confirmationCodeVerification = new ConfirmationCodeVerification();
    //confirmationCodeVerification.Verify(encryptedBallot, deviceHash, encryptionRecord, null);
    //confirmationCodeVerification.Verify(encryptedBallot2, deviceHash, encryptionRecord, null);

    //var encryptedTally = new EncryptedTally(manifest);
    //encryptedTally.AddBallot(encryptedBallot);
    //encryptedTally.AddBallot(encryptedBallot2);

    //// Verification 9
    //var ballotAggregationVerification = new BallotAggregationVerification();
    //ballotAggregationVerification.Verify(new List<EncryptedBallot> { encryptedBallot, encryptedBallot2 }, manifest, encryptedTally);

    Console.WriteLine("Done.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}

Console.ReadKey();