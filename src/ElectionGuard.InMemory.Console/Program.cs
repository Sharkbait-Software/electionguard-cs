// We're going to assume 2/3 guardians for now.
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Text.Json;

var jsonOptions = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
};

CryptographicParameters cryptographicParameters = new CryptographicParameters();
GuardianParameters guardianParameters = new GuardianParameters();
EGParameters.Init(cryptographicParameters, guardianParameters);

// Assume the following directory for writing out the encryption package.
string outputDirectory = @"c:\temp\eg\";

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
    var manifestBytes = File.ReadAllBytes("../../../../../test/data/famous-names/manifest.json");
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

    // Encrypt a ballot
    var deviceHash = new VotingDeviceInformationHash(extendedBaseHash, "Device 1");
    BallotEncryptor ballotEncryptor = new BallotEncryptor(encryptionRecord, deviceHash);
    var ballot = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes("../../../../../test/data/famous-names/ballots/1.json"), jsonOptions)!;
    var encryptedBallot = ballotEncryptor.Encrypt(ballot, null);
    var serializedEncryptedBallot = JsonSerializer.Serialize(encryptedBallot, jsonOptions);
    File.WriteAllBytes(Path.Combine(outputDirectory, "encrypted-ballots", "1.json"), System.Text.Encoding.UTF8.GetBytes(serializedEncryptedBallot));

    var ballot2 = JsonSerializer.Deserialize<Ballot>(File.ReadAllBytes("../../../../../test/data/famous-names/ballots/2.json"), jsonOptions)!;
    var encryptedBallot2 = ballotEncryptor.Encrypt(ballot2, encryptedBallot.ConfirmationCode);
    var serializedEncryptedBallot2 = JsonSerializer.Serialize(encryptedBallot2, jsonOptions);
    File.WriteAllBytes(Path.Combine(outputDirectory, "encrypted-ballots", "2.json"), System.Text.Encoding.UTF8.GetBytes(serializedEncryptedBallot2));

    // TODO: SOMEWHERE NEEDS TO BE AN 'END OF ELECTION' FUNCTION (MAYBE TALLY?) WHERE WE CLOSE THE CONFIRMATION CODE CHAIN.

    Console.WriteLine("Done.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}

Console.ReadKey();