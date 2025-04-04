// We're going to assume 2/3 guardians for now.
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Text.Json;

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
    var serializedGuardianRecord = JsonSerializer.Serialize(guardianRecord);
    File.WriteAllBytes(Path.Combine(outputDirectory, "guardian-record.json"), System.Text.Encoding.UTF8.GetBytes(serializedGuardianRecord));

    // Combine with manifest
    var manifestBytes = File.ReadAllBytes("../../../../../test/data/famous-names-manifest.json");
    var manifest = new ManifestFile
    {
        Bytes = manifestBytes
    };
    var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifest);
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
    };
    var serializedEncryptionRecord = JsonSerializer.Serialize(encryptionRecord);
    File.WriteAllBytes(Path.Combine(outputDirectory, "encryption-record.json"), System.Text.Encoding.UTF8.GetBytes(serializedEncryptionRecord));

    // Encrypt a ballot
    BallotEncryptor ballotEncryptor = new BallotEncryptor(encryptionRecord);
    ballotEncryptor.Encrypt();

    Console.WriteLine("Done.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}

Console.ReadKey();