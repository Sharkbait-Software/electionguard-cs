// We're going to assume 2/3 guardians for now.
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

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

    Console.WriteLine("Writing out encryption package.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex}");
}

Console.ReadKey();