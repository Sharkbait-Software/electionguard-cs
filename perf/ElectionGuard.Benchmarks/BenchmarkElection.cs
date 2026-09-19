using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Benchmarks;

/// <summary>
/// One bootstrapped election shared by every benchmark class. DKG is expensive and is not what any
/// of these benchmarks measure, so it happens once in [GlobalSetup] and never inside a measured
/// method.
/// </summary>
public sealed class BenchmarkElection
{
    public const string DeviceId = "benchmark-device";

    private BenchmarkElection(
        ElectionFixtureBuilder.GuardianSetResult guardians,
        Manifest manifest,
        EncryptionRecord encryptionRecord,
        VotingDeviceInformationHash deviceHash)
    {
        Guardians = guardians;
        Manifest = manifest;
        EncryptionRecord = encryptionRecord;
        DeviceHash = deviceHash;
    }

    public ElectionFixtureBuilder.GuardianSetResult Guardians { get; }
    public Manifest Manifest { get; }
    public EncryptionRecord EncryptionRecord { get; }
    public VotingDeviceInformationHash DeviceHash { get; }

    public static BenchmarkElection Create()
    {
        var guardians = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardians, manifest, manifestFile);

        return new BenchmarkElection(
            guardians,
            manifest,
            records.EncryptionRecord,
            new VotingDeviceInformationHash(records.ExtendedBaseHash, DeviceId));
    }

    public BallotEncryptor CreateEncryptor() => new(EncryptionRecord, DeviceId, DeviceHash);

    public Ballot GenerateBallot(int index) => new BallotGenerator(Manifest, seed: 20260907).Generate(index);

    public EncryptedBallot EncryptBallot(int index) => CreateEncryptor().Encrypt(GenerateBallot(index), null);
}
