using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Testing.Common;
using System.Text;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// S5: the supplemental fields are a manifest-indexed list on <see cref="EncryptedContest"/>, keyed
/// by label, and a contest may carry the undervote difference proof and (S5b) the null-vote proof.
/// Both serializers carry all three
/// (CLAUDE.md: a field added to an encrypted-ballot type goes into the domain type and the protobuf
/// DTO), and a decoded ballot still passes Verifications 6 to 8.
/// </summary>
public class SupplementalFieldSerializationTests
{
    public SupplementalFieldSerializationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    public static TheoryData<string> Serializers() => new() { "json", "protobuf" };

    private static IEncryptedBallotSerializer Serializer(string name) =>
        name == "json" ? new JsonEncryptedBallotSerializer() : new ProtobufEncryptedBallotSerializer();

    private static (EncryptedBallot Ballot, EncryptionRecord Record, VotingDeviceInformationHash DeviceHash) Encrypt(IReadOnlyList<SupplementalFieldKind> kinds)
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(
            selectionLimit: 2,
            supplementalFields: kinds,
            // Write-ins only where the count is declared (Manifest.Validate, user decision Q19).
            writeInFieldCount: kinds.Contains(SupplementalFieldKind.WriteInCount) ? 2 : 0);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, "device-1");
        var ballot = ElectionFixtureBuilder.CreateBallot(
            manifest, selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 }, numWriteinsSelected: kinds.Contains(SupplementalFieldKind.WriteInCount) ? 1 : 0);
        return (ElectionFixtureBuilder.CreateEncryptedBallot(records.EncryptionRecord, "device-1", deviceHash, ballot), records.EncryptionRecord, deviceHash);
    }

    private static (EncryptedBallot Ballot, byte[] Encoded) RoundTrip(string serializerName, EncryptedBallot ballot)
    {
        var serializer = Serializer(serializerName);
        using var stream = new MemoryStream();
        serializer.Serialize(stream, ballot);
        var encoded = stream.ToArray();
        stream.Position = 0;
        return (serializer.Deserialize(stream)!, encoded);
    }

    [Theory]
    [MemberData(nameof(Serializers))]
    public void RoundTrip_KeepsEveryFieldInOrder_AndTheRelationProofs_AndStillVerifies(string serializerName)
    {
        var (original, record, deviceHash) = Encrypt(ElectionFixtureBuilder.AllSupplementalFields);

        var (result, _) = RoundTrip(serializerName, original);

        var originalContest = original.Contests.Single();
        var resultContest = result.Contests.Single();
        Assert.Equal(originalContest.SupplementalFields.Select(x => x.FieldId), resultContest.SupplementalFields.Select(x => x.FieldId));
        for (int i = 0; i < originalContest.SupplementalFields.Count; i++)
        {
            var expected = originalContest.SupplementalFields[i];
            var actual = resultContest.SupplementalFields[i];
            Assert.Equal(expected.Alpha, actual.Alpha);
            Assert.Equal(expected.Beta, actual.Beta);
            Assert.Equal(expected.Proofs, actual.Proofs);
            Assert.Null(actual.EncryptionNonce);
        }

        Assert.Equal(originalContest.UndervoteDifferenceProof, resultContest.UndervoteDifferenceProof);
        Assert.Single(resultContest.UndervoteDifferenceProof!);
        Assert.Equal(originalContest.NullVoteProof, resultContest.NullVoteProof);
        Assert.Equal(3, resultContest.NullVoteProof!.Length);

        new SelectionEncryptionsWellFormedVerification().Verify(result, record);
        new AdherenceToVoteLimitsVerification().Verify(result, record);
        new ConfirmationCodeVerification().Verify(result, deviceHash, record, null);
    }

    [Theory]
    [MemberData(nameof(Serializers))]
    public void RoundTrip_ContestWithoutAnUndervoteDifferenceCountOrNullVoteIndicator_HasNoRelationProof(string serializerName)
    {
        var (original, record, _) = Encrypt([SupplementalFieldKind.OvervoteIndicator]);
        Assert.Null(original.Contests.Single().UndervoteDifferenceProof);
        Assert.Null(original.Contests.Single().NullVoteProof);

        var (result, encoded) = RoundTrip(serializerName, original);

        Assert.Null(result.Contests.Single().UndervoteDifferenceProof);
        Assert.Null(result.Contests.Single().NullVoteProof);
        if (serializerName == "json")
        {
            Assert.DoesNotContain("undervoteDifferenceProof", Encoding.UTF8.GetString(encoded), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("nullVoteProof", Encoding.UTF8.GetString(encoded), StringComparison.OrdinalIgnoreCase);
        }

        new AdherenceToVoteLimitsVerification().Verify(result, record);
    }

    [Theory]
    [MemberData(nameof(Serializers))]
    public void RoundTrip_ContestWithoutSupplementalFields_DecodesAnEmptyList(string serializerName)
    {
        // Protobuf writes nothing for an empty list; it decodes as empty, not null.
        var (original, record, _) = Encrypt([]);

        var (result, _) = RoundTrip(serializerName, original);

        Assert.Empty(result.Contests.Single().SupplementalFields);
        new SelectionEncryptionsWellFormedVerification().Verify(result, record);
    }
}
