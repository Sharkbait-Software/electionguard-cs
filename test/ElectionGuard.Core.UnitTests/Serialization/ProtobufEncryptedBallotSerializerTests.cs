using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.UnitTests.TestFixtures;
using ProtoBuf;

namespace ElectionGuard.Core.UnitTests.Serialization;

public class ProtobufEncryptedBallotSerializerTests
{
    public ProtobufEncryptedBallotSerializerTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    /// <summary>
    /// Same fixture ballot as JsonEncryptedBallotSerializerTests (kept as an independent private
    /// copy per this test project's existing per-class-helper convention -- see e.g.
    /// BallotEncryptorTests.BuildEncryptionRecord / EncryptedTallyTests.CreateHandCraftedBallot):
    /// both choices selected against SelectionLimit=1/OptionSelectionLimit=1 defaults triggers the
    /// overvote branch, plus a write-in count + ContestData string, so every EncryptedContest field
    /// (including the four optional counters and ContestData) is populated with real values.
    /// </summary>
    private static EncryptedBallot BuildRichEncryptedBallot()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");

        var ballot = ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1, ["choice-2"] = 1 },
            numWriteinsSelected: 1,
            contestData: "Write-In Candidate Name");

        return ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot);
    }

    private static void AssertEncryptedValueWithProofsEqual(EncryptedValueWithProofs expected, EncryptedValueWithProofs actual)
    {
        Assert.Equal(expected.Alpha, actual.Alpha);
        Assert.Equal(expected.Beta, actual.Beta);
        Assert.Equal(expected.Proofs.Length, actual.Proofs.Length);
        for (int i = 0; i < expected.Proofs.Length; i++)
        {
            Assert.Equal(expected.Proofs[i].Challenge, actual.Proofs[i].Challenge);
            Assert.Equal(expected.Proofs[i].Response, actual.Proofs[i].Response);
        }
    }

    private static void AssertDtoValueWithProofsMatchesDomain(
        EncryptedValueWithProofs domainValue,
        ProtobufEncryptedBallotSerializer.ProtobufEncryptedValueWithProofs dtoValue)
    {
        Assert.Equal((byte[])domainValue.Alpha, dtoValue.Alpha);
        Assert.Equal((byte[])domainValue.Beta, dtoValue.Beta);
        Assert.Equal(domainValue.Proofs.Length, dtoValue.Proofs.Length);
        for (int i = 0; i < domainValue.Proofs.Length; i++)
        {
            Assert.Equal((byte[])domainValue.Proofs[i].Challenge, dtoValue.Proofs[i].Challenge);
            Assert.Equal((byte[])domainValue.Proofs[i].Response, dtoValue.Proofs[i].Response);
        }
        // EncryptionNonce has no [ProtoMember] on ProtobufEncryptedValueWithProofs -- it never
        // reaches the wire at all (see RoundTrip_DoesNotAttemptToSerializeEncryptionNonce).
        Assert.Null(dtoValue.EncryptionNonce);
    }

    // ------------------------------------------------------------------------------------------
    // MAJOR FINDING FOR THIS PHASE: ProtobufEncryptedBallotSerializer.Deserialize() cannot
    // successfully process ANY EncryptedBallot that BallotEncryptor actually produces. Confirmed
    // via two independent, isolated root causes below. Per CLAUDE.md / task instructions, this is
    // pinned with regression tests, NOT fixed as part of test generation.
    // ------------------------------------------------------------------------------------------

    [Fact]
    public void RoundTrip_RealisticBallotWithSelections_ThrowsArgumentNullException_DueToMissingProtoIncludeOnSelection_KnownBug()
    {
        // GENUINE BUG #1, PINNED NOT FIXED. Root cause, confirmed via isolated repro against the
        // real production DTO types: `ProtobufEncryptedSelection : ProtobufEncryptedValueWithProofs`
        // (both [ProtoContract], see Serialization/IEncryptedBallotSerializer.cs) declares its own
        // additional [ProtoMember(4)] ChoiceId, but the base class is never linked back to the
        // derived type via a `[ProtoInclude(n, typeof(ProtobufEncryptedSelection))]` attribute.
        // Without that link, protobuf-net does not carry the base class's [ProtoMember(1..3)]
        // members (Alpha, Beta, Proofs) through a round trip of a ProtobufEncryptedSelection
        // instance -- only ChoiceId (declared directly on the derived type) survives; Alpha/Beta/
        // Proofs silently come back null. EncryptedContest.Choices always has one EncryptedSelection
        // per manifest choice regardless of vote value (see BallotEncryptor.EncryptContest), so
        // EVERY ballot BallotEncryptor produces hits this. The very next line in Deserialize()
        // (`s.Proofs.Select(...)`) then throws ArgumentNullException, so Deserialize cannot return
        // anything at all for a ballot with selections -- see
        // SerializedDto_NonListFields_RoundTripCorrectly_WhenInspectedDirectly below for proof that
        // every OTHER field in the DTO tree is wired correctly and it is genuinely only this one
        // derived/base relationship that is broken.
        var original = BuildRichEncryptedBallot();
        Assert.NotEmpty(original.Contests.Single().Choices);

        var serializer = new ProtobufEncryptedBallotSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, original);
        stream.Position = 0;

        Assert.Throws<ArgumentNullException>(() => serializer.Deserialize(stream));
    }

    [Fact]
    public void RoundTrip_ContestWithNoChoices_AlsoThrowsArgumentNullException_DueToEmptyRepeatedFieldBecomingNull_KnownBug()
    {
        // GENUINE BUG #2, PINNED NOT FIXED -- a second, independent root cause with the same
        // symptom. protobuf-net does not write any bytes at all for an empty repeated field
        // (List<T>), so on deserialize a List<T> property that was empty at serialize time comes
        // back as null rather than an empty list (this is standard protobuf-net/proto3 wire
        // behavior, not specific to this codebase). EncryptedContest.Choices is `required
        // List<EncryptedSelection>` with no default value, so an empty Choices list round-trips to
        // a null `c.Choices` on the DTO -- and Deserialize()'s `c.Choices.Select(...)` then throws
        // ArgumentNullException too, just at the CONTEST level instead of the SELECTION level (see
        // the other pinned bug above). Net effect: there is no possible Choices value -- empty or
        // populated -- for which ProtobufEncryptedBallotSerializer.Deserialize() succeeds on a
        // ballot with at least one contest, i.e. every real ballot.
        var realBallot = BuildRichEncryptedBallot();
        var contestWithNoChoices = realBallot.Contests.Single() with { Choices = new List<EncryptedSelection>() };
        var ballotWithEmptyChoices = new EncryptedBallot
        {
            Id = realBallot.Id,
            SelectionEncryptionIdentifier = realBallot.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = realBallot.SelectionEncryptionIdentifierHash,
            BallotStyleId = realBallot.BallotStyleId,
            DeviceId = realBallot.DeviceId,
            ConfirmationCode = realBallot.ConfirmationCode,
            Weight = realBallot.Weight,
            Contests = new List<EncryptedContest> { contestWithNoChoices },
        };

        var serializer = new ProtobufEncryptedBallotSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, ballotWithEmptyChoices);
        stream.Position = 0;

        Assert.Throws<ArgumentNullException>(() => serializer.Deserialize(stream));
    }

    [Fact]
    public void SerializedDto_NonListFields_RoundTripCorrectly_WhenInspectedDirectly()
    {
        // Because ProtobufEncryptedBallotSerializer.Deserialize() cannot successfully process ANY
        // real EncryptedBallot (both bugs pinned above), the only way left to fulfil this phase's
        // mandate -- "every field on EncryptedBallot/EncryptedContest/.../EncryptedData must be
        // asserted equal after round trip" -- is to inspect the wire bytes the real, UNMODIFIED
        // Serialize() method produces using a raw ProtoBuf.Serializer.Deserialize<...> call against
        // the actual production ProtobufEncryptedBallot DTO type, bypassing only the broken
        // hand-mapped Deserialize() orchestration that would otherwise throw. Every type used below
        // (ProtobufEncryptedBallot, ProtobufEncryptedContest, ProtobufEncryptedValueWithProofs,
        // ProtobufEncryptedData) is a real production nested type declared alongside
        // ProtobufEncryptedBallotSerializer in Serialization/IEncryptedBallotSerializer.cs, and the
        // bytes come from the real Serializer.Serialize call inside Serialize() -- nothing here
        // reinvents serialization logic, it only skips the one broken re-hydration step.
        var original = BuildRichEncryptedBallot();
        var serializer = new ProtobufEncryptedBallotSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, original);
        stream.Position = 0;

        var dto = Serializer.Deserialize<ProtobufEncryptedBallotSerializer.ProtobufEncryptedBallot>(stream);

        // Ballot-level fields.
        Assert.Equal(original.Id, dto.Id);
        Assert.Equal(original.BallotStyleId, dto.BallotStyleId);
        Assert.Equal(original.DeviceId, dto.DeviceId);
        Assert.Equal(original.Weight, dto.Weight);
        // Unlike JsonEncryptedBallotSerializer (see JsonEncryptedBallotSerializerTests'
        // RoundTrip_SelectionEncryptionIdentifier_IsDroppedByJsonSerializer_KnownBug),
        // ProtobufEncryptedBallotSerializer hand-maps SelectionEncryptionIdentifier to/from a raw
        // byte[] ProtoMember, so it survives correctly here.
        Assert.Equal((byte[])original.SelectionEncryptionIdentifier, dto.SelectionEncryptionIdentifier);
        Assert.Equal((byte[])original.SelectionEncryptionIdentifierHash, dto.SelectionEncryptionIdentifierHash);
        // ConfirmationCode is the field that folds the (currently no-op, see
        // BallotEncryptorTests.Encrypt_SecondBallotOnDevice_ChainingHasNoEffect...) ChainingField
        // into the ballot -- asserting it here is how this phase covers "ChainingField" per the
        // plan, since ChainingField itself is a transient input to BallotEncryptor.Encrypt and is
        // not a stored property of EncryptedBallot.
        Assert.Equal((byte[])original.ConfirmationCode, dto.ConfirmationCode);

        var originalContest = original.Contests.Single();
        var dtoContest = dto.Contests.Single();

        Assert.Equal(originalContest.Id, dtoContest.Id);
        Assert.Equal((byte[])originalContest.ContestHash, dtoContest.ContestHash);

        // Contest-level aggregate proofs (over the summed selection ciphertext) use the base
        // ChallengeResponsePair/byte[] mapping directly and are unaffected by the Choices bugs.
        Assert.Equal(originalContest.Proofs.Length, dtoContest.Proofs.Length);
        for (int p = 0; p < originalContest.Proofs.Length; p++)
        {
            Assert.Equal((byte[])originalContest.Proofs[p].Challenge, dtoContest.Proofs[p].Challenge);
            Assert.Equal((byte[])originalContest.Proofs[p].Response, dtoContest.Proofs[p].Response);
        }

        // The four optional counters are all typed as the BASE ProtobufEncryptedValueWithProofs
        // directly (no derived-type indirection), so -- unlike Choices -- they round-trip correctly.
        AssertDtoValueWithProofsMatchesDomain(originalContest.OvervoteCount, dtoContest.OvervoteCount);
        AssertDtoValueWithProofsMatchesDomain(originalContest.NullvoteCount, dtoContest.NullvoteCount);
        AssertDtoValueWithProofsMatchesDomain(originalContest.UndervoteCount, dtoContest.UndervoteCount);
        AssertDtoValueWithProofsMatchesDomain(originalContest.WriteInVoteCount, dtoContest.WriteInVoteCount);

        Assert.NotNull(originalContest.ContestData);
        Assert.NotNull(dtoContest.ContestData);
        Assert.Equal(originalContest.ContestData!.C0, dtoContest.ContestData!.C0);
        Assert.Equal(originalContest.ContestData!.C1, dtoContest.ContestData!.C1);
        Assert.Equal((byte[])originalContest.ContestData!.Challenge, dtoContest.ContestData!.Challenge);
        Assert.Equal((byte[])originalContest.ContestData!.Response, dtoContest.ContestData!.Response);

        // The bug, demonstrated here without a crash: each selection's own declared member
        // (ChoiceId) survives, but its INHERITED members (Alpha/Beta/Proofs, declared on the base
        // ProtobufEncryptedValueWithProofs) do not -- this is exactly what makes
        // ProtobufEncryptedBallotSerializer.Deserialize() throw ArgumentNullException for any real
        // ballot (see RoundTrip_RealisticBallotWithSelections_ThrowsArgumentNullException_
        // DueToMissingProtoIncludeOnSelection_KnownBug): it unconditionally does
        // `s.Proofs.Select(...)` for every selection, and Proofs is always null here.
        Assert.Equal(originalContest.Choices.Count, dtoContest.Choices.Count);
        foreach (var originalSelection in originalContest.Choices)
        {
            var dtoSelection = dtoContest.Choices.Single(s => s.ChoiceId == originalSelection.ChoiceId);
            Assert.Null(dtoSelection.Alpha);
            Assert.Null(dtoSelection.Beta);
            Assert.Null(dtoSelection.Proofs);
        }
    }

    [Fact]
    public void RoundTrip_DoesNotAttemptToSerializeEncryptionNonce()
    {
        // EncryptedValueWithProofs.EncryptionNonce has no [ProtoMember] attribute on either
        // ProtobufEncryptedValueWithProofs or ProtobufEncryptedValue (see
        // Serialization/IEncryptedBallotSerializer.cs) -- by design, for the same reason the JSON
        // serializer marks it [JsonIgnore]: the whole point of shipping an EncryptedBallot
        // off-device is that nobody downstream can recover the plaintext selection from it. Uses
        // the same direct-DTO-inspection technique as SerializedDto_NonListFields_
        // RoundTripCorrectly_WhenInspectedDirectly to avoid the unrelated pinned bugs above -- the
        // four counters checked here are unaffected by those bugs.
        var original = BuildRichEncryptedBallot();
        var originalContest = original.Contests.Single();
        Assert.NotNull(originalContest.OvervoteCount.EncryptionNonce);
        Assert.NotNull(originalContest.WriteInVoteCount.EncryptionNonce);

        var serializer = new ProtobufEncryptedBallotSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, original);
        stream.Position = 0;
        var dto = Serializer.Deserialize<ProtobufEncryptedBallotSerializer.ProtobufEncryptedBallot>(stream);
        var dtoContest = dto.Contests.Single();

        Assert.Null(dtoContest.OvervoteCount.EncryptionNonce);
        Assert.Null(dtoContest.NullvoteCount.EncryptionNonce);
        Assert.Null(dtoContest.UndervoteCount.EncryptionNonce);
        Assert.Null(dtoContest.WriteInVoteCount.EncryptionNonce);
    }

    [Fact]
    public void SerializedDto_ContestDataNull_MapsToNullWithoutThrowing_WhenNoWriteInProvided()
    {
        // Gap-closing test (verified via mutation analysis for this task): every other test in this
        // file builds ballots via BuildRichEncryptedBallot, which always supplies a write-in +
        // ContestData string, so EncryptedContest.ContestData is always non-null there and the
        // `c.ContestData != null ? new ProtobufEncryptedData {...} : null` null-check branch in
        // ProtobufEncryptedBallotSerializer.Serialize (see Serialization/IEncryptedBallotSerializer.cs)
        // never took its null path anywhere in this suite. Empirically confirmed: temporarily forcing
        // that ternary to always evaluate the non-null branch (i.e. dereferencing c.ContestData
        // unconditionally) left every other test in this file green, and only threw/failed once a
        // ballot with a genuinely null ContestData -- like the one built here -- exercised it. This
        // test builds such a ballot (no write-ins, no ContestData string) and confirms
        // Serialize() maps it to a null DTO ContestData without throwing. Uses the same
        // direct-DTO-inspection technique as SerializedDto_NonListFields_RoundTripCorrectly_
        // WhenInspectedDirectly to sidestep the unrelated pinned Choices bugs in Deserialize().
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: false);
        var encryptionRecordResult = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(encryptionRecordResult.ExtendedBaseHash, "device-1");
        var ballot = ElectionFixtureBuilder.CreateBallot(
            manifest,
            selectionValuesByChoiceId: new Dictionary<string, int> { ["choice-1"] = 1 });
        var original = ElectionFixtureBuilder.CreateEncryptedBallot(
            encryptionRecordResult.EncryptionRecord, "device-1", deviceHash, ballot);
        Assert.Null(original.Contests.Single().ContestData);

        var serializer = new ProtobufEncryptedBallotSerializer();
        using var stream = new MemoryStream();
        serializer.Serialize(stream, original);
        stream.Position = 0;

        var dto = Serializer.Deserialize<ProtobufEncryptedBallotSerializer.ProtobufEncryptedBallot>(stream);

        Assert.Null(dto.Contests.Single().ContestData);
    }

    [Fact]
    public void RoundTrip_JsonSucceedsWhileProtobufThrows_ForTheIdenticalRealisticBallot()
    {
        // This is the cross-serializer consistency check called for by the plan
        // (RoundTrip_JsonAndProtobufProduceEquivalentDomainObjects). The two DTO trees are NOT
        // equivalent: for the exact same realistic source ballot (real selections, an overvote, a
        // write-in, and ContestData), JsonEncryptedBallotSerializer round-trips successfully end to
        // end, while ProtobufEncryptedBallotSerializer throws ArgumentNullException and cannot
        // produce a domain object at all (see
        // RoundTrip_RealisticBallotWithSelections_ThrowsArgumentNullException_
        // DueToMissingProtoIncludeOnSelection_KnownBug for the root cause). That asymmetry -- one
        // serializer silently succeeding, the other crashing outright, for identical input -- is
        // exactly the kind of hand-mapping drift between the two DTO trees this phase exists to
        // catch, and it is far more severe than a single dropped field. Asserting "equivalent
        // domain objects" here would require pretending the crash doesn't happen; instead this test
        // pins the actual, asymmetric behavior.
        var original = BuildRichEncryptedBallot();

        var jsonSerializer = new JsonEncryptedBallotSerializer();
        using var jsonStream = new MemoryStream();
        jsonSerializer.Serialize(jsonStream, original);
        jsonStream.Position = 0;
        var jsonResult = jsonSerializer.Deserialize(jsonStream);

        Assert.NotNull(jsonResult);
        Assert.Equal(original.Id, jsonResult!.Id);

        var protobufSerializer = new ProtobufEncryptedBallotSerializer();
        using var protobufStream = new MemoryStream();
        protobufSerializer.Serialize(protobufStream, original);
        protobufStream.Position = 0;

        Assert.Throws<ArgumentNullException>(() => protobufSerializer.Deserialize(protobufStream));
    }
}
