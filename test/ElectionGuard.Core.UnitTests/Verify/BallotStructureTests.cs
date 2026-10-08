using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;
using System.Text.Json;

namespace ElectionGuard.Core.UnitTests.Verify;

/// <summary>
/// G4: a ballot must list exactly its ballot style's contests, each once, and in each contest exactly
/// the manifest's options, each once (§3.1.3 p.17, Verification 6 preamble p.36, Verifications 7 and
/// 9). Every malformed shape is rejected by Verifications 6, 7 and 8 and by
/// <see cref="EncryptedTally.AddBallot"/> (which Verification 9 reuses), each under its own
/// "N.structure" sub-section, before anything else is checked or multiplied in. The fixture's two
/// contests also pin the order of failures across contests (see the tests at the end).
/// </summary>
public class BallotStructureTests
{
    private const string DeviceId = "device-1";
    private const string StyleId = "style-ab";

    public BallotStructureTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private sealed record Fixture(EncryptionRecord Record, VotingDeviceInformationHash DeviceHash, EncryptedBallot Ballot);

    // Building guardians and encrypting is the slow part; every case only reshapes the same ballot.
    private static readonly Lazy<Fixture> Shared = new(Build);

    /// <summary>
    /// Contests A (three options, selection limit 2, so an option has slack to be repeated), B and C.
    /// The ballot style holds A and B only, so C is a real manifest contest the ballot must not list.
    /// </summary>
    private static Fixture Build()
    {
        var manifest = new Manifest
        {
            ElectionId = "ballot-structure",
            Contests =
            [
                new Contest
                {
                    Id = "contest-a", Name = "A", Index = 1, SelectionLimit = 2, OptionSelectionLimit = 1,
                    Choices =
                    [
                        new Choice { Id = "a-1", Name = "A 1", Index = 1 },
                        new Choice { Id = "a-2", Name = "A 2", Index = 2 },
                        new Choice { Id = "a-3", Name = "A 3", Index = 3 },
                    ],
                },
                new Contest
                {
                    Id = "contest-b", Name = "B", Index = 2, SelectionLimit = 1, OptionSelectionLimit = 1,
                    // §3.3.10: B carries a contest data field on every ballot; A carries none.
                    ContestDataBlocks = 1,
                    Choices =
                    [
                        new Choice { Id = "b-1", Name = "B 1", Index = 1 },
                        new Choice { Id = "b-2", Name = "B 2", Index = 2 },
                    ],
                },
                new Contest
                {
                    Id = "contest-c", Name = "C", Index = 3, SelectionLimit = 1, OptionSelectionLimit = 1,
                    Choices =
                    [
                        new Choice { Id = "c-1", Name = "C 1", Index = 1 },
                        new Choice { Id = "c-2", Name = "C 2", Index = 2 },
                    ],
                },
            ],
            BallotStyles =
            [
                new BallotStyle { Id = StyleId, Name = "A and B", ContestIds = ["contest-a", "contest-b"] },
                new BallotStyle { Id = "style-abc", Name = "All", ContestIds = ["contest-a", "contest-b", "contest-c"] },
            ],
            ChainingMode = ChainingMode.None,
        };
        var manifestFile = new ManifestFile { Bytes = JsonSerializer.SerializeToUtf8Bytes(manifest) };
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, DeviceId);

        var ballot = new Core.BallotEncryption.Ballot
        {
            Id = "ballot-1",
            BallotStyleId = StyleId,
            Contests =
            [
                new BallotContest
                {
                    Id = "contest-a",
                    NumWriteinsSelected = 0,
                    Choices =
                    [
                        new BallotChoice { Id = "a-1", SelectionValue = 0 },
                        new BallotChoice { Id = "a-2", SelectionValue = 1 },
                        new BallotChoice { Id = "a-3", SelectionValue = 0 },
                    ],
                },
                new BallotContest
                {
                    Id = "contest-b",
                    NumWriteinsSelected = 0,
                    Choices =
                    [
                        new BallotChoice { Id = "b-1", SelectionValue = 1 },
                        new BallotChoice { Id = "b-2", SelectionValue = 0 },
                    ],
                },
            ],
        };
        var encrypted = new BallotEncryptor(records.EncryptionRecord, DeviceId, deviceHash).Encrypt(ballot, null);

        // Cast, so that it can be tallied (AddBallot rejects a ballot with no recorded status).
        encrypted.RecordStatus(BallotStatus.Cast);
        return new Fixture(records.EncryptionRecord, deviceHash, encrypted);
    }

    private static EncryptedBallot With(EncryptedBallot ballot, List<EncryptedContest>? contests = null, string? ballotStyleId = null, ConfirmationCode? confirmationCode = null) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballotStyleId ?? ballot.BallotStyleId,
        Contests = contests ?? ballot.Contests,
        ConfirmationCode = confirmationCode ?? ballot.ConfirmationCode,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        ChainingField = ballot.ChainingField,
        Weight = ballot.Weight,
        Status = ballot.Status,
        DeviceId = ballot.DeviceId,
    };

    private static EncryptedContest A(EncryptedBallot ballot) => ballot.Contests[0];

    private static EncryptedContest B(EncryptedBallot ballot) => ballot.Contests[1];

    private static EncryptedBallot WithChoicesOfA(EncryptedBallot ballot, Func<List<EncryptedSelection>, List<EncryptedSelection>> change) =>
        With(ballot, [A(ballot) with { Choices = change(A(ballot).Choices) }, B(ballot)]);

    /// <summary>Each malformed shape, made from the valid ballot.</summary>
    private static readonly Dictionary<string, Func<EncryptedBallot, EncryptedBallot>> Shapes = new()
    {
        ["duplicated contest"] = b => With(b, [A(b), B(b), A(b)]),
        ["duplicated option"] = b => WithChoicesOfA(b, c => [.. c, c[1]]),
        ["duplicated option in place of another"] = b => WithChoicesOfA(b, c => [c[0], c[1], c[1]]),
        ["missing option"] = b => WithChoicesOfA(b, c => [c[0], c[1]]),
        ["extra option"] = b => WithChoicesOfA(b, c => [.. c, c[0] with { ChoiceId = "a-not-in-manifest" }]),
        ["option of another contest"] = b => WithChoicesOfA(b, c => [c[0], c[1], B(b).Choices[0]]),
        ["missing contest of the ballot style"] = b => With(b, [A(b)]),
        ["extra contest of the manifest, not on the ballot style"] = b => With(b, [A(b), B(b), B(b) with { Id = "contest-c" }]),
        ["contest not in the manifest"] = b => With(b, [A(b), B(b) with { Id = "contest-not-in-manifest" }]),
        ["unknown ballot style"] = b => With(b, ballotStyleId: "style-not-in-manifest"),
        ["another ballot style"] = b => With(b, ballotStyleId: "style-abc"),
        // S5 review: the manifest declares no supplemental fields for A, but a null list is still
        // malformed (the consumers after the structure check walk it unguarded); so is a null entry.
        ["null supplemental field list"] = b => With(b, [A(b) with { SupplementalFields = null! }, B(b)]),
        ["null supplemental field entry"] = b => With(b, [A(b) with { SupplementalFields = [null!] }, B(b)]),
        // S6 (G11, user decision Q7): a contest that declares b_Λ carries one field of exactly
        // 32·b_Λ bytes on every ballot, and a contest that declares none carries none.
        ["contest data on a contest that declares none"] = b => With(b, [A(b) with { ContestData = B(b).ContestData }, B(b)]),
        ["missing contest data"] = b => With(b, [A(b), B(b) with { ContestData = null }]),
        ["contest data C1 one block too long"] = b => With(b, [A(b), B(b) with { ContestData = WithC1(B(b).ContestData!, [.. B(b).ContestData!.C1, .. new byte[32]]) }]),
        ["contest data C1 one byte short"] = b => With(b, [A(b), B(b) with { ContestData = WithC1(B(b).ContestData!, B(b).ContestData!.C1[1..]) }]),
        ["contest data C1 null"] = b => With(b, [A(b), B(b) with { ContestData = WithC1(B(b).ContestData!, null!) }]),
        // S7 (G17, §3.3.4): every ballot carries the encrypted ballot nonce C_ξB, its C_ξB,1 exactly
        // 32 bytes (eq. 37).
        ["missing encrypted ballot nonce"] = b => WithBallotNonce(b, null!),
        ["ballot nonce C1 one byte short"] = b => WithBallotNonce(b, WithNonceC1(b.EncryptedBallotNonce, b.EncryptedBallotNonce.C1[1..])),
        ["ballot nonce C1 one byte long"] = b => WithBallotNonce(b, WithNonceC1(b.EncryptedBallotNonce, [.. b.EncryptedBallotNonce.C1, 0])),
        ["ballot nonce C1 null"] = b => WithBallotNonce(b, WithNonceC1(b.EncryptedBallotNonce, null!)),
        // S8 (G19/G37, §3.4.4): every ballot carries the 36-byte chaining field B_C it was hashed with.
        ["missing chaining field"] = b => new()
        {
            Id = b.Id,
            SelectionEncryptionIdentifier = b.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = b.SelectionEncryptionIdentifierHash,
            BallotStyleId = b.BallotStyleId,
            Contests = b.Contests,
            ConfirmationCode = b.ConfirmationCode,
            EncryptedBallotNonce = b.EncryptedBallotNonce,
            ChainingField = default,
            Weight = b.Weight,
            Status = b.Status,
            DeviceId = b.DeviceId,
        },
        // S9 review round 3: every ballot names its device S_device (§3.4.3 eq. 72), which V8.C
        // hashes. A JSON document that writes "deviceId": null yields a ballot without it.
        ["null device id"] = b => new()
        {
            Id = b.Id,
            SelectionEncryptionIdentifier = b.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = b.SelectionEncryptionIdentifierHash,
            BallotStyleId = b.BallotStyleId,
            Contests = b.Contests,
            ConfirmationCode = b.ConfirmationCode,
            EncryptedBallotNonce = b.EncryptedBallotNonce,
            ChainingField = b.ChainingField,
            Weight = b.Weight,
            Status = b.Status,
            DeviceId = null!,
        },
    };

    private static EncryptedBallot WithBallotNonce(EncryptedBallot ballot, EncryptedBallotNonce nonce) => new()
    {
        Id = ballot.Id,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        BallotStyleId = ballot.BallotStyleId,
        Contests = ballot.Contests,
        ConfirmationCode = ballot.ConfirmationCode,
        EncryptedBallotNonce = nonce,
        ChainingField = ballot.ChainingField,
        Weight = ballot.Weight,
        Status = ballot.Status,
        DeviceId = ballot.DeviceId,
    };

    private static EncryptedBallotNonce WithNonceC1(EncryptedBallotNonce nonce, byte[] c1) => new()
    {
        C0 = nonce.C0,
        C1 = c1,
        Challenge = nonce.Challenge,
        Response = nonce.Response,
    };

    private static EncryptedContestData WithC1(EncryptedContestData data, byte[] c1) => new()
    {
        C0 = data.C0,
        C1 = c1,
        Challenge = data.Challenge,
        Response = data.Response,
    };

    public static TheoryData<string, int> ShapesByVerification()
    {
        var data = new TheoryData<string, int>();
        foreach (var shape in Shapes.Keys)
        {
            foreach (var verification in new[] { 6, 7, 8, 9 })
            {
                data.Add(shape, verification);
            }
        }

        return data;
    }

    /// <summary>Runs Verification 6, 7 or 8, or for 9 adds the ballot to a fresh tally.</summary>
    private static void Run(int verification, EncryptedBallot ballot, Fixture fixture, EncryptedTally? tally = null)
    {
        switch (verification)
        {
            case 6:
                new SelectionEncryptionsWellFormedVerification().Verify(ballot, fixture.Record);
                break;
            case 7:
                new AdherenceToVoteLimitsVerification().Verify(ballot, fixture.Record);
                break;
            case 8:
                new ConfirmationCodeVerification().Verify(ballot, fixture.DeviceHash, fixture.Record, null);
                break;
            case 9:
                (tally ?? new EncryptedTally(fixture.Record.Manifest)).AddBallot(ballot);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(verification));
        }
    }

    [Theory]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    public void ValidBallot_Passes(int verification)
    {
        var fixture = Shared.Value;

        Assert.Null(Record.Exception(() => Run(verification, fixture.Ballot, fixture)));
    }

    [Theory]
    [MemberData(nameof(ShapesByVerification))]
    public void MalformedBallot_IsRejected_AsStructure(string shape, int verification)
    {
        var fixture = Shared.Value;
        var malformed = Shapes[shape](fixture.Ballot);

        var exception = Assert.Throws<VerificationFailedException>(() => Run(verification, malformed, fixture));

        Assert.Equal($"{verification}.structure", exception.SubSection);
    }

    [Theory]
    [InlineData("duplicated contest")]
    [InlineData("duplicated option")]
    [InlineData("missing option")]
    public void MalformedBallot_AddsNothingToTheTally(string shape)
    {
        var fixture = Shared.Value;
        var tally = new EncryptedTally(fixture.Record.Manifest);
        var empty = new EncryptedTally(fixture.Record.Manifest);

        Assert.Throws<VerificationFailedException>(() => Run(9, Shapes[shape](fixture.Ballot), fixture, tally));

        Assert.Equal(0, tally.BallotsCast);
        AssertSameAggregates(empty, tally);
    }

    /// <summary>
    /// The audit's attack (G4): a malicious encryptor repeats a valid contest verbatim. Its proofs are
    /// bound to H_I and the indices only, not to a position on the ballot, so the copy passes 6.D and
    /// 7.D, and the encryptor hashes the confirmation code over the contest hashes as listed, adjacent
    /// copies included, so 8.A and 8.B match too. Before the structural check this ballot passed
    /// Verifications 5-9 and its contest A was tallied twice; now each verification rejects it.
    /// </summary>
    [Fact]
    public void ContestCopiedVerbatim_WithAMatchingConfirmationCode_IsRejectedEverywhere()
    {
        var fixture = Shared.Value;
        var ballot = fixture.Ballot;
        var contests = new List<EncryptedContest> { A(ballot), A(ballot), B(ballot) };
        var chainingField = new ChainingField(ChainingMode.None, fixture.DeviceHash, fixture.Record.ExtendedBaseHash, null);
        var code = new ConfirmationCode(ballot.SelectionEncryptionIdentifierHash, contests.Select(x => x.ContestHash).ToList(), chainingField);
        var attack = With(ballot, contests, confirmationCode: code);

        // 5.B still holds: the copy keeps the ballot's own identifier and H_I.
        new SelectionEncryptionIdentifierVerification().Verify(
            attack.SelectionEncryptionIdentifier, attack.SelectionEncryptionIdentifierHash, fixture.Record.ExtendedBaseHash);

        foreach (var verification in new[] { 6, 7, 8, 9 })
        {
            var exception = Assert.Throws<VerificationFailedException>(() => Run(verification, attack, fixture));
            Assert.Equal($"{verification}.structure", exception.SubSection);
            Assert.Contains("more than once", exception.Message);
        }

        // Verification 9 recomputes the aggregate from the ballots; the attack ballot cannot reach it.
        var verifier = new BallotAggregationVerifier(fixture.Record.Manifest);
        Assert.Throws<VerificationFailedException>(() => verifier.AddBallot(attack));
    }

    // The order of failures: the ballot's structure first, then 6.A/7.A for every value on the
    // ballot, then everything else. These use two contests, so a membership check moved inside the
    // per-contest loop would report contest A's failure before contest B's non-member.

    private static readonly IntegerModP NonMember = new(2);

    private static EncryptedBallot WithNonMemberAlphaInB(EncryptedBallot ballot) =>
        With(ballot, [A(ballot), B(ballot) with { Choices = [B(ballot).Choices[0], B(ballot).Choices[1] with { Alpha = NonMember }] }]);

    private static ChallengeResponsePair[] WithFirstChallengeShifted(ChallengeResponsePair[] proofs)
    {
        var copy = (ChallengeResponsePair[])proofs.Clone();
        copy[0] = copy[0] with { Challenge = copy[0].Challenge + 1 };
        return copy;
    }

    /// <summary>
    /// Contest A's contest proof fails 7.D and contest B has a non-member alpha_i. 7.A for any value
    /// on the ballot is reported first.
    /// </summary>
    [Fact]
    public void Verification7_NonMemberInALaterContest_IsReportedBeforeAnEarlierContestsSumFailure()
    {
        var fixture = Shared.Value;
        var ballot = fixture.Ballot;
        var sumFailureInA = With(ballot, [A(ballot) with { Proofs = WithFirstChallengeShifted(A(ballot).Proofs) }, B(ballot)]);
        Assert.False(SubgroupMembership.IsMember(NonMember));

        // Each fault on its own.
        Assert.Equal("7.D", Assert.Throws<VerificationFailedException>(() => Run(7, sumFailureInA, fixture)).SubSection);
        Assert.Equal("7.A", Assert.Throws<VerificationFailedException>(() => Run(7, WithNonMemberAlphaInB(ballot), fixture)).SubSection);

        var exception = Assert.Throws<VerificationFailedException>(() => Run(7, WithNonMemberAlphaInB(sumFailureInA), fixture));

        Assert.Equal("7.A", exception.SubSection);
    }

    /// <summary>
    /// Contest A's first selection fails 6.D and a selection of contest B has a non-member alpha. 6.A
    /// for any selection is reported first, on the fused path as on the in-order one.
    /// </summary>
    [Fact]
    public void Verification6_NonMemberInALaterContest_IsReportedBeforeAnEarlierSelectionsSumFailure()
    {
        var fixture = Shared.Value;
        var ballot = fixture.Ballot;
        var first = A(ballot).Choices[0];
        var sumFailureInA = WithChoicesOfA(ballot, c => [first with { Proofs = WithFirstChallengeShifted(first.Proofs) }, .. c.Skip(1)]);

        // Each fault on its own.
        Assert.Equal("6.D", Assert.Throws<VerificationFailedException>(() => Run(6, sumFailureInA, fixture)).SubSection);
        Assert.Equal("6.A", Assert.Throws<VerificationFailedException>(() => Run(6, WithNonMemberAlphaInB(ballot), fixture)).SubSection);

        var exception = Assert.Throws<VerificationFailedException>(() => Run(6, WithNonMemberAlphaInB(sumFailureInA), fixture));

        Assert.Equal("6.A", exception.SubSection);
    }

    /// <summary>
    /// A malformed ballot that also carries a non-member is reported as malformed: the structure is
    /// checked before 6.A and 7.A.
    /// </summary>
    [Theory]
    [InlineData(6)]
    [InlineData(7)]
    public void MalformedBallotWithANonMember_IsRejected_AsStructure(int verification)
    {
        var fixture = Shared.Value;
        var ballot = fixture.Ballot;
        var withNonMember = WithChoicesOfA(ballot, c => [c[0] with { Alpha = NonMember }, .. c.Skip(1)]);
        Assert.Equal($"{verification}.A", Assert.Throws<VerificationFailedException>(() => Run(verification, withNonMember, fixture)).SubSection);

        var malformed = Shapes["duplicated option"](withNonMember);
        Assert.Contains(malformed.Contests[0].Choices, s => s.Alpha == NonMember);

        var exception = Assert.Throws<VerificationFailedException>(() => Run(verification, malformed, fixture));

        Assert.Equal($"{verification}.structure", exception.SubSection);
    }

    /// <summary>
    /// S5 review: the JSON decoder (unlike protobuf, which decodes an absent list as empty) accepts
    /// <c>"supplementalFields": null</c> for the required list. For a contest whose manifest declares
    /// no fields, that once passed the structure check and then crashed Verifications 6-8 and the
    /// tally with a NullReferenceException; it is now a structural failure.
    /// </summary>
    [Theory]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    public void JsonBallotWithANullSupplementalFieldList_IsRejected_AsStructure(int verification)
    {
        var fixture = Shared.Value;
        var serializer = new Core.Serialization.JsonEncryptedBallotSerializer();
        using var encoded = new MemoryStream();
        serializer.Serialize(encoded, fixture.Ballot);
        var document = System.Text.Json.Nodes.JsonNode.Parse(encoded.ToArray())!;
        Assert.NotNull(document["contests"]![0]!["supplementalFields"]);
        document["contests"]![0]!["supplementalFields"] = null;

        var decoded = serializer.Deserialize(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(document.ToJsonString())))!;
        Assert.Null(decoded.Contests[0].SupplementalFields);
        Assert.Empty(fixture.Record.Manifest.Contests[0].SupplementalFields);

        var exception = Assert.Throws<VerificationFailedException>(() => Run(verification, decoded, fixture));

        Assert.Equal($"{verification}.structure", exception.SubSection);
    }

    private static void AssertSameAggregates(EncryptedTally expected, EncryptedTally actual)
    {
        foreach (var (contestId, contest) in expected.Contests)
        {
            foreach (var (choiceId, choice) in contest.Choices)
            {
                Assert.Equal(choice.A, actual.Contests[contestId].Choices[choiceId].A);
                Assert.Equal(choice.B, actual.Contests[contestId].Choices[choiceId].B);
            }
        }
    }
}
