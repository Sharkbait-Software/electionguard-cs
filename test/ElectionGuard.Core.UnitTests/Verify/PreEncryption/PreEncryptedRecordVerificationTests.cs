using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.UnitTests.PreEncryption;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Core.Verify.Tally;

namespace ElectionGuard.Core.UnitTests.Verify.PreEncryption;

/// <summary>
/// Verifications 15 to 19 on the records the recording tool produces (§4.3, §4.4): cast ballots
/// (15, and the cast forms of 16 and 17) and uncast ones (18, 19). Each failing case tampers one
/// published value, or forges a ballot the way a dishonest device would, and asserts the lettered
/// sub-check that catches it.
/// </summary>
public class PreEncryptedRecordVerificationTests
{
    public PreEncryptedRecordVerificationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static PreEncryptedElection Election => PreEncryptedElection.Get();

    private static EncryptedBallot WithPreEncryptedContest(EncryptedBallot ballot, int index, Func<PreEncryptedCastContest, PreEncryptedCastContest> change)
    {
        var contests = ballot.PreEncryptedContests!.ToList();
        contests[index] = change(contests[index]);
        return Copy(ballot, contests);
    }

    private static EncryptedBallot Copy(EncryptedBallot ballot, List<PreEncryptedCastContest>? preEncryptedContests = null, ConfirmationCode? confirmationCode = null, BallotStatus? status = null) => new()
    {
        Id = ballot.Id,
        BallotStyleId = ballot.BallotStyleId,
        DeviceId = ballot.DeviceId,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        Contests = ballot.Contests,
        ConfirmationCode = confirmationCode ?? ballot.ConfirmationCode,
        ChainingField = ballot.ChainingField,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        Weight = ballot.Weight,
        Status = status ?? ballot.Status,
        PreEncryptedContests = preEncryptedContests ?? ballot.PreEncryptedContests,
    };

    /// <summary>The ballot's standard part alone: what a regular ballot with the same contents would be.</summary>
    private static EncryptedBallot AsRegular(EncryptedBallot ballot) => new()
    {
        Id = ballot.Id,
        BallotStyleId = ballot.BallotStyleId,
        DeviceId = ballot.DeviceId,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        Contests = ballot.Contests,
        ConfirmationCode = ballot.ConfirmationCode,
        ChainingField = ballot.ChainingField,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        Weight = ballot.Weight,
        Status = ballot.Status,
    };

    private static PreEncryptedCastSelection Published(PreEncryptedSelection selection, SelectionEncryptionIdentifierHash selectionHash) => new()
    {
        Vector = selection.Vector.Select(x => new EncryptedValue { Alpha = x.Alpha, Beta = x.Beta }).ToList(),
        SelectionHash = new SelectionHash(selectionHash, selection.Vector),
        ShortCode = HashTrimming.Trim(HashTrimmingFunction.FourHex, new SelectionHash(selectionHash, selection.Vector)),
    };

    private static string Fails(Action verify) => Assert.Throws<VerificationFailedException>(verify).SubSection;

    // --- Verification 15 --------------------------------------------------------------------------

    /// <summary>
    /// The voter selected option 1 of contest-1 and the combined vector counts option 1, but the
    /// record publishes option 2's vector and short code as the one selected: everything else is
    /// consistent (the vector is one of the contest's, its hash is listed, its short code is right),
    /// so only 15.A shows that the vote counted is not the one the short code names.
    /// </summary>
    [Fact]
    public void Verification15_PublishedVectorIsNotTheOneCombined_Fails15A()
    {
        var election = Election;
        var (preEncrypted, cast) = election.Cast("cast-1", [1], [1, 2]);
        var other = preEncrypted.Contests[0].Selections.Single(x => x.ChoiceId == "contest-1-option-2");
        var forged = WithPreEncryptedContest(cast, 0, c => c with { SelectedVectors = [Published(other, cast.SelectionEncryptionIdentifierHash)] });

        new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(forged, election.Record);
        new SelectionEncryptionsWellFormedVerification().Verify(forged, election.Record);
        Assert.Equal("15.A", Fails(() => new SelectionVectorAccumulationVerification().Verify(forged, election.Record)));
    }

    /// <summary>A combined vector that is not the product of the published selected vectors (contest-2, L = 2).</summary>
    [Fact]
    public void Verification15_CombinedVectorIsNotTheProduct_Fails15A()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var (_, other) = election.Cast("cast-2", [1], [3, 4]);
        var contests = cast.Contests.ToList();
        contests[1] = other.Contests[1];
        var forged = WithContests(cast, contests);

        Assert.Equal("15.A", Fails(() => new SelectionVectorAccumulationVerification().Verify(forged, election.Record)));
    }

    /// <summary>
    /// S9 review round 3: the beta half of 15.A. The voter selected option 1 of contest-1, and the
    /// record publishes that vector as selected, but the combined vector is the one re-encrypted
    /// with the same nonces and the one moved to option 2: every alpha equals the product of the
    /// selected vectors' alphas, only the betas of options 1 and 2 differ (β = K^(σ+ξ)). The selected
    /// vectors, the hashes and the short codes are untouched, so Verifications 16 and 17 pass, and
    /// only 15.A shows that the vote counted is not the one the short code names.
    /// </summary>
    [Fact]
    public void Verification15_CombinedVectorWithTheSameNoncesAndTheOneMoved_Fails15A()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var key = election.Record.ElectionPublicKeys.VoteEncryptionKey;
        var choices = cast.Contests[0].Choices;
        var contests = cast.Contests.ToList();
        contests[0] = contests[0] with
        {
            Choices = [choices[0] with { Beta = choices[0].Beta / key }, choices[1] with { Beta = choices[1].Beta * key }, .. choices.Skip(2)],
        };
        var forged = WithContests(cast, contests);

        var selected = cast.PreEncryptedContests![0].SelectedVectors.Single();
        Assert.Equal(selected.Vector.Select(x => x.Alpha), forged.Contests[0].Choices.Select(x => x.Alpha));
        Assert.NotEqual(selected.Vector.Select(x => x.Beta), forged.Contests[0].Choices.Select(x => x.Beta));

        new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(forged, election.Record);
        Assert.Equal("15.A", Fails(() => new SelectionVectorAccumulationVerification().Verify(forged, election.Record)));
    }

    /// <summary>
    /// S9 review round 3: a cast record without a device id (as read from JSON that writes
    /// <c>"deviceId": null</c>) is malformed under Verifications 15 and 16, not an
    /// <see cref="ArgumentNullException"/> from 16.D's hash of S_device.
    /// </summary>
    [Fact]
    public void Verifications15And16_CastRecordWithNoDeviceId_FailStructure()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var forged = new EncryptedBallot
        {
            Id = cast.Id,
            BallotStyleId = cast.BallotStyleId,
            DeviceId = null!,
            SelectionEncryptionIdentifier = cast.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = cast.SelectionEncryptionIdentifierHash,
            Contests = cast.Contests,
            ConfirmationCode = cast.ConfirmationCode,
            ChainingField = cast.ChainingField,
            EncryptedBallotNonce = cast.EncryptedBallotNonce,
            Weight = cast.Weight,
            Status = cast.Status,
            PreEncryptedContests = cast.PreEncryptedContests,
        };

        Assert.Equal("15.structure", Fails(() => new SelectionVectorAccumulationVerification().Verify(forged, election.Record)));
        Assert.Equal("16.structure", Fails(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null)));
    }

    [Fact]
    public void Verification15_FewerSelectedVectorsThanTheSelectionLimit_Fails15Structure()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var forged = WithPreEncryptedContest(cast, 1, c => c with { SelectedVectors = c.SelectedVectors.Take(1).ToList() });

        Assert.Equal("15.structure", Fails(() => new SelectionVectorAccumulationVerification().Verify(forged, election.Record)));
    }

    /// <summary>The combined vector's proofs are the standard ones: Verifications 6 and 7 apply unchanged.</summary>
    [Fact]
    public void Verifications6And7_TamperedProofOnTheCombinedVector_Fail6DAnd7D()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var choice = cast.Contests[0].Choices[0];
        var badRange = cast.Contests.ToList();
        badRange[0] = badRange[0] with
        {
            Choices = [choice with { Proofs = [choice.Proofs[0] with { Response = choice.Proofs[0].Response + 1 }, .. choice.Proofs[1..]] }, .. cast.Contests[0].Choices.Skip(1)],
        };
        var badLimit = cast.Contests.ToList();
        badLimit[1] = badLimit[1] with { Proofs = [cast.Contests[1].Proofs[0] with { Response = cast.Contests[1].Proofs[0].Response + 1 }, .. cast.Contests[1].Proofs[1..]] };

        Assert.Equal("6.D", Fails(() => new SelectionEncryptionsWellFormedVerification().Verify(WithContests(cast, badRange), election.Record)));
        Assert.Equal("7.D", Fails(() => new AdherenceToVoteLimitsVerification().Verify(WithContests(cast, badLimit), election.Record)));
    }

    private static EncryptedBallot WithContests(EncryptedBallot ballot, List<EncryptedContest> contests) => new()
    {
        Id = ballot.Id,
        BallotStyleId = ballot.BallotStyleId,
        DeviceId = ballot.DeviceId,
        SelectionEncryptionIdentifier = ballot.SelectionEncryptionIdentifier,
        SelectionEncryptionIdentifierHash = ballot.SelectionEncryptionIdentifierHash,
        Contests = contests,
        ConfirmationCode = ballot.ConfirmationCode,
        ChainingField = ballot.ChainingField,
        EncryptedBallotNonce = ballot.EncryptedBallotNonce,
        Weight = ballot.Weight,
        Status = ballot.Status,
        PreEncryptedContests = ballot.PreEncryptedContests,
    };

    // --- Verifications 16 and 17 on cast records -------------------------------------------------

    [Fact]
    public void Verification16_CastRecord_TamperedSelectedVector_Fails16A()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var forged = WithPreEncryptedContest(cast, 0, c =>
        {
            var vector = c.SelectedVectors[0].Vector.ToList();
            vector[0] = new EncryptedValue { Alpha = vector[0].Alpha * new IntegerModP(EGParameters.G), Beta = vector[0].Beta };
            return c with { SelectedVectors = [c.SelectedVectors[0] with { Vector = vector }] };
        });

        Assert.Equal("16.A", Fails(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null)));
    }

    /// <summary>A selected vector, consistently hashed and coded, that is not one of the ballot's.</summary>
    [Fact]
    public void Verification16_CastRecord_SelectedVectorFromAnotherBallot_Fails16A()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var otherBallot = election.PreEncrypt("other");
        var stranger = Published(otherBallot.Contests[0].Selections[0], cast.SelectionEncryptionIdentifierHash);
        var forged = WithPreEncryptedContest(cast, 0, c => c with { SelectedVectors = [stranger] });

        var exception = Assert.Throws<VerificationFailedException>(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null));

        Assert.Equal("16.A", exception.SubSection);
        Assert.Contains("is not one of the contest's published selection hashes", exception.Message);
    }

    [Fact]
    public void Verification16_CastRecord_ReplacedSelectionHash_Fails16B()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var forged = WithPreEncryptedContest(cast, 0, c =>
        {
            // Replace a hash that is not selected, keeping the list sorted.
            var selected = c.SelectedVectors.Select(x => x.SelectionHash).ToHashSet();
            var hashes = c.SelectionHashes.ToList();
            int victim = hashes.FindIndex(x => !selected.Contains(x));
            byte[] bytes = ((byte[])hashes[victim]).ToArray();
            bytes[^1] ^= 1;
            hashes[victim] = new SelectionHash(bytes);
            return c with { SelectionHashes = hashes.Order().ToList() };
        });

        Assert.Equal("16.B", Fails(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null)));
    }

    [Fact]
    public void Verification16_CastRecord_ReplacedConfirmationCode_Fails16C()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var forged = Copy(cast, confirmationCode: new ConfirmationCode(new byte[32]));

        Assert.Equal("16.C", Fails(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null)));
    }

    public static IEnumerable<object[]> MalformedCastRecords()
    {
        yield return ["unsorted selection hashes", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 0, c => c with { SelectionHashes = c.SelectionHashes.AsEnumerable().Reverse().ToList() }))];
        yield return ["a selection hash missing", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 0, c => c with { SelectionHashes = c.SelectionHashes.Skip(1).ToList() }))];
        yield return ["a 31-byte selection hash", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 0, c => c with { SelectionHashes = [new SelectionHash(new byte[31]), .. c.SelectionHashes.Skip(1)] }))];
        yield return ["a vector of the wrong length", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 0, c => c with { SelectedVectors = [c.SelectedVectors[0] with { Vector = c.SelectedVectors[0].Vector.Take(2).ToList() }] }))];
        yield return ["the same vector twice", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 1, c => c with { SelectedVectors = [c.SelectedVectors[0], c.SelectedVectors[0]] }))];
        yield return ["data for one contest only", new Func<EncryptedBallot, EncryptedBallot>(b => Copy(b, [b.PreEncryptedContests![0]]))];
        yield return ["contests swapped", new Func<EncryptedBallot, EncryptedBallot>(b => Copy(b, [b.PreEncryptedContests![1], b.PreEncryptedContests![0]]))];
        yield return ["a regular ballot", new Func<EncryptedBallot, EncryptedBallot>(AsRegular)];
        // Distinct but out of order: only strictly increasing hashes pass (">= 0", not "== 0").
        yield return ["selected vectors in decreasing order", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 1, c => c with { SelectedVectors = c.SelectedVectors.AsEnumerable().Reverse().ToList() }))];
        yield return ["a selected vector without a short code", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 0, c => c with { SelectedVectors = [c.SelectedVectors[0] with { ShortCode = default }] }))];
        yield return ["a selected vector with a 31-byte hash", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 0, c => c with { SelectedVectors = [c.SelectedVectors[0] with { SelectionHash = new SelectionHash(new byte[31]) }] }))];
        yield return ["a selected vector with no hash", new Func<EncryptedBallot, EncryptedBallot>(b => WithPreEncryptedContest(b, 0, c => c with { SelectedVectors = [c.SelectedVectors[0] with { SelectionHash = default }] }))];
        // A pre-encrypted record is a cast ballot's; under any other status it would leave the tally
        // silently, and an uncast pre-encrypted ballot is published with its nonces (Verification 18).
        yield return ["recorded as challenged", new Func<EncryptedBallot, EncryptedBallot>(b => Copy(b, status: BallotStatus.Challenged))];
        yield return ["recorded as not submitted", new Func<EncryptedBallot, EncryptedBallot>(b => Copy(b, status: BallotStatus.NotSubmitted))];
    }

    [Theory]
    [MemberData(nameof(MalformedCastRecords))]
    public void Verifications15To17_MalformedCastRecord_FailStructure(string description, Func<EncryptedBallot, EncryptedBallot> malform)
    {
        _ = description;
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var forged = malform(cast);

        Assert.Equal("15.structure", Fails(() => new SelectionVectorAccumulationVerification().Verify(forged, election.Record)));
        Assert.Equal("16.structure", Fails(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null)));
        Assert.Equal("17.structure", Fails(() => new ShortCodeVerification().Verify(forged, election.Record)));
    }

    /// <summary>
    /// An election whose manifest names no hash-trimming function has no pre-encrypted ballots
    /// (§4.1.5): a cast record, and a printed pre-encrypted ballot, under such a record fail the
    /// structure check before any lettered check.
    /// </summary>
    [Fact]
    public void PreEncryptedBallots_ManifestWithoutHashTrimmingFunction_FailStructure()
    {
        var election = Election;
        var (ballot, cast) = election.Cast("cast-1", [1], [1, 2]);
        var uncast = election.Uncast("uncast-1");
        var record = WithoutHashTrimmingFunction(election.Record);

        Assert.Equal("15.structure", Fails(() => new SelectionVectorAccumulationVerification().Verify(cast, record)));
        Assert.Equal("16.structure", Fails(() => new PreEncryptedConfirmationCodeVerification().Verify(cast, election.DeviceHash, record, null)));
        Assert.Equal("17.structure", Fails(() => new ShortCodeVerification().Verify(cast, record)));

        var exception = Assert.Throws<VerificationFailedException>(() => new PreEncryptedConfirmationCodeVerification().Verify(ballot, election.DeviceHash, record, null));
        Assert.Equal("16.structure", exception.SubSection);
        Assert.Contains("hash-trimming", exception.Message);
        Assert.Equal("18.structure", Fails(() => new UncastBallotEncryptionVerification().Verify(uncast, record)));
    }

    /// <summary>
    /// A pre-encrypted ballot's record marked challenged is not opened as a challenged ballot: its
    /// contests are combined vectors with summed nonces, which eq. (33) does not open, so guardians
    /// would release shares for a decryption that can never succeed. The guardian and the
    /// administrator refuse it, and Verifications 13 and 14 fail it as structure.
    /// </summary>
    [Fact]
    public void CastRecordMarkedChallenged_IsNotOpenedAsAChallengedBallot()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var challenged = Copy(cast, status: BallotStatus.Challenged);
        var decrypted = new DecryptedChallengedBallot { BallotId = challenged.Id, Contests = [] };

        var guardianException = Assert.Throws<ArgumentException>(() => election.Guardians[0].DecryptBallotNonce(challenged, election.Record, election.NoCastBallots, election.NoIssuedBallots));
        Assert.Contains("pre-encrypted", guardianException.Message);
        Assert.Throws<ArgumentException>(() => new TallyAdmin().CombineChallengedBallot(challenged, election.Record, []));
        Assert.Equal("13.structure", Fails(() => new ChallengedBallotDecryptionVerification().Verify(election.Record, challenged, decrypted, election.DeviceHash, null)));
        Assert.Equal("14.structure", Fails(() => new ChallengedBallotWellFormednessVerification().Verify(election.Manifest, challenged, decrypted)));
    }

    private static EncryptionRecord WithoutHashTrimmingFunction(EncryptionRecord record) => new()
    {
        CryptographicParameters = record.CryptographicParameters,
        GuardianParameters = record.GuardianParameters,
        ParameterBaseHash = record.ParameterBaseHash,
        ManifestFile = record.ManifestFile,
        ElectionBaseHash = record.ElectionBaseHash,
        Guardians = record.Guardians,
        ElectionPublicKeys = record.ElectionPublicKeys,
        ExtendedBaseHash = record.ExtendedBaseHash,
        Manifest = record.Manifest with { HashTrimmingFunction = null },
    };

    [Fact]
    public void Verification17_CastRecord_WrongShortCode_Fails17A()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1, 2]);
        var forged = WithPreEncryptedContest(cast, 1, c => c with { SelectedVectors = [c.SelectedVectors[0] with { ShortCode = new ShortCode("ZZZZ") }, c.SelectedVectors[1]] });

        Assert.Equal("17.A", Fails(() => new ShortCodeVerification().Verify(forged, election.Record)));
    }

    // --- Verification 16 over a simple-chaining device -------------------------------------------

    /// <summary>
    /// A pre-encrypted device's list names every ballot it printed, cast or not (§3.7, §4.1.4): the
    /// walk accepts the device's cast records and uncast records together, checks each cast record
    /// against its place in the chain, and refuses a regular ballot among the cast ones.
    /// </summary>
    [Fact]
    public void Verification16_DeviceWalk_CastAndUncastRecordsOfOneDevice()
    {
        var election = PreEncryptedElection.Get(ChainingMode.Simple);
        var chain = DeviceChain.ForPreEncryptedBallots(election.Record, PreEncryptedElection.DeviceId);
        var preEncryptor = election.PreEncryptor();
        var printed = Enumerable.Range(1, 3).Select(i => preEncryptor.PreEncryptNext($"ballot-{i}", PreEncryptedElection.BallotStyleId, chain)).ToList();
        var device = chain.Close();

        var tool = new BallotRecordingTool(election.Record);
        var cast1 = tool.RecordCast(printed[0], election.DecryptNonce(printed[0]), election.Selections("ballot-1", [1], [2]));
        var uncast2 = tool.RecordUncast(printed[1], election.DecryptNonce(printed[1]));
        var cast3 = tool.RecordCast(printed[2], election.DecryptNonce(printed[2]), election.Selections("ballot-3", [], [3, 4]));
        var verification = new PreEncryptedConfirmationCodeVerification();

        verification.VerifyDevices([device], [cast1, cast3], [uncast2], election.Record);
        verification.Verify(cast1, election.DeviceHash, election.Record, null);
        verification.Verify(uncast2.Ballot, election.DeviceHash, election.Record, cast1.ConfirmationCode);
        verification.Verify(cast3, election.DeviceHash, election.Record, uncast2.Ballot.ConfirmationCode);

        // Cast record 3 checked as if it followed ballot 1: 16.F.
        Assert.Equal("16.F", Fails(() => verification.Verify(cast3, election.DeviceHash, election.Record, cast1.ConfirmationCode)));

        // The uncast ballot left out of the record: the list names a ballot that is not there.
        Assert.Equal("16.structure", Fails(() => verification.VerifyDevices([device], [cast1, cast3], [], election.Record)));

        // A regular ballot among the cast records.
        var regular = AsRegular(cast1);
        Assert.Equal("16.structure", Fails(() => verification.VerifyDevices([device], [regular, cast3], [uncast2], election.Record)));
    }

    // --- Verification 18 --------------------------------------------------------------------------

    /// <summary>
    /// The cut-and-choose attack the audit exists for: a dishonest device prints, beside option 1 of
    /// contest-1, a vector that encrypts a one at option 2's position, with the eq. (121) nonces of
    /// option 1's vector, and hashes and codes everything consistently. A voter who cast it would
    /// vote for option 2 by marking option 1's short code. Verifications 16, 17 and 19 accept the
    /// uncast ballot; 18 recomputes option 1's vector from its label and fails 18.A.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Verification18_MislabelledVector_Fails18A(bool releaseBallotNonce)
    {
        var election = Election;
        var honest = election.PreEncrypt("uncast-1");
        var ballotNonce = election.DecryptNonce(honest);
        var selectionHash = honest.SelectionEncryptionIdentifierHash;
        var key = election.Record.ElectionPublicKeys.VoteEncryptionKey;

        // Option 1's vector, with the one moved to position 2.
        var contest = honest.Contests[0];
        var mislabelled = contest.Selections.Select(selection =>
        {
            if (selection.ChoiceId != "contest-1-option-1")
            {
                return selection;
            }

            var vector = Enumerable.Range(1, 3).Select(k =>
            {
                IntegerModQ nonce = new PreEncryptionNonce(selectionHash, ballotNonce, 1, 1, k);
                return new EncryptedValue
                {
                    Alpha = MontgomeryModP.PowModP(EGParameters.G, nonce),
                    Beta = MontgomeryModP.PowModP(key, k == 2 ? nonce + 1 : nonce),
                };
            }).ToList();
            var hash = new SelectionHash(selectionHash, vector);
            return selection with { Vector = vector, SelectionHash = hash, ShortCode = HashTrimming.Trim(HashTrimmingFunction.FourHex, hash) };
        }).ToList();
        var forgedContest = contest with
        {
            Selections = mislabelled,
            ContestHash = ContestHash.ForPreEncryptedContest(selectionHash, 1, mislabelled.Select(x => x.SelectionHash)),
        };
        var contests = new List<PreEncryptedContest> { forgedContest, honest.Contests[1] };
        var forged = honest with
        {
            Contests = contests,
            ConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(selectionHash, contests.Select(x => x.ContestHash), honest.ChainingField),
        };

        // The device releases exactly the nonces it used: the honest eq. (121) values.
        var released = new BallotRecordingTool(election.Record).RecordUncast(honest, ballotNonce, releaseBallotNonce) with { Ballot = forged };

        new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(forged, election.Record);
        new UncastBallotContentVerification().Verify(election.Manifest, released);
        var exception = Assert.Throws<VerificationFailedException>(() => new UncastBallotEncryptionVerification().Verify(released, election.Record));
        Assert.Equal("18.A", exception.SubSection);
        Assert.Contains("contest-1-option-1", exception.Message);
    }

    /// <summary>
    /// The cheapest form of the attack: a device prints two honest vectors beside each other's
    /// options (option 1's label beside the vector that encrypts option 2, and the reverse) and
    /// releases each label's eq. (121) nonces honestly, with or without ξ_B. χ sorts the selection
    /// hashes, so every hash, χ and H_C is the honest ballot's: Verifications 16, 17 and 19 accept
    /// it, and so does 18.A's confirmation code, since the nonces recompute the honest set of
    /// vectors. Only comparing each recomputed encryption with the one published under its label
    /// (S9 hardening, reported as 18.A) shows that the code printed beside option 1 is a vote for
    /// option 2.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Verification18_TwoVectorsPrintedBesideEachOthersOptions_Fails18A(bool releaseBallotNonce)
    {
        var election = Election;
        var uncast = election.Uncast("uncast-1", releaseBallotNonce);
        var contest = uncast.Ballot.Contests[0];
        var selections = contest.Selections.ToList();
        (selections[0], selections[1]) = (
            selections[1] with { ChoiceId = selections[0].ChoiceId, SelectionIndex = selections[0].SelectionIndex },
            selections[0] with { ChoiceId = selections[1].ChoiceId, SelectionIndex = selections[1].SelectionIndex });
        var forged = uncast with { Ballot = uncast.Ballot with { Contests = [contest with { Selections = selections }, uncast.Ballot.Contests[1]] } };
        Assert.Equal(uncast.Ballot.ConfirmationCode, forged.Ballot.ConfirmationCode);

        new PreEncryptedConfirmationCodeVerification().Verify(forged.Ballot, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(forged.Ballot, election.Record);
        new UncastBallotContentVerification().Verify(election.Manifest, forged);
        var exception = Assert.Throws<VerificationFailedException>(() => new UncastBallotEncryptionVerification().Verify(forged, election.Record));
        Assert.Equal("18.A", exception.SubSection);
        Assert.Contains("is not Enc(", exception.Message);
    }

    [Fact]
    public void Verification18_WrongReleasedNonce_Fails18A()
    {
        var election = Election;
        var uncast = election.Uncast("uncast-1");
        var forged = WithNonce(uncast, 1, 2, 0, n => n + 1);

        Assert.Equal("18.A", Fails(() => new UncastBallotEncryptionVerification().Verify(forged, election.Record)));
    }

    /// <summary>With ξ_B released, a released nonce that is not its eq. (121) derivation fails 18.A, before any encryption is recomputed.</summary>
    [Fact]
    public void Verification18_ReleasedNonceNotDerivedFromTheReleasedBallotNonce_Fails18A()
    {
        var election = Election;
        var uncast = election.Uncast("uncast-1", releaseBallotNonce: true);
        var forged = WithNonce(uncast, 0, 0, 1, n => n + 1);

        var exception = Assert.Throws<VerificationFailedException>(() => new UncastBallotEncryptionVerification().Verify(forged, election.Record));

        Assert.Equal("18.A", exception.SubSection);
        Assert.Contains("eq. 121", exception.Message);
    }

    [Fact]
    public void Verification18_WrongReleasedBallotNonce_Fails18A()
    {
        var election = Election;
        var forged = election.Uncast("uncast-1", releaseBallotNonce: true) with { BallotNonce = new BallotNonce(new byte[32]) };

        Assert.Equal("18.A", Fails(() => new UncastBallotEncryptionVerification().Verify(forged, election.Record)));
    }

    [Fact]
    public void Verification18_ReplacedConfirmationCode_Fails18A()
    {
        var election = Election;
        var uncast = election.Uncast("uncast-1");
        var forged = uncast with { Ballot = uncast.Ballot with { ConfirmationCode = new ConfirmationCode(new byte[32]) } };

        var exception = Assert.Throws<VerificationFailedException>(() => new UncastBallotEncryptionVerification().Verify(forged, election.Record));

        Assert.Equal("18.A", exception.SubSection);
        Assert.Contains("confirmation code", exception.Message);
    }

    public static IEnumerable<object[]> MalformedReleases()
    {
        yield return ["no nonces for a contest", new Func<PreEncryptedUncastBallot, PreEncryptedUncastBallot>(u => u with { Contests = [u.Contests[0]] })];
        yield return ["a vector's nonces missing", new Func<PreEncryptedUncastBallot, PreEncryptedUncastBallot>(u => u with { Contests = [u.Contests[0] with { Selections = u.Contests[0].Selections.Skip(1).ToList() }, u.Contests[1]] })];
        yield return ["one nonce short", new Func<PreEncryptedUncastBallot, PreEncryptedUncastBallot>(u => WithNonces(u, 0, 0, n => n.Take(2).ToList()))];
        yield return ["contests in another order", new Func<PreEncryptedUncastBallot, PreEncryptedUncastBallot>(u => u with { Contests = [u.Contests[1], u.Contests[0]] })];
        yield return ["a 31-byte ballot nonce", new Func<PreEncryptedUncastBallot, PreEncryptedUncastBallot>(u => u with { BallotNonce = new BallotNonce(new byte[31]) })];
        yield return ["a null vector missing from the ballot", new Func<PreEncryptedUncastBallot, PreEncryptedUncastBallot>(u => u with { Ballot = u.Ballot with { Contests = [u.Ballot.Contests[0] with { Selections = u.Ballot.Contests[0].Selections.Take(3).ToList() }, u.Ballot.Contests[1]] } })];
    }

    [Theory]
    [MemberData(nameof(MalformedReleases))]
    public void Verification18_MalformedRecord_Fails18Structure(string description, Func<PreEncryptedUncastBallot, PreEncryptedUncastBallot> malform)
    {
        _ = description;
        var election = Election;
        var forged = malform(election.Uncast("uncast-1"));

        Assert.Equal("18.structure", Fails(() => new UncastBallotEncryptionVerification().Verify(forged, election.Record)));
    }

    private static PreEncryptedUncastBallot WithNonce(PreEncryptedUncastBallot uncast, int contest, int selection, int position, Func<IntegerModQ, IntegerModQ> change) =>
        WithNonces(uncast, contest, selection, nonces =>
        {
            var copy = nonces.ToList();
            copy[position] = change(copy[position]);
            return copy;
        });

    private static PreEncryptedUncastBallot WithNonces(PreEncryptedUncastBallot uncast, int contest, int selection, Func<List<IntegerModQ>, List<IntegerModQ>> change)
    {
        var contests = uncast.Contests.ToList();
        var selections = contests[contest].Selections.ToList();
        selections[selection] = selections[selection] with { Nonces = change(selections[selection].Nonces) };
        contests[contest] = contests[contest] with { Selections = selections };
        return uncast with { Contests = contests };
    }

    /// <summary>
    /// Eq. (121) indexes an option's vector by its option index and the l-th null vector by m + l
    /// (S9 structure rule): a vector whose published index disagrees is refused before 16.A.
    /// </summary>
    [Theory]
    [InlineData(0, 2)] // option 1's vector claiming option 2's index
    [InlineData(3, 3)] // contest-1's null vector claiming index 3 (an option's)
    [InlineData(3, 5)] // contest-1's null vector claiming index m + 2 (L = 1)
    public void Verification16_SelectionIndexDisagreesWithEq121_Fails16Structure(int selection, int index)
    {
        var election = Election;
        var ballot = election.PreEncrypt("ballot-1");
        var forged = WithSelections(ballot, 0, s => s.Select((x, i) => i == selection ? x with { SelectionIndex = index } : x).ToList());

        Assert.Equal("16.structure", Fails(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null)));
    }

    /// <summary>
    /// Each null vector has its own index among m + 1..m + L (eq. 121): in contest-2 (m = 4, L = 2)
    /// the second null vector claiming the first one's index m + 1 is refused.
    /// </summary>
    [Fact]
    public void Verification16_TwoNullVectorsShareAnIndex_Fails16Structure()
    {
        var election = Election;
        var ballot = election.PreEncrypt("ballot-1");
        Assert.Equal([null, null], ballot.Contests[1].Selections.Skip(4).Select(x => x.ChoiceId));
        var forged = WithSelections(ballot, 1, s => s.Select((x, i) => i == 5 ? x with { SelectionIndex = 5 } : x).ToList());

        var exception = Assert.Throws<VerificationFailedException>(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null));
        Assert.Equal("16.structure", exception.SubSection);
        Assert.Contains("own index", exception.Message);
    }

    /// <summary>Every ballot carries C_ξB with a 32-byte C_ξB,1 (§3.3.4, §4.2), pre-encrypted ones included.</summary>
    [Theory]
    [InlineData("missing")]
    [InlineData("31-byte C1")]
    public void Verification16_PreEncryptedBallotWithoutAWellFormedBallotNonce_Fails16Structure(string tamper)
    {
        var election = Election;
        var ballot = election.PreEncrypt("ballot-1");
        var nonce = ballot.EncryptedBallotNonce;
        var forged = ballot with
        {
            EncryptedBallotNonce = tamper == "missing"
                ? null!
                : new EncryptedBallotNonce { C0 = nonce.C0, C1 = nonce.C1[1..], Challenge = nonce.Challenge, Response = nonce.Response },
        };

        var exception = Assert.Throws<VerificationFailedException>(() => new PreEncryptedConfirmationCodeVerification().Verify(forged, election.DeviceHash, election.Record, null));
        Assert.Equal("16.structure", exception.SubSection);
        Assert.Contains("C_ξB", exception.Message);
    }

    // --- Verification 19 --------------------------------------------------------------------------

    public static IEnumerable<object[]> ContentViolations()
    {
        yield return ["19.A", "a contest not on the ballot style", new Func<PreEncryptedBallot, PreEncryptedBallot>(b => b with { Contests = [b.Contests[0], b.Contests[1] with { ContestId = "contest-9" }] })];
        yield return ["19.B", "a contest of the ballot style missing", new Func<PreEncryptedBallot, PreEncryptedBallot>(b => b with { Contests = [b.Contests[0]] })];
        yield return ["19.C", "an option label not in the contest", new Func<PreEncryptedBallot, PreEncryptedBallot>(b => WithSelections(b, 0, s => [s[0] with { ChoiceId = "contest-1-option-9" }, .. s.Skip(1)]))];
        yield return ["19.D", "an option of the contest missing", new Func<PreEncryptedBallot, PreEncryptedBallot>(b => WithSelections(b, 1, s => s.Where(x => x.ChoiceId != "contest-2-option-3").ToList()))];
        yield return ["19.D", "an option relabelled as a null vector", new Func<PreEncryptedBallot, PreEncryptedBallot>(b => WithSelections(b, 0, s => [s[0] with { ChoiceId = null }, .. s.Skip(1)]))];
        yield return ["19.structure", "an option listed twice", new Func<PreEncryptedBallot, PreEncryptedBallot>(b => WithSelections(b, 0, s => [.. s, s[0]]))];
        yield return ["19.structure", "a contest listed twice", new Func<PreEncryptedBallot, PreEncryptedBallot>(b => b with { Contests = [b.Contests[0], b.Contests[1], b.Contests[0]] })];
        yield return ["19.structure", "an unknown ballot style", new Func<PreEncryptedBallot, PreEncryptedBallot>(b => b with { BallotStyleId = "style-9" })];
    }

    [Theory]
    [MemberData(nameof(ContentViolations))]
    public void Verification19_ContentViolation_FailsItsSubSection(string subSection, string description, Func<PreEncryptedBallot, PreEncryptedBallot> change)
    {
        _ = description;
        var election = Election;
        var uncast = election.Uncast("uncast-1");

        Assert.Equal(subSection, Fails(() => new UncastBallotContentVerification().Verify(election.Manifest, uncast with { Ballot = change(uncast.Ballot) })));
    }

    private static PreEncryptedBallot WithSelections(PreEncryptedBallot ballot, int contest, Func<List<PreEncryptedSelection>, List<PreEncryptedSelection>> change)
    {
        var contests = ballot.Contests.ToList();
        contests[contest] = contests[contest] with { Selections = change(contests[contest].Selections) };
        return ballot with { Contests = contests };
    }
}
