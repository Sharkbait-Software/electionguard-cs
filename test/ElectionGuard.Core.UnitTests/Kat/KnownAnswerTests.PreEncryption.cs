using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Testing.Common;
using System.Buffers.Binary;
using System.Numerics;
using System.Text.Json;

namespace ElectionGuard.Core.UnitTests.Kat;

/// <summary>
/// Pre-encrypted ballots (§4.1-4.4, Verifications 6, 7 and 15-19) through the library's own API:
/// the encryption nonces of eq. (121) (0x45), selection and null-vector hashes (eqs. 113, 114; 0x40),
/// contest hashes (eq. 115; 0x41, ind_c, sorted), combined vectors and their proofs (eqs. 59 and 62,
/// 0x24, keyed with the pre-encrypted ballot's H_I), and the oracle's two ballots rebuilt end to end:
/// P1 pre-encrypted and recorded as cast, P2 pre-encrypted and recorded as uncast, each accepted by
/// the verifications that apply to it. The ballots are generated, combined and proved by the public
/// <see cref="PreEncryptionPrimitives"/>; the test-only <see cref="PreEncryptedBallotFixtures"/>
/// assembles them as a tool would (the library has no encrypting or recording tool, user decision
/// Q35).
/// </summary>
public partial class KnownAnswerTests
{
    private static JsonElement PreEncryptedSummary(string ballot) =>
        Root.GetProperty("preencrypted_ballots").GetProperty("ballots").EnumerateArray()
            .Single(x => x.GetProperty("ballot").GetString()!.StartsWith(ballot, StringComparison.Ordinal));

    private static IntegerModP MainChainVoteKey => IntegerModP.PowModP(EGParameters.G, new BigInteger(5));

    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_encryption_nonce")]
    public void PreEncryptedEncryptionNonce_Eq121(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!);

        // xi_{i,j,k} = H_q(H_I; 0x45, i, j, k, xi_B), xi_B as its 32 bytes, never reduced.
        IntegerModQ nonce = new PreEncryptionNonce(selectionHash, new BallotNonce(Hex(inputs, "xi_B_hex")), Int(inputs, "i"), Int(inputs, "j"), Int(inputs, "k"));

        AssertExpected(vector, nonce.ToByteArray());
        Assert.Equal(45, vector.GetProperty("b1_len").GetInt32());
    }

    /// <summary>
    /// Eqs. (113)/(114): each encryption of the vector is Enc(σ; ξ_{i,j,k}) with σ = 1 exactly at
    /// k = j (never for a null vector), and ψ hashes the 2m group elements.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_selection_hash")]
    [MemberData(nameof(VectorNames), "preencrypted_null_selection_hash")]
    public void PreEncryptedSelectionHash_Eq113And114(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!);
        var ballotNonce = new BallotNonce(Hex(inputs, "xi_B_hex"));
        int contestIndex = Int(inputs, "ind_c");
        int j = Int(inputs, "j");
        bool isNull = vector.GetProperty("family").GetString() == "preencrypted_null_selection_hash";
        Assert.Equal(isNull, j > Int(inputs, "m"));

        var encryptions = new List<EncryptedValue>();
        foreach (var encryption in inputs.GetProperty("encryptions").EnumerateArray())
        {
            int k = Int(encryption, "k");
            IntegerModQ nonce = new PreEncryptionNonce(selectionHash, ballotNonce, contestIndex, j, k);
            Assert.Equal(encryption.GetProperty("xi_hex").GetString(), ToHex(nonce.ToByteArray()));
            Assert.Equal(!isNull && k == j ? 1 : 0, Int(encryption, "sigma"));

            var alpha = MontgomeryModP.PowModP(EGParameters.G, nonce);
            var beta = MontgomeryModP.PowModP(MainChainVoteKey, nonce + Int(encryption, "sigma"));
            Assert.Equal(encryption.GetProperty("alpha_hex").GetString(), ToHex(alpha.ToByteArray()));
            Assert.Equal(encryption.GetProperty("beta_hex").GetString(), ToHex(beta.ToByteArray()));
            encryptions.Add(new EncryptedValue { Alpha = alpha, Beta = beta });
        }

        AssertExpected(vector, new SelectionHash(selectionHash, encryptions));
    }

    /// <summary>
    /// Eq. (115) with b(ind_c, 4) and the m + L hashes sorted ascending. The oracle's diagnostics (the
    /// unsorted form, and 16.B's literal position l where it differs from ind_c) are not the spec's.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_contest_hash")]
    public void PreEncryptedContestHash_Eq115(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!);
        var hashes = inputs.GetProperty("selection_hashes_generation_order_hex").EnumerateArray()
            .Select(x => new SelectionHash(Convert.FromHexString(x.GetString()!)))
            .ToList();
        Assert.Equal(Int(inputs, "m") + Int(inputs, "L"), hashes.Count);

        var contestHash = ContestHash.ForPreEncryptedContest(selectionHash, Int(inputs, "ind_c"), hashes);

        AssertExpected(vector, contestHash);
        foreach (var diagnostic in vector.GetProperty("diagnostics").EnumerateArray())
        {
            Assert.False(diagnostic.GetProperty("expected").GetBoolean());
            Assert.NotEqual(diagnostic.GetProperty("hash_hex").GetString(), ToHex(contestHash));
        }
    }

    /// <summary>
    /// Eq. (59) on a combined vector component (§4.3), as Verification 6.3 recomputes it from the
    /// published proof: c = H_q(H_I; 0x24, ind_c, ind_o, α, β, a_0, b_0, a_1, b_1).
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_range_proof_challenge")]
    public void PreEncryptedRangeProofChallenge_Eq59(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!);
        byte[] prefix = new byte[9];
        prefix[0] = 0x24;
        BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(1), Int(inputs, "ind_c"));
        BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(5), Int(inputs, "ind_o"));

        var challenge = new RangeProofChallenge(MainChainVoteKey).Compute(selectionHash, prefix, P(inputs, "alpha_hex"), P(inputs, "beta_hex"), OracleProofs(inputs));

        AssertExpected(vector, challenge.ToByteArray());
        Assert.Equal(inputs.GetProperty("proof").GetProperty("c_hex").GetString(), ToHex(challenge.ToByteArray()));
    }

    /// <summary>Eq. (62) on a contest's combined vector: c = H_q(H_I; 0x24, ind_c, ᾱ, β̄, a_0, b_0, ..., a_L, b_L), no ind_o.</summary>
    [Theory]
    [MemberData(nameof(VectorNames), "preencrypted_selection_limit_challenge")]
    public void PreEncryptedSelectionLimitChallenge_Eq62(string name)
    {
        var vector = Vector(name);
        var inputs = Inputs(vector);
        var selectionHash = SelectionEncryptionIdentifierHashFor(inputs.GetProperty("H_I_hex").GetString()!);
        byte[] prefix = new byte[5];
        prefix[0] = 0x24;
        BinaryPrimitives.WriteInt32BigEndian(prefix.AsSpan(1), Int(inputs, "ind_c"));

        var challenge = new RangeProofChallenge(MainChainVoteKey).Compute(selectionHash, prefix, P(inputs, "alpha_bar_hex"), P(inputs, "beta_bar_hex"), OracleProofs(inputs));

        AssertExpected(vector, challenge.ToByteArray());
        Assert.Equal(Int(inputs, "L") + 1, OracleProofs(inputs).Length);
    }

    private static ChallengeResponsePair[] OracleProofs(JsonElement inputs)
    {
        var proof = inputs.GetProperty("proof");
        var challenges = proof.GetProperty("c_j_hex").EnumerateArray().Select(x => new IntegerModQ(Convert.FromHexString(x.GetString()!))).ToList();
        var responses = proof.GetProperty("v_j_hex").EnumerateArray().Select(x => new IntegerModQ(Convert.FromHexString(x.GetString()!))).ToList();
        return challenges.Select((c, j) => new ChallengeResponsePair { Challenge = c, Response = responses[j] }).ToArray();
    }

    /// <summary>
    /// The main-chain election (K = g^5) with contests 1..5 shaped as the oracle's two pre-encrypted
    /// ballots need them (m options, selection limit L, R = 1), one ballot style holding the
    /// contests of <paramref name="ballot"/>, Ω1 (two hex characters, the oracle's
    /// <c>omega_last_byte_hex</c>), and the chaining mode its B_C shows.
    /// </summary>
    private static (EncryptionRecord Record, JsonElement Summary) PreEncryptedRecord(string ballot)
    {
        var shapes = Root.GetProperty("preencrypted_ballots").GetProperty("ballots").EnumerateArray()
            .SelectMany(x => x.GetProperty("contests").EnumerateArray())
            .ToDictionary(x => Int(x, "ind_c"), x => (M: Int(x, "m"), L: Int(x, "L")));
        var contests = Enumerable.Range(1, shapes.Keys.Max()).Select(index => new Contest
        {
            Id = $"contest-{index}",
            Name = $"Contest {index}",
            SelectionLimit = shapes[index].L,
            OptionSelectionLimit = 1,
            Index = index,
            Choices = Enumerable.Range(1, shapes[index].M).Select(j => new Choice { Id = $"contest-{index}-option-{j}", Name = $"Option {j}", Index = j }).ToList(),
        }).ToList();

        var summary = PreEncryptedSummary(ballot);
        var mode = summary.GetProperty("B_C_hex").GetString()!.StartsWith("00000000", StringComparison.Ordinal) ? ChainingMode.None : ChainingMode.Simple;
        var styleContests = summary.GetProperty("contests").EnumerateArray().Select(x => $"contest-{Int(x, "ind_c")}").ToList();
        return (MainChainRecord(contests, mode, styleContests, HashTrimmingFunction.TwoHex), summary);
    }

    /// <summary>
    /// P1, rebuilt from its id_B and ξ_B (no chaining, main-chain device), has the oracle's
    /// selection hashes in generation order, short codes, contest hashes, B_C and H_C. Recorded as
    /// cast with the oracle's selections, and with the oracle's proof nonces through the internal
    /// test seam of <see cref="PreEncryptionPrimitives.ProveCombinedContest"/>, every combined vector component (α, β, summed ξ) and every proof
    /// (each c_j and v_j of eqs. 59 and 62) is the oracle's; the selected vectors are the ones the
    /// oracle combined (null vectors padding the ind_c = 4 undervote); and Verifications 6, 7, 15, 16
    /// and 17 accept the record.
    /// </summary>
    [Fact]
    public void PreEncryptedBallot_P1_RecordedAsCast_ReproducesTheOracle()
    {
        var (record, summary) = PreEncryptedRecord("P1");
        string device = summary.GetProperty("S_device").GetString()!;
        var ballotNonce = new BallotNonce(Hex(summary, "xi_B_hex"));
        var ballot = PreEncryptedBallotFixtures.PreEncrypt(record, device, "P1", "style", new SelectionEncryptionIdentifier(Hex(summary, "id_B_hex")), ballotNonce, previousConfirmationCode: null);

        AssertBallotMatchesSummary(ballot, summary);

        // The combined vectors proved with the oracle's u_j and simulated c_j.
        var rangeProofs = AllVectors.Where(x => x.GetProperty("family").GetString() == "preencrypted_range_proof_challenge")
            .ToDictionary(x => (Int(Inputs(x), "ind_c"), (int?)Int(Inputs(x), "ind_o")), Inputs);
        var limitProofs = AllVectors.Where(x => x.GetProperty("family").GetString() == "preencrypted_selection_limit_challenge")
            .ToDictionary(x => (Int(Inputs(x), "ind_c"), (int?)null), Inputs);
        var proofInputs = rangeProofs.Concat(limitProofs).ToDictionary();
        PreEncryptedBallotFixtures.CombinedContestProver prover = (keys, contest, selectionHash, combined, values, contestHash) =>
            PreEncryptionPrimitives.ProveCombinedContest(keys, contest, selectionHash, combined, values, contestHash, (optionIndex, j) =>
            {
                var inputs = proofInputs[(contest.Index, optionIndex)];
                var u = new IntegerModQ(Convert.FromHexString(inputs.GetProperty("u_hex")[j].GetString()!));
                var c = inputs.GetProperty("c_fake_hex").TryGetProperty(j.ToString(), out var fake) ? new IntegerModQ(Convert.FromHexString(fake.GetString()!)) : new IntegerModQ(0);
                return (u, c);
            });

        var contestSummaries = summary.GetProperty("contests").EnumerateArray().ToList();
        var selections = new Core.BallotEncryption.Ballot
        {
            Id = "P1",
            BallotStyleId = "style",
            Contests = contestSummaries.Select(x =>
            {
                int index = Int(x, "ind_c");
                var selected = x.GetProperty("recording").GetProperty("selected_options").EnumerateArray().Select(o => o.GetInt32()).ToList();
                return new BallotContest
                {
                    Id = $"contest-{index}",
                    Choices = Enumerable.Range(1, Int(x, "m")).Select(j => new BallotChoice { Id = $"contest-{index}-option-{j}", SelectionValue = selected.Contains(j) ? 1 : 0 }).ToList(),
                };
            }).ToList(),
        };

        var cast = PreEncryptedBallotFixtures.RecordCast(record, ballot, ballotNonce, selections, prover);

        for (int c = 0; c < contestSummaries.Count; c++)
        {
            var contestSummary = contestSummaries[c];
            int index = Int(contestSummary, "ind_c");
            var recording = contestSummary.GetProperty("recording");
            var contest = cast.Contests[c];
            Assert.Equal($"contest-{index}", contest.Id);

            // §4.3: the componentwise product, nonces summed mod q (Verification 15).
            var combined = recording.GetProperty("combined_vector").EnumerateArray().ToList();
            Assert.Equal(combined.Count, contest.Choices.Count);
            for (int k = 0; k < combined.Count; k++)
            {
                Assert.Equal(combined[k].GetProperty("alpha_hex").GetString(), ToHex(contest.Choices[k].Alpha.ToByteArray()));
                Assert.Equal(combined[k].GetProperty("beta_hex").GetString(), ToHex(contest.Choices[k].Beta.ToByteArray()));
                Assert.Equal(combined[k].GetProperty("xi_hex").GetString(), ToHex(contest.Choices[k].EncryptionNonce!.Value.ToByteArray()));
                AssertProof(rangeProofs[(index, k + 1)], contest.Choices[k].Proofs);
            }

            AssertProof(limitProofs[(index, null)], contest.Proofs);

            // The vectors combined, padded with null vectors: their hashes and short codes.
            var generationOrder = contestSummary.GetProperty("selection_hashes_generation_order_hex").EnumerateArray().Select(x => x.GetString()!).ToList();
            var combinedFrom = recording.GetProperty("combined_from_j").EnumerateArray().Select(x => generationOrder[x.GetInt32() - 1]).Order(StringComparer.Ordinal);
            var preEncrypted = cast.PreEncryptedContests![c];
            Assert.Equal(combinedFrom, preEncrypted.SelectedVectors.Select(x => x.SelectionHash.ToString()));
            Assert.Equal(
                recording.GetProperty("selected_short_codes_last_byte_hex").EnumerateArray().Select(x => x.GetString()!).Order(StringComparer.Ordinal),
                preEncrypted.SelectedVectors.Select(x => x.ShortCode.Value).Order(StringComparer.Ordinal));
            Assert.Equal(generationOrder.Order(StringComparer.Ordinal), preEncrypted.SelectionHashes.Select(x => x.ToString()));
        }

        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, device);
        new SelectionEncryptionsWellFormedVerification().Verify(cast, record);
        new AdherenceToVoteLimitsVerification().Verify(cast, record);
        new SelectionVectorAccumulationVerification().Verify(cast, record);
        new PreEncryptedConfirmationCodeVerification().Verify(cast, deviceHash, record, null);
        new ShortCodeVerification().Verify(cast, record);
    }

    private static void AssertProof(JsonElement inputs, ChallengeResponsePair[] proofs)
    {
        var expected = OracleProofs(inputs);
        Assert.Equal(expected.Select(x => ToHex(x.Challenge.ToByteArray())), proofs.Select(x => ToHex(x.Challenge.ToByteArray())));
        Assert.Equal(expected.Select(x => ToHex(x.Response.ToByteArray())), proofs.Select(x => ToHex(x.Response.ToByteArray())));
    }

    /// <summary>
    /// P2 (simple chaining, the first ballot of device "kat pre-encrypted ballot printer 2", ξ_B = q + 11
    /// as raw bytes), rebuilt and recorded as uncast with ξ_B released: every released nonce is the
    /// oracle's eq. (121) vector for its (i, j, k), and Verifications 16, 17, 18 and 19 accept the
    /// record.
    /// </summary>
    [Fact]
    public void PreEncryptedBallot_P2_RecordedAsUncast_ReleasesTheOraclesNonces_AndVerifications16To19Accept()
    {
        var (record, summary) = PreEncryptedRecord("P2");
        string device = summary.GetProperty("S_device").GetString()!;
        var ballotNonce = new BallotNonce(Hex(summary, "xi_B_hex"));
        var ballot = PreEncryptedBallotFixtures.PreEncrypt(record, device, "P2", "style", new SelectionEncryptionIdentifier(Hex(summary, "id_B_hex")), ballotNonce, previousConfirmationCode: null);

        AssertBallotMatchesSummary(ballot, summary);

        var uncast = PreEncryptedBallotFixtures.RecordUncast(record, ballot, ballotNonce, releaseBallotNonce: true);

        var nonceVectors = AllVectors.Where(x => x.GetProperty("family").GetString() == "preencrypted_encryption_nonce"
                && Inputs(x).GetProperty("H_I_hex").GetString() == summary.GetProperty("H_I_hex").GetString())
            .ToDictionary(x => (Int(Inputs(x), "i"), Int(Inputs(x), "j"), Int(Inputs(x), "k")), x => x.GetProperty("expected_hex").GetString());
        int released = 0;
        for (int c = 0; c < uncast.Contests.Count; c++)
        {
            int index = ballot.Contests[c].ContestIndex;
            foreach (var selection in uncast.Contests[c].Selections)
            {
                for (int k = 0; k < selection.Nonces.Count; k++)
                {
                    Assert.Equal(nonceVectors[(index, selection.SelectionIndex, k + 1)], ToHex(selection.Nonces[k].ToByteArray()));
                    released++;
                }
            }
        }

        Assert.Equal(nonceVectors.Count, released);
        Assert.Equal(summary.GetProperty("xi_B_hex").GetString(), ToHex(uncast.BallotNonce!.Value.ToByteArray()));

        var deviceHash = VotingDeviceInformationHash.ForPreEncryptedBallots(record.ExtendedBaseHash, device);
        new PreEncryptedConfirmationCodeVerification().Verify(ballot, deviceHash, record, null);
        new ShortCodeVerification().Verify(ballot, record);
        new UncastBallotEncryptionVerification().Verify(uncast, record);
        new UncastBallotContentVerification().Verify(record.Manifest, uncast);
    }

    /// <summary>The rebuilt ballot's selection hashes (generation order), short codes, contest hashes, B_C and H_C are the summary's.</summary>
    private static void AssertBallotMatchesSummary(PreEncryptedBallot ballot, JsonElement summary)
    {
        var contestSummaries = summary.GetProperty("contests").EnumerateArray().ToList();
        Assert.Equal(contestSummaries.Count, ballot.Contests.Count);
        for (int c = 0; c < contestSummaries.Count; c++)
        {
            var contestSummary = contestSummaries[c];
            var contest = ballot.Contests[c];
            Assert.Equal(Int(contestSummary, "ind_c"), contest.ContestIndex);

            // Generation order: option vectors j = 1..m, then null vectors j = m + 1..m + L.
            Assert.Equal(
                contestSummary.GetProperty("selection_hashes_generation_order_hex").EnumerateArray().Select(x => x.GetString()),
                contest.Selections.Select(x => x.SelectionHash.ToString()));
            Assert.Equal(
                contestSummary.GetProperty("short_codes").EnumerateArray().Select(x => x.GetProperty("omega_last_byte_hex").GetString()),
                contest.Selections.Select(x => x.ShortCode.Value));
            Assert.Equal(contestSummary.GetProperty("chi_hex").GetString(), ToHex(contest.ContestHash));
        }

        Assert.Equal(summary.GetProperty("B_C_hex").GetString(), ToHex(ballot.ChainingField));
        Assert.Equal(summary.GetProperty("H_C_hex").GetString(), ToHex(ballot.ConfirmationCode));
    }
}
