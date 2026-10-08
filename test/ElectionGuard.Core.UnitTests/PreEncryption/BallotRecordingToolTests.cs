using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Core.Verify.Tally;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.PreEncryption;

/// <summary>
/// §4.3 the pre-encrypted ballot recording tool: cast records that verify and tally with regular
/// ballots, uncast records that open, the guardians' decryption of a pre-encrypted ballot's nonce,
/// and the inputs the tool refuses.
/// </summary>
public class BallotRecordingToolTests
{
    public BallotRecordingToolTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static PreEncryptedElection Election => PreEncryptedElection.Get();

    /// <summary>The plaintext σ of each component of a cast ballot's combined vector, from its summed nonce.</summary>
    private static int[] Plaintexts(EncryptedContest contest, EncryptionRecord record) => contest.Choices
        .Select(x =>
        {
            var gToNonce = MontgomeryModP.PowModP(record.ElectionPublicKeys.VoteEncryptionKey, x.EncryptionNonce!.Value);
            Assert.Equal(MontgomeryModP.PowModP(EGParameters.G, x.EncryptionNonce!.Value), x.Alpha);
            return x.Beta == gToNonce ? 0 : x.Beta == gToNonce * record.ElectionPublicKeys.VoteEncryptionKey ? 1 : -1;
        })
        .ToArray();

    [Fact]
    public void RecordCast_CombinesTheSelectedVectors_AndEveryBallotVerificationAccepts()
    {
        var election = Election;
        var (preEncrypted, cast) = election.Cast("cast-1", [2], [1, 4]);

        Assert.True(cast.IsPreEncrypted);
        Assert.Equal(BallotStatus.Cast, cast.Status);
        Assert.Equal(1, cast.Weight);
        Assert.Equal(preEncrypted.ConfirmationCode, cast.ConfirmationCode);
        Assert.Equal(preEncrypted.ChainingField, cast.ChainingField);
        Assert.Equal(preEncrypted.Contests.Select(x => x.ContestHash), cast.Contests.Select(x => x.ContestHash));
        Assert.Equal([0, 1, 0], Plaintexts(cast.Contests[0], election.Record));
        Assert.Equal([1, 0, 0, 1], Plaintexts(cast.Contests[1], election.Record));

        new SelectionEncryptionIdentifierVerification().Verify(cast.SelectionEncryptionIdentifier, cast.SelectionEncryptionIdentifierHash, election.Record.ExtendedBaseHash);
        new SelectionEncryptionsWellFormedVerification().Verify(cast, election.Record);
        new AdherenceToVoteLimitsVerification().Verify(cast, election.Record);
        new SelectionVectorAccumulationVerification().Verify(cast, election.Record);
        new PreEncryptedConfirmationCodeVerification().Verify(cast, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(cast, election.Record);
    }

    [Fact]
    public void RecordCast_PublishesEverySelectionHash_TheSelectedVectorsAndTheirShortCodes_AndNoOptionLabel()
    {
        var election = Election;
        var (preEncrypted, cast) = election.Cast("cast-1", [3], [2, 3]);

        for (int i = 0; i < cast.Contests.Count; i++)
        {
            var record = cast.PreEncryptedContests![i];
            var contest = preEncrypted.Contests[i];
            Assert.Equal(contest.ContestId, record.ContestId);

            // §4.4: every selection hash, null vectors included, sorted numerically.
            Assert.Equal(contest.Selections.Select(x => x.SelectionHash).Order(), record.SelectionHashes);

            // The selected vectors, sorted by hash, with their published (α, β) and short codes,
            // and no nonce.
            Assert.Equal(record.SelectedVectors.Select(x => x.SelectionHash).Order(), record.SelectedVectors.Select(x => x.SelectionHash));
            foreach (var selected in record.SelectedVectors)
            {
                var source = contest.Selections.Single(x => x.SelectionHash == selected.SelectionHash);
                Assert.NotNull(source.ChoiceId);
                Assert.Equal(source.ShortCode, selected.ShortCode);
                Assert.Equal(source.Vector.Select(x => (x.Alpha, x.Beta)), selected.Vector.Select(x => (x.Alpha, x.Beta)));
                Assert.All(selected.Vector, x => Assert.Null(x.EncryptionNonce));
            }
        }

        // The selected vectors are the voter's: option 3 of contest-1, options 2 and 3 of contest-2.
        Assert.Equal(["contest-1-option-3"], SelectedLabels(preEncrypted, cast, 0));
        Assert.Equal(["contest-2-option-2", "contest-2-option-3"], SelectedLabels(preEncrypted, cast, 1));
    }

    private static string[] SelectedLabels(PreEncryptedBallot preEncrypted, EncryptedBallot cast, int contest) =>
        cast.PreEncryptedContests![contest].SelectedVectors
            .Select(v => preEncrypted.Contests[contest].Selections.Single(x => x.SelectionHash == v.SelectionHash).ChoiceId!)
            .Order()
            .ToArray();

    /// <summary>
    /// An undervote is padded with the contest's first null vectors, so the record always shows L
    /// short codes (§4.1.5: "the use of null short codes allows the election record to not reveal
    /// undervotes"); the combined vector still encrypts only the voter's selections.
    /// </summary>
    [Theory]
    [InlineData(new int[0], new int[0])]
    [InlineData(new[] { 1 }, new[] { 4 })]
    public void RecordCast_Undervote_IsPaddedWithTheFirstNullVectors(int[] contest1, int[] contest2)
    {
        var election = Election;
        var (preEncrypted, cast) = election.Cast("undervote", contest1, contest2);

        for (int i = 0; i < 2; i++)
        {
            var contest = preEncrypted.Contests[i];
            int limit = election.Manifest.Contests[i].SelectionLimit;
            int selections = i == 0 ? contest1.Length : contest2.Length;
            var selected = cast.PreEncryptedContests![i].SelectedVectors
                .Select(v => contest.Selections.Single(x => x.SelectionHash == v.SelectionHash))
                .ToList();

            Assert.Equal(limit, selected.Count);
            Assert.Equal(
                contest.Selections.Where(x => x.IsNullVote).Take(limit - selections).Select(x => x.SelectionIndex).Order(),
                selected.Where(x => x.IsNullVote).Select(x => x.SelectionIndex).Order());
        }

        Assert.Equal(Enumerable.Range(1, 3).Select(j => contest1.Contains(j) ? 1 : 0), Plaintexts(cast.Contests[0], election.Record));
        Assert.Equal(Enumerable.Range(1, 4).Select(j => contest2.Contains(j) ? 1 : 0), Plaintexts(cast.Contests[1], election.Record));
        new AdherenceToVoteLimitsVerification().Verify(cast, election.Record);
        new SelectionVectorAccumulationVerification().Verify(cast, election.Record);
        new PreEncryptedConfirmationCodeVerification().Verify(cast, election.DeviceHash, election.Record, null);
    }

    [Fact]
    public void RecordCast_DoesNotModifyTheSelections()
    {
        var election = Election;
        var ballot = election.PreEncrypt("cast-1");
        var selections = election.Selections("cast-1", [1], [2, 4]);

        new BallotRecordingTool(election.Record).RecordCast(ballot, election.DecryptNonce(ballot), selections);

        Assert.Equal([1, 0, 0], selections.Contests[0].Choices.Select(x => x.SelectionValue));
        Assert.Equal([0, 1, 0, 1], selections.Contests[1].Choices.Select(x => x.SelectionValue));
    }

    /// <summary>
    /// p.64: "Verification 8 is only used for regular ElectionGuard ballots". A cast pre-encrypted
    /// ballot is refused, not reported as a wrong hash.
    /// </summary>
    [Fact]
    public void Verification8_CastPreEncryptedBallot_IsRefused()
    {
        var election = Election;
        var (_, cast) = election.Cast("cast-1", [1], [1]);

        var exception = Assert.Throws<VerificationFailedException>(() => new ConfirmationCodeVerification().Verify(cast, election.Record));

        Assert.Equal("8.structure", exception.SubSection);
    }

    /// <summary>
    /// "Ordinary and pre-encrypted ballots can be tallied together" (§4): regular and cast
    /// pre-encrypted ballots aggregate into one tally that Verifications 9, 10 and 11 accept and that
    /// decrypts to the sum of both kinds' selections. An uncast pre-encrypted ballot is not tallied.
    /// </summary>
    [Fact]
    public void Tally_MixedRegularAndPreEncryptedBallots_DecryptsToTheSumOfTheirSelections()
    {
        var election = Election;
        var record = election.Record;
        var regularDeviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "regular-device");
        var regular = new[]
        {
            ElectionFixtureBuilder.CreateEncryptedBallot(record, "regular-device", regularDeviceHash, election.Selections("regular-1", [1], [1, 2])),
            ElectionFixtureBuilder.CreateEncryptedBallot(record, "regular-device", regularDeviceHash, election.Selections("regular-2", [2], [])),
        };
        var cast = new[]
        {
            election.Cast("pre-1", [1], [2, 3]).Cast,
            election.Cast("pre-2", [3], [4]).Cast,
            election.Cast("pre-3", [], []).Cast,
        };
        var ballots = regular.Concat(cast).ToList();

        var tally = new EncryptedTally(election.Manifest);
        tally.AddBallots(ballots);
        new BallotAggregationVerification().Verify(ballots, election.Manifest, tally);
        var decrypted = new TallyAdmin().Decrypt(election.Guardians, tally, record);
        new TallyDecryptionVerification().Verify(record, tally, decrypted);
        new TallyContentsVerification().Verify(election.Manifest, decrypted, ballots);

        Assert.Equal(5, tally.BallotsCast);
        Assert.Equal([2, 1, 1], Enumerable.Range(1, 3).Select(j => decrypted.Contests["contest-1"].Choices[$"contest-1-option-{j}"].VoteCount));
        Assert.Equal([1, 2, 1, 1], Enumerable.Range(1, 4).Select(j => decrypted.Contests["contest-2"].Choices[$"contest-2-option-{j}"].VoteCount));
    }

    [Fact]
    public void RecordUncast_ReleasesEveryEncryptionNonce_AndVerifications16To19Accept()
    {
        var election = Election;
        var uncast = election.Uncast("uncast-1");

        Assert.Null(uncast.BallotNonce);
        Assert.Equal(uncast.Ballot.Contests.Select(x => x.ContestId), uncast.Contests.Select(x => x.ContestId));
        for (int i = 0; i < uncast.Contests.Count; i++)
        {
            var contest = uncast.Ballot.Contests[i];
            Assert.Equal(contest.Selections.Select(x => x.SelectionIndex), uncast.Contests[i].Selections.Select(x => x.SelectionIndex));
            for (int j = 0; j < contest.Selections.Count; j++)
            {
                var nonces = uncast.Contests[i].Selections[j].Nonces;
                Assert.Equal(contest.Selections[j].Vector.Select(x => x.Alpha), nonces.Select(x => MontgomeryModP.PowModP(EGParameters.G, x)));
            }
        }

        new PreEncryptedConfirmationCodeVerification().Verify(uncast.Ballot, election.DeviceHash, election.Record, null);
        new ShortCodeVerification().Verify(uncast.Ballot, election.Record);
        new UncastBallotEncryptionVerification().Verify(uncast, election.Record);
        new UncastBallotContentVerification().Verify(election.Manifest, uncast);
    }

    [Fact]
    public void RecordUncast_ReleasingTheBallotNonce_PublishesTheDecryptedBallotNonce()
    {
        var election = Election;
        var ballot = election.PreEncrypt("uncast-1");
        var ballotNonce = election.DecryptNonce(ballot);

        var uncast = new BallotRecordingTool(election.Record).RecordUncast(ballot, ballotNonce, releaseBallotNonce: true);

        Assert.Equal(ballotNonce.ToByteArray(), uncast.BallotNonce!.Value.ToByteArray());
        new UncastBallotEncryptionVerification().Verify(uncast, election.Record);
    }

    // --- Refused inputs -------------------------------------------------------------------------

    [Fact]
    public void Record_WrongBallotNonce_Throws()
    {
        var election = Election;
        var ballot = election.PreEncrypt("cast-1");
        var wrong = new BallotNonce(new byte[32]);
        var tool = new BallotRecordingTool(election.Record);

        Assert.Contains("does not regenerate", Assert.Throws<ArgumentException>(() => tool.RecordCast(ballot, wrong, election.Selections("cast-1", [1], [1]))).Message);
        Assert.Contains("does not regenerate", Assert.Throws<ArgumentException>(() => tool.RecordUncast(ballot, wrong)).Message);
    }

    /// <summary>A ballot whose confirmation code was replaced is not the one ξ_B regenerates.</summary>
    [Fact]
    public void Record_BallotWhoseConfirmationCodeDiffers_Throws()
    {
        var election = Election;
        var ballot = election.PreEncrypt("cast-1");
        var ballotNonce = election.DecryptNonce(ballot);
        var tampered = ballot with { ConfirmationCode = new ConfirmationCode(new byte[32]) };

        Assert.Throws<ArgumentException>(() => new BallotRecordingTool(election.Record).RecordUncast(tampered, ballotNonce));
    }

    /// <summary>
    /// The cut-and-choose attack at the recording tool: a printed ballot that is not what ξ_B
    /// regenerates, in a way the confirmation code cannot show, is refused selection by selection.
    /// <list type="bullet">
    /// <item>"swapped": two honest vectors printed beside each other's options (labels and indices
    /// kept, vector, hash and short code swapped). χ sorts the selection hashes, so every contest hash
    /// and H_C is the honest ballot's.</item>
    /// <item>"mislabelled": option 1's vector re-encrypted with a one at option 2's position, with the
    /// eq. (121) nonces of option 1, and every hash recomputed. Its H_C is internally consistent.</item>
    /// <item>"short code": one printed short code replaced, nothing else. Short codes enter no hash.</item>
    /// </list>
    /// Each is refused naming a selection vector, so the per-selection comparison fires, not the
    /// final H_C check. Otherwise the tool would publish the honest vector and short code for the
    /// option the voter named, which no longer matches the code the voter saw printed.
    /// </summary>
    [Theory]
    [InlineData("swapped", true)]
    [InlineData("swapped", false)]
    [InlineData("mislabelled", true)]
    [InlineData("mislabelled", false)]
    [InlineData("short code", true)]
    [InlineData("short code", false)]
    public void Record_PrintedBallotThatTheBallotNonceDoesNotRegenerate_IsRefusedPerSelection(string forgery, bool cast)
    {
        var election = Election;
        var honest = election.PreEncrypt("b");
        var ballotNonce = election.DecryptNonce(honest);
        var forged = forgery switch
        {
            "swapped" => SwapFirstTwoVectors(honest),
            "mislabelled" => MislabelOption1(honest, ballotNonce, election.Record),
            _ => ReplaceFirstShortCode(honest),
        };
        if (forgery != "mislabelled")
        {
            // Nothing but the per-selection comparison distinguishes these from the honest ballot.
            Assert.Equal(honest.Contests.Select(x => x.ContestHash), forged.Contests.Select(x => x.ContestHash));
            Assert.Equal(honest.ConfirmationCode, forged.ConfirmationCode);
        }

        var tool = new BallotRecordingTool(election.Record);
        var exception = Assert.Throws<ArgumentException>(() =>
        {
            _ = cast ? tool.RecordCast(forged, ballotNonce, election.Selections("b", [1], [1])) : (object)tool.RecordUncast(forged, ballotNonce);
        });

        Assert.Contains("does not regenerate", exception.Message);
        Assert.Contains("selection vector", exception.Message);
    }

    /// <summary>Contest-1's first two vectors printed beside each other's options (as Verification18_TwoVectorsPrintedBesideEachOthersOptions).</summary>
    private static PreEncryptedBallot SwapFirstTwoVectors(PreEncryptedBallot ballot)
    {
        var contest = ballot.Contests[0];
        var selections = contest.Selections.ToList();
        (selections[0], selections[1]) = (
            selections[1] with { ChoiceId = selections[0].ChoiceId, SelectionIndex = selections[0].SelectionIndex },
            selections[0] with { ChoiceId = selections[1].ChoiceId, SelectionIndex = selections[1].SelectionIndex });
        return ballot with { Contests = [contest with { Selections = selections }, .. ballot.Contests.Skip(1)] };
    }

    /// <summary>
    /// Contest-1 option 1's vector with the one moved to position 2, under option 1's eq. (121)
    /// nonces, with its hash, short code, contest hash and H_C recomputed (as Verification18_MislabelledVector).
    /// </summary>
    private static PreEncryptedBallot MislabelOption1(PreEncryptedBallot ballot, BallotNonce ballotNonce, EncryptionRecord record)
    {
        var selectionHash = ballot.SelectionEncryptionIdentifierHash;
        var key = record.ElectionPublicKeys.VoteEncryptionKey;
        var contest = ballot.Contests[0];
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
        List<PreEncryptedContest> contests = [forgedContest, .. ballot.Contests.Skip(1)];
        return ballot with
        {
            Contests = contests,
            ConfirmationCode = ConfirmationCode.ForPreEncryptedBallot(selectionHash, contests.Select(x => x.ContestHash), ballot.ChainingField),
        };
    }

    /// <summary>Contest-1's first short code replaced by one that differs from it, everything else honest.</summary>
    private static PreEncryptedBallot ReplaceFirstShortCode(PreEncryptedBallot ballot)
    {
        var contest = ballot.Contests[0];
        var selections = contest.Selections.ToList();
        var other = selections[0].ShortCode.Value == "0000" ? "0001" : "0000";
        selections[0] = selections[0] with { ShortCode = new ShortCode(other) };
        return ballot with { Contests = [contest with { Selections = selections }, .. ballot.Contests.Skip(1)] };
    }

    /// <summary>
    /// Each row: a description, the selections, and a fragment of the refusal message, so that each
    /// row is refused by its own check and not by an earlier one.
    /// </summary>
    public static IEnumerable<object[]> RefusedSelections()
    {
        // More than L selections (an overvote): contest-1 has L = 1.
        yield return ["overvote", new Func<PreEncryptedElection, Ballot>(e => e.Selections("b", [1, 2], [])), "its selection limit is 1"];
        // A selection value other than 0 or 1.
        yield return ["value 2", new Func<PreEncryptedElection, Ballot>(e =>
        {
            var b = e.Selections("b", [], []);
            b.Contests[1].Choices[0].SelectionValue = 2;
            return b;
        }), "a selection is 0 or 1"];
        // An option that is not in the contest.
        yield return ["unknown option", new Func<PreEncryptedElection, Ballot>(e =>
        {
            var b = e.Selections("b", [], []);
            b.Contests[0].Choices.Add(new BallotChoice { Id = "contest-2-option-1", SelectionValue = 1 });
            return b;
        }), "which is not an option of that contest"];
        // An option listed twice.
        yield return ["option twice", new Func<PreEncryptedElection, Ballot>(e =>
        {
            var b = e.Selections("b", [], []);
            b.Contests[0].Choices.Add(new BallotChoice { Id = "contest-1-option-1", SelectionValue = 0 });
            return b;
        }), "list option contest-1-option-1 more than once"];
        // A contest of the ballot left out.
        yield return ["contest missing", new Func<PreEncryptedElection, Ballot>(e => e.Selections("b", [], []) with { Contests = [e.Selections("b", [], []).Contests[0]] }), "omit contest contest-2"];
        // A contest that is not on the ballot.
        yield return ["foreign contest", new Func<PreEncryptedElection, Ballot>(e =>
        {
            var b = e.Selections("b", [], []);
            b.Contests.Add(new BallotContest { Id = "contest-3", Choices = [] });
            return b;
        }), "contest-3, which is not on pre-encrypted ballot"];
        // A contest listed twice.
        yield return ["contest twice", new Func<PreEncryptedElection, Ballot>(e =>
        {
            var b = e.Selections("b", [], []);
            b.Contests.Add(e.Selections("b", [], []).Contests[0]);
            return b;
        }), "list contest contest-1 more than once"];
        // Write-ins: a pre-encrypted ballot has no place for them.
        yield return ["write-in", new Func<PreEncryptedElection, Ballot>(e =>
        {
            var b = e.Selections("b", [], []);
            b.Contests[0] = b.Contests[0] with { NumWriteinsSelected = 1 };
            return b;
        }), "write-ins or contest data"];
        // Contest data without write-ins: no place for it either.
        yield return ["contest data", new Func<PreEncryptedElection, Ballot>(e =>
        {
            var b = e.Selections("b", [], []);
            b.Contests[0] = b.Contests[0] with { NumWriteinsSelected = 0, ContestData = new byte[32] };
            return b;
        }), "write-ins or contest data"];
        // Another ballot style.
        yield return ["ballot style", new Func<PreEncryptedElection, Ballot>(e => e.Selections("b", [], []) with { BallotStyleId = "other" }), "are for ballot style other"];
    }

    [Theory]
    [MemberData(nameof(RefusedSelections))]
    public void RecordCast_SelectionsItCannotRecord_Throw(string description, Func<PreEncryptedElection, Ballot> selections, string expectedMessage)
    {
        _ = description;
        var election = Election;
        var ballot = election.PreEncrypt("b");
        var ballotNonce = election.DecryptNonce(ballot);

        var exception = Assert.Throws<ArgumentException>(() => new BallotRecordingTool(election.Record).RecordCast(ballot, ballotNonce, selections(election)));

        Assert.Equal("selections", exception.ParamName);
        Assert.Contains(expectedMessage, exception.Message);
    }

    [Fact]
    public void Constructor_ManifestWithoutHashTrimmingFunction_Throws()
    {
        var election = Election;
        var record = new EncryptionRecord
        {
            CryptographicParameters = election.Record.CryptographicParameters,
            GuardianParameters = election.Record.GuardianParameters,
            ParameterBaseHash = election.Record.ParameterBaseHash,
            ManifestFile = election.Record.ManifestFile,
            ElectionBaseHash = election.Record.ElectionBaseHash,
            Guardians = election.Record.Guardians,
            ElectionPublicKeys = election.Record.ElectionPublicKeys,
            ExtendedBaseHash = election.Record.ExtendedBaseHash,
            Manifest = election.Manifest with { HashTrimmingFunction = null },
        };

        Assert.Throws<ArgumentException>(() => new BallotRecordingTool(record));
    }

    // --- The guardians' decryption of a pre-encrypted ballot's nonce ----------------------------

    [Fact]
    public void DecryptPreEncryptedBallotNonce_WithAQuorum_RegeneratesTheBallot()
    {
        var election = Election;
        var ballot = election.PreEncrypt("b");

        var ballotNonce = new TallyAdmin().DecryptPreEncryptedBallotNonce(election.Guardians.Take(2).ToList(), ballot, election.Record);

        Assert.Equal(ballot.ConfirmationCode, new BallotPreEncryptor(election.Record, PreEncryptedElection.DeviceId)
            .PreEncrypt(ballot.Id, ballot.BallotStyleId, ballot.SelectionEncryptionIdentifier, ballotNonce, null).ConfirmationCode);
    }

    [Fact]
    public void DecryptPreEncryptedBallotNonce_ACorruptShare_ThrowsWithoutNamingAGuardian()
    {
        var election = Election;
        var ballot = election.PreEncrypt("b");
        var admin = new TallyAdmin();
        var shares = election.Guardians.Take(2).Select(x => x.DecryptBallotNonce(ballot, election.Record)).ToList();
        shares[0] = new BallotNoncePartialDecryption { GuardianIndex = shares[0].GuardianIndex, BallotId = shares[0].BallotId, Mi = shares[0].Mi * new IntegerModP(EGParameters.G) };

        var exception = Assert.Throws<TallyDecryptionException>(() => admin.CombinePreEncryptedBallotNonce(ballot, election.Record, shares));

        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("regenerates", exception.Message);
    }

    [Fact]
    public void DecryptBallotNonce_PreEncryptedBallotWithAForeignSelectionIdentifierHash_Throws()
    {
        var election = Election;
        var ballot = election.PreEncrypt("b");
        var tampered = ballot with { SelectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(new byte[32]) };

        Assert.Throws<ArgumentException>(() => election.Guardians[0].DecryptBallotNonce(tampered, election.Record));
    }

    private static PreEncryptedBallot WithNonce(PreEncryptedBallot ballot, EncryptedBallotNonce nonce) => ballot with { EncryptedBallotNonce = nonce };

    private static EncryptedBallotNonce WithNonce(EncryptedBallotNonce nonce, IntegerModP? c0 = null, byte[]? c1 = null, IntegerModQ? challenge = null, IntegerModQ? response = null) => new()
    {
        C0 = c0 ?? nonce.C0,
        C1 = c1 ?? nonce.C1,
        Challenge = challenge ?? nonce.Challenge,
        Response = response ?? nonce.Response,
    };

    /// <summary>
    /// §3.6.7 p.52, as for a challenged ballot: "only if the proof is verified as correct" does a
    /// guardian decrypt a pre-encrypted ballot's nonce. A broken eq. (38) proof is refused by the
    /// guardian and again by the administrator, naming no guardian: the fault is the ballot's.
    /// </summary>
    [Theory]
    [InlineData("response")]
    [InlineData("challenge")]
    [InlineData("C1")]
    [InlineData("C0")]
    public void DecryptBallotNonce_PreEncryptedBallotWithAnInvalidSchnorrProof_IsRefusedNamingNoGuardian(string tamper)
    {
        var election = Election;
        var ballot = election.PreEncrypt("b");
        var nonce = ballot.EncryptedBallotNonce;
        var tampered = tamper switch
        {
            "response" => WithNonce(nonce, response: nonce.Response + 1),
            "challenge" => WithNonce(nonce, challenge: nonce.Challenge + 1),
            "C1" => WithNonce(nonce, c1: [(byte)(nonce.C1[0] ^ 1), .. nonce.C1[1..]]),
            _ => WithNonce(nonce, c0: nonce.C0 * new IntegerModP(EGParameters.G)),
        };
        Assert.False(BallotNonceEncryption.ProofHolds(ballot.SelectionEncryptionIdentifierHash, tampered));
        var bad = WithNonce(ballot, tampered);

        var exception = Assert.Throws<TallyDecryptionException>(() => election.Guardians[0].DecryptBallotNonce(bad, election.Record));
        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("eq. 38", exception.Message);

        // The administrator checks it again before combining anything.
        var shares = election.Guardians.Take(2).Select(x => x.DecryptBallotNonce(ballot, election.Record)).ToList();
        var adminException = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().CombinePreEncryptedBallotNonce(bad, election.Record, shares));
        Assert.Null(adminException.OffendingGuardian);
        Assert.Contains("eq. 38", adminException.Message);
    }

    /// <summary>
    /// The S6/S7 hardening on the pre-encrypted path: the eq. (38) proof accepts C_ξB,0 = 0 and
    /// C_ξB,0 = -g^ξ-hat (with an even c_B), so C_ξB,0 must be in Z_p^r before a guardian raises it
    /// to its share. The forged proofs are keyed with the pre-encrypted ballot's own H_I and C_ξB,1, so
    /// they hold and the refusal comes from the membership check.
    /// </summary>
    [Theory]
    [InlineData("zero")]
    [InlineData("negated")]
    public void DecryptBallotNonce_PreEncryptedBallotWithANonMemberC0AndAValidProof_IsRefusedNamingNoGuardian(string forgery)
    {
        var election = Election;
        var ballot = election.PreEncrypt("b");
        var selectionHash = ballot.SelectionEncryptionIdentifierHash;
        var c1 = ballot.EncryptedBallotNonce.C1;
        EncryptedBallotNonce forged;
        if (forgery == "zero")
        {
            // a_B = g^v·0^c = 0 for c != 0.
            var challenge = BallotNonceEncryption.ProofChallenge(selectionHash, 0, 0, c1);
            forged = new EncryptedBallotNonce { C0 = 0, C1 = c1, Challenge = challenge, Response = 12345 };
        }
        else
        {
            // C_ξB,0 = -g^ξ-hat with an even c_B: (-g^ξ-hat)^c_B = g^(ξ-hat·c_B), so the proof holds.
            IntegerModQ xiHat = ElectionGuardRandom.GetIntegerModQ();
            var negated = new IntegerModP(EGParameters.P - MontgomeryModP.PowModP(EGParameters.G, xiHat).ToBigInteger());
            while (true)
            {
                var u = ElectionGuardRandom.GetIntegerModQ();
                var challenge = BallotNonceEncryption.ProofChallenge(selectionHash, MontgomeryModP.PowModP(EGParameters.G, u), negated, c1);
                if (challenge.ToBigInteger().IsEven)
                {
                    forged = new EncryptedBallotNonce { C0 = negated, C1 = c1, Challenge = challenge, Response = u - challenge * xiHat };
                    break;
                }
            }
        }

        Assert.True(BallotNonceEncryption.ProofHolds(selectionHash, forged));
        Assert.False(SubgroupMembership.IsMember(forged.C0));
        var bad = WithNonce(ballot, forged);

        var exception = Assert.Throws<TallyDecryptionException>(() => election.Guardians[0].DecryptBallotNonce(bad, election.Record));
        Assert.Null(exception.OffendingGuardian);
        Assert.Contains("Z_p^r", exception.Message);

        var shares = election.Guardians.Take(2).Select(x => x.DecryptBallotNonce(ballot, election.Record)).ToList();
        var adminException = Assert.Throws<TallyDecryptionException>(() => new TallyAdmin().CombinePreEncryptedBallotNonce(bad, election.Record, shares));
        Assert.Null(adminException.OffendingGuardian);
        Assert.Contains("Z_p^r", adminException.Message);
    }

    /// <summary>A malformed pre-encrypted ballot (here a 31-byte C_ξB,1) is refused before any proof is checked.</summary>
    [Fact]
    public void DecryptBallotNonce_PreEncryptedBallotWithAShortC1_IsRefused()
    {
        var election = Election;
        var ballot = election.PreEncrypt("b");
        var bad = WithNonce(ballot, WithNonce(ballot.EncryptedBallotNonce, c1: ballot.EncryptedBallotNonce.C1[1..]));
        var shares = election.Guardians.Take(2).Select(x => x.DecryptBallotNonce(ballot, election.Record)).ToList();

        Assert.Contains("C_ξB,1", Assert.Throws<ArgumentException>(() => election.Guardians[0].DecryptBallotNonce(bad, election.Record)).Message);
        Assert.Throws<ArgumentException>(() => new TallyAdmin().CombinePreEncryptedBallotNonce(bad, election.Record, shares));
    }

    /// <summary>
    /// S9 review round 3: a printed ballot read from JSON that writes <c>"deviceId": null</c>. The
    /// property is required, but the reader does not enforce nullable annotations, so the ballot
    /// comes back without one. Before, every guardian answered it, and the administrator's
    /// regeneration (which builds a <see cref="BallotPreEncryptor"/> on the ballot's device) threw
    /// an <see cref="ArgumentNullException"/> that it reported as a wrong m_i or a wrong ξ_B. Now the
    /// structure check refuses it before any share is computed or combined, as malformed input.
    /// </summary>
    [Fact]
    public void DecryptBallotNonce_PreEncryptedBallotWithNoDeviceId_IsRefusedAsMalformed()
    {
        var election = Election;
        var ballot = election.PreEncrypt("b");
        var serializer = new ElectionGuard.Core.Serialization.JsonPreEncryptedBallotSerializer();
        using var written = new MemoryStream();
        serializer.Serialize(written, ballot);
        var node = System.Text.Json.Nodes.JsonNode.Parse(written.ToArray())!;
        Assert.Equal(ballot.DeviceId, (string?)node["deviceId"]);
        node["deviceId"] = null;
        using var tampered = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(node.ToJsonString()));
        var bad = serializer.DeserializeBallot(tampered)!;
        Assert.Null(bad.DeviceId);
        var shares = election.Guardians.Take(2).Select(x => x.DecryptBallotNonce(ballot, election.Record)).ToList();

        Assert.Contains("names no device", Assert.Throws<ArgumentException>(() => election.Guardians[0].DecryptBallotNonce(bad, election.Record)).Message);
        Assert.Contains("names no device", Assert.Throws<ArgumentException>(() => new TallyAdmin().CombinePreEncryptedBallotNonce(bad, election.Record, shares)).Message);
        Assert.Equal("16.structure", Assert.Throws<VerificationFailedException>(() => new PreEncryptedConfirmationCodeVerification().Verify(bad, election.DeviceHash, election.Record, null)).SubSection);
    }

    /// <summary>
    /// A regular cast ballot's published id_B, H_I and C_ξB, wrapped in a made-up pre-encrypted
    /// ballot of the right shape (S9 open question S9-6). A regular ballot's C_ξB is made exactly as
    /// a pre-encrypted ballot's (§4.2: "as shown in Section 3.3.4"), and the guardians' checks read
    /// only id_B, H_I and C_ξB, so the wrapper passes them unless something else refuses it.
    /// </summary>
    private static (EncryptedBallot Regular, PreEncryptedBallot Wrapper) RegularCastBallotWrappedAsPreEncrypted(PreEncryptedElection election)
    {
        var deviceHash = new VotingDeviceInformationHash(election.Record.ExtendedBaseHash, "regular-device");
        var regular = ElectionFixtureBuilder.CreateEncryptedBallot(election.Record, "regular-device", deviceHash, election.Selections("regular-1", [2], [1, 4]));
        Assert.Equal(BallotStatus.Cast, regular.Status);
        var wrapper = election.PreEncrypt("wrapper") with
        {
            SelectionEncryptionIdentifier = regular.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = regular.SelectionEncryptionIdentifierHash,
            EncryptedBallotNonce = regular.EncryptedBallotNonce,
        };

        // The regular cast ballot itself is refused on the challenged path.
        Assert.Throws<ArgumentException>(() => election.Guardians[0].DecryptBallotNonce(regular, election.Record));
        return (regular, wrapper);
    }

    /// <summary>
    /// The enforced part of S9-6: in an election whose manifest names no hash-trimming function,
    /// which therefore has no pre-encrypted ballots, a guardian and the administrator refuse the
    /// wrapper (§4.1.5).
    /// </summary>
    [Fact]
    public void DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_WithoutHashTrimming_IsRefused()
    {
        var election = Election;
        var (_, wrapper) = RegularCastBallotWrappedAsPreEncrypted(election);

        var recordWithoutPreEncryption = new EncryptionRecord
        {
            CryptographicParameters = election.Record.CryptographicParameters,
            GuardianParameters = election.Record.GuardianParameters,
            ParameterBaseHash = election.Record.ParameterBaseHash,
            ManifestFile = election.Record.ManifestFile,
            ElectionBaseHash = election.Record.ElectionBaseHash,
            Guardians = election.Record.Guardians,
            ElectionPublicKeys = election.Record.ElectionPublicKeys,
            ExtendedBaseHash = election.Record.ExtendedBaseHash,
            Manifest = election.Manifest with { HashTrimmingFunction = null },
        };
        var refused = Assert.Throws<ArgumentException>(() => election.Guardians[0].DecryptBallotNonce(wrapper, recordWithoutPreEncryption));
        Assert.Contains("hash-trimming", refused.Message);
        Assert.Throws<ArgumentException>(() => new TallyAdmin().CombinePreEncryptedBallotNonce(wrapper, recordWithoutPreEncryption, []));
    }

    /// <summary>
    /// KNOWN EXPOSURE, NOT A DESIRED BEHAVIOR (open question S9-6). In an election that has both
    /// kinds of ballot (its manifest names Ω), the guardians answer the wrapper, and their shares,
    /// combined as the challenged-ballot path combines them, open the regular cast ballot to its
    /// exact selections, bypassing its challenged-only gate.
    ///
    /// This test asserts that the attack succeeds so that the exposure stays visible and any change
    /// to it is noticed. When it fails because the guardians or the administrator now refuse the
    /// wrapper, S9-6 has been fixed: that is not a regression. Replace the open-the-ballot assertions
    /// with an assertion of the refusal, and rename the test without the KnownExposure suffix.
    /// </summary>
    [Fact]
    public void DecryptBallotNonce_RegularCastBallotWrappedAsPreEncrypted_WithHashTrimming_OpensIt_KnownExposure_S9_6()
    {
        var election = Election;
        var (regular, wrapper) = RegularCastBallotWrappedAsPreEncrypted(election);

        var shares = election.Guardians.Take(2).Select(x => x.DecryptBallotNonce(wrapper, election.Record)).ToList();
        var asChallenged = new EncryptedBallot
        {
            Id = wrapper.Id,
            BallotStyleId = regular.BallotStyleId,
            DeviceId = regular.DeviceId,
            SelectionEncryptionIdentifier = regular.SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = regular.SelectionEncryptionIdentifierHash,
            Contests = regular.Contests,
            ConfirmationCode = regular.ConfirmationCode,
            ChainingField = regular.ChainingField,
            EncryptedBallotNonce = regular.EncryptedBallotNonce,
            Weight = regular.Weight,
            Status = BallotStatus.Challenged,
        };
        var opened = new TallyAdmin().CombineChallengedBallot(asChallenged, election.Record, shares);
        Assert.Equal([0, 1, 0], opened.Contests[0].Choices.Select(x => x.Value));
        Assert.Equal([1, 0, 0, 1], opened.Contests[1].Choices.Select(x => x.Value));
    }
}
