using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using static ElectionGuard.Core.Tally.DecryptedTally;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// A guardian's side of verifiable decryption: of a tally (§3.6.3-§3.6.5), and of one ballot
/// contest's contest data field (§3.6.6). For every option of every contest, the participating
/// guardians U jointly compute M = A^s (eq. 86) and a Chaum-Pedersen proof (c, v) that they did
/// (eqs. 87-93), in three rounds, each a method here:
/// <list type="number">
/// <item><see cref="Commit"/>: pick a fresh secret u_i, compute M_i = A^{z_i} (eq. 84) and the
/// commitment pair (a_i, b_i) = (g^{u_i}, A^{u_i}) (eq. 87), and send M_i with the commitment hash
/// d_i (eq. 88), keeping (a_i, b_i) back.</item>
/// <item><see cref="Reveal"/>: once every participant's d_j has arrived, send (a_i, b_i).</item>
/// <item><see cref="Respond"/>: check every revealed (a_j, b_j, M_j) against its d_j, halting with a
/// <see cref="TallyDecryptionException"/> naming the guardian if one does not match (p.48); compute
/// a, b, M (eqs. 86, 89) and the challenge c (eq. 90) itself, and send
/// v_i = u_i - c·w_i·z_i (eqs. 91, 92).</item>
/// </list>
/// Contest data decryption is "exactly the same" protocol (§3.6.6 p.50) over the field's C_0, with
/// the ballot data encryption key share ẑ_i, the hashes of eqs. (99) and (101) keyed with H_I, and
/// one extra step first: the guardian checks the field's Schnorr proof C_2 (eq. 69) and refuses to
/// decrypt if it fails (<see cref="CommitContestData"/>, <see cref="RevealContestData"/>,
/// <see cref="RespondContestData"/>). Both run on <see cref="VerifiableDecryption"/>.
///
/// The administrator mediates every message (<see cref="TallyAdmin"/>). There is no network layer
/// in this library: <see cref="TallyAdmin.Decrypt"/> drives in-process guardians through the three
/// rounds, and a distributed deployment carries the same three messages between machines and hands
/// them to <see cref="TallyAdmin.Combine"/> (<see cref="TallyAdmin.DecryptContestData"/> and
/// <see cref="TallyAdmin.CombineContestData"/> for contest data).
///
/// The guardian never accepts a challenge from anyone. It computes c from values that every
/// participant committed to before any was revealed, so no one can choose c after seeing a
/// commitment. Each u_i is used for exactly one response: the respond step discards the
/// decryption in progress, and a second call throws. Two responses with one u_i to two different
/// challenges would give away the key share.
///
/// A challenged ballot is opened differently (§3.6.7): the guardian checks the ballot's encrypted
/// nonce C_ξB (membership of C_ξB,0 and the eq. (38) Schnorr proof) and sends m_i = C_ξB,0^{ẑ_i}
/// alone (<see cref="DecryptBallotNonce"/>); the administrator recovers ξ_B and releases the
/// encryption nonces derived from it (<see cref="TallyAdmin.CombineChallengedBallot"/>).
///
/// A guardian works on one decryption at a time, a tally's or a contest data field's. Either commit
/// step starts a new one and discards any unfinished one, which is safe: nothing is ever responded
/// with an old u_i. The reveal and respond steps of one kind refuse a decryption of the other kind.
/// </summary>
public class TallyGuardian
{
    public TallyGuardian(GuardianIndex index, GuardianSecretShares shares)
    {
        _index = index;
        _shares = shares;
    }

    private readonly GuardianIndex _index;
    private readonly GuardianSecretShares _shares;
    private object? _session;

    public GuardianIndex Index => _index;

    /// <summary>
    /// Test seam: supplies u_i for an option, given (ind_c, ind_o), in place of a fresh random
    /// value; for a contest data field, given (ind_c, 0) (no option index is 0). Lets the
    /// known-answer tests reproduce the spec oracle's proofs exactly. Null outside tests.
    /// </summary>
    internal Func<int, int, IntegerModQ>? NonceSourceForTesting { get; set; }

    /// <summary>
    /// Test seam: replaces this guardian's M_i for an option, given (ind_c, ind_o, M_i), before it is
    /// hashed into d_i and sent: a dishonest guardian that is consistent about its wrong share, such
    /// as M_i·K^(-δ/w_i), which would shift the count by δ if nothing checked the proof. For a
    /// contest data field it is given (ind_c, 0, m_i), and for a ballot nonce (0, 0, m_i). Null
    /// outside tests.
    /// </summary>
    internal Func<int, int, IntegerModP, IntegerModP>? PartialDecryptionTamperForTesting { get; set; }

    /// <summary>
    /// Round 1. Starts a decryption of <paramref name="encryptedTally"/> by
    /// <paramref name="participants"/> (U, which must include this guardian and be a quorum: at
    /// least k distinct indices in 1..n), and returns this guardian's M_i and d_i for every option
    /// of every contest in <paramref name="encryptionRecord"/>'s manifest. The indices ind_c and
    /// ind_o, H_E and n, k come from the record and <see cref="EGParameters"/>, never from the
    /// tally. Works on up to <paramref name="maxDegreeOfParallelism"/> threads (-1, the default,
    /// for no limit).
    /// </summary>
    public PartialTallyDecryption Commit(
        EncryptedTally encryptedTally,
        EncryptionRecord encryptionRecord,
        IReadOnlyCollection<GuardianIndex> participants,
        int maxDegreeOfParallelism = -1)
    {
        _session = null;

        var sorted = RequireParticipant(participants);
        var options = TallyOption.ForTally(encryptionRecord, encryptedTally);
        var nonceSource = NonceSourceForTesting;
        var tamper = PartialDecryptionTamperForTesting;
        var session = Begin(
            options,
            sorted,
            _shares.VoteEncryptionKeyShare,
            nonceSource is null ? null : o => nonceSource(options[o].ContestIndex, options[o].ChoiceIndex),
            tamper is null ? null : (o, m) => tamper(options[o].ContestIndex, options[o].ChoiceIndex, m),
            maxDegreeOfParallelism);

        return TallyDecryptionMessages.Commitment(_index, options, session.Round1.PartialDecryptions, session.Round1.CommitmentHashes);
    }

    /// <summary>
    /// Round 2. Given every participant's round-1 message, this guardian's included unchanged,
    /// returns its commitment pairs (a_i, b_i). Refuses, with a <see cref="TallyDecryptionException"/>
    /// naming the guardian, if a participant's message is missing, repeated or malformed, or comes
    /// from a guardian outside U: (a_i, b_i) may be revealed only after every d_j is in (p.47).
    /// </summary>
    public TallyDecryptionCommitmentReveal Reveal(IReadOnlyCollection<PartialTallyDecryption> commitments)
    {
        var session = Current<TallyOption>("a reveal", "Commit");
        Accept(session, () => TallyDecryptionMessages.ReadCommitments(commitments, session.Participants, session.Statements));
        return TallyDecryptionMessages.Reveal(_index, session.Statements, session.Round1.CommitmentsA, session.Round1.CommitmentsB);
    }

    /// <summary>
    /// Round 3. Given every participant's round-2 message, this guardian's included unchanged,
    /// checks each guardian's d_j against the (a_j, b_j) it revealed and the M_j it sent, by eq. (88)
    /// over this guardian's own A, B, indices and U; computes a, b, M and the challenge c (eq. 90);
    /// and returns v_i = (u_i - c·w_i·z_i) mod q for every option. Any failure halts the decryption
    /// with a <see cref="TallyDecryptionException"/> naming the guardian. Either way the decryption
    /// is over: u_i is discarded and a second call throws <see cref="InvalidOperationException"/>.
    /// </summary>
    public TallyDecryptionResponse Respond(IReadOnlyCollection<TallyDecryptionCommitmentReveal> reveals, int maxDegreeOfParallelism = -1)
    {
        var session = Current<TallyOption>("a response", "Commit and Reveal");
        var responses = RespondTo(
            session,
            () => TallyDecryptionMessages.ReadReveals(reveals, session.Participants, session.Statements),
            _shares.VoteEncryptionKeyShare,
            maxDegreeOfParallelism);

        return TallyDecryptionMessages.Response(_index, session.Statements, responses);
    }

    /// <summary>
    /// Round 1 of a contest data decryption (§3.6.6): starts a decryption of contest
    /// <paramref name="contestId"/>'s contest data field on <paramref name="ballot"/> by
    /// <paramref name="participants"/> (U, which must include this guardian and be a quorum). First
    /// checks that C_0 is in Z_p^r (a library hardening the spec does not state; see
    /// <c>ContestDataStatement.RequireDecryptable</c>) and verifies the field's Schnorr proof C_2:
    /// a = g^v·C_0^c and c = H_q(H_I; 0x27, ind_c, a, C_0, C_1) (eq. 69); "only if this is the case"
    /// does the guardian compute m_i = C_0^{ẑ_i} (eq. 96), the commitment pair (g^{u_i}, C_0^{u_i})
    /// (eq. 98) and d_i (eq. 99). A non-member C_0 or a failing proof throws
    /// <see cref="TallyDecryptionException"/> naming no guardian, as does nothing else here; a malformed ballot, a
    /// contest that declares no contest data, or a ballot whose H_I is not H(H_E; 0x20, id_B) throws
    /// <see cref="ArgumentException"/>. ind_c, b_Λ and H_E come from <paramref name="encryptionRecord"/>.
    /// </summary>
    public ContestDataPartialDecryption CommitContestData(
        EncryptedBallot ballot,
        string contestId,
        EncryptionRecord encryptionRecord,
        IReadOnlyCollection<GuardianIndex> participants)
    {
        _session = null;

        var sorted = RequireParticipant(participants);
        var statement = ContestDataStatement.For(encryptionRecord, ballot, contestId);
        statement.RequireDecryptable($"guardian {_index.Index}");

        var nonceSource = NonceSourceForTesting;
        var tamper = PartialDecryptionTamperForTesting;
        var session = Begin(
            [statement],
            sorted,
            _shares.OtherBallotDataEncryptionKeyShare,
            nonceSource is null ? null : _ => nonceSource(statement.ContestIndex, 0),
            tamper is null ? null : (_, m) => tamper(statement.ContestIndex, 0, m),
            maxDegreeOfParallelism: 1);

        return new ContestDataPartialDecryption
        {
            GuardianIndex = _index,
            BallotId = statement.BallotId,
            ContestId = statement.ContestId,
            Mi = session.Round1.PartialDecryptions[0],
            CommitmentHash = session.Round1.CommitmentHashes[0],
        };
    }

    /// <summary>
    /// Round 2 of a contest data decryption: given every participant's round-1 message, this
    /// guardian's included unchanged, returns (a_i, b_i), as <see cref="Reveal"/> does for a tally.
    /// </summary>
    public ContestDataCommitmentReveal RevealContestData(IReadOnlyCollection<ContestDataPartialDecryption> commitments)
    {
        var session = Current<ContestDataStatement>("a contest data reveal", "CommitContestData");
        var statement = session.Statements[0];
        Accept(session, () => ReadContestDataCommitments(statement, commitments, session.Participants));

        return new ContestDataCommitmentReveal
        {
            GuardianIndex = _index,
            BallotId = statement.BallotId,
            ContestId = statement.ContestId,
            CommitmentA = session.Round1.CommitmentsA[0],
            CommitmentB = session.Round1.CommitmentsB[0],
        };
    }

    /// <summary>
    /// Round 3 of a contest data decryption: given every participant's round-2 message, checks each
    /// d_j by eq. (99), computes a, b (eq. 100), β = ∏ m_j^{w_j} (eq. 97) and c (eq. 101) itself, and
    /// returns v_i = (u_i - c·w_i·ẑ_i) mod q (eq. 102). As for <see cref="Respond"/>, the decryption
    /// is over whatever happens.
    /// </summary>
    public ContestDataDecryptionResponse RespondContestData(IReadOnlyCollection<ContestDataCommitmentReveal> reveals)
    {
        var session = Current<ContestDataStatement>("a contest data response", "CommitContestData and RevealContestData");
        var statement = session.Statements[0];
        var responses = RespondTo(
            session,
            () => ReadContestDataReveals(statement, reveals, session.Participants),
            _shares.OtherBallotDataEncryptionKeyShare,
            maxDegreeOfParallelism: 1);

        return new ContestDataDecryptionResponse
        {
            GuardianIndex = _index,
            BallotId = statement.BallotId,
            ContestId = statement.ContestId,
            Response = responses[0],
        };
    }

    /// <summary>
    /// §3.6.7 p.52: this guardian's partial decryption of a challenged ballot's encrypted nonce,
    /// m_i = C_ξB,0^{ẑ_i} mod p (eq. 107), with its ballot data encryption key share ẑ_i. First it
    /// requires the ballot to be recorded as challenged, not to be a pre-encrypted ballot's record
    /// (always a cast ballot's, §4.3.1), and to be well formed and keyed with
    /// H_I = H(H_E; 0x20, id_B) (an <see cref="ArgumentException"/> otherwise: decrypting a cast
    /// ballot's nonce would reveal its votes); then that C_ξB,0 is in Z_p^r (a library hardening the
    /// spec does not state; see S6) and that the Schnorr proof C_ξB,2 holds (eq. 38), and "only if"
    /// both do it computes m_i (a <see cref="TallyDecryptionException"/> naming no guardian
    /// otherwise). It is a single message: §3.6.7 defines no proof of correct decryption here, and
    /// m_i does not depend on who else takes part. It does not touch a tally or contest data
    /// decryption in progress.
    ///
    /// Trust boundary (the spec is silent): the status, like everything else checked here, is read
    /// from the ballot object the caller hands in, and <see cref="EncryptedBallot.Status"/> can be
    /// set by an initializer. A copy of a cast ballot (same id_B, H_I, contests, confirmation code
    /// and C_ξB) under a new string <see cref="EncryptedBallot.Id"/> and marked challenged passes
    /// every check, including the eq. (38) proof, which binds H_I and not the string id; k such m_i
    /// give ξ_B and with it every vote of the cast ballot, and Verification 5.A (unique id_B) only
    /// notices afterwards. In-process the caller is the holder of the record. A guardian in a
    /// distributed deployment must refuse when the published record holds any cast ballot with the
    /// same id_B (or H_I, or C_ξB,0); matching by <see cref="EncryptedBallot.Id"/> is not enough.
    /// In an election with pre-encrypted ballots the same values reach the guardians through the
    /// pre-encrypted overload too, which has no status to check (S9 open question S9-6).
    /// </summary>
    public BallotNoncePartialDecryption DecryptBallotNonce(EncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        var statement = ChallengedBallotStatement.For(encryptionRecord, ballot);
        statement.RequireDecryptable($"guardian {_index.Index}");

        // ẑ_i is secret and a full-width element of Z_q: the constant-time path.
        var partialDecryption = MontgomeryModP.PowModP(statement.Nonce.C0, _shares.OtherBallotDataEncryptionKeyShare);
        if (PartialDecryptionTamperForTesting is { } tamper)
        {
            partialDecryption = tamper(0, 0, partialDecryption);
        }

        return new BallotNoncePartialDecryption
        {
            GuardianIndex = _index,
            BallotId = ballot.Id,
            Mi = partialDecryption,
        };
    }

    /// <summary>
    /// This guardian's share m_i = C_ξB,0^{ẑ_i} mod p (eq. 107) of a pre-encrypted ballot's
    /// encrypted nonce, which the recording tool needs whether the ballot is cast or not (§4.3.1;
    /// see <see cref="TallyAdmin.DecryptPreEncryptedBallotNonce"/>). Requires the manifest to name a
    /// hash-trimming function and the ballot to be well formed and keyed with H_I = H(H_E; 0x20, id_B)
    /// (<see cref="ArgumentException"/> otherwise), and C_ξB,0 in Z_p^r and the Schnorr proof C_ξB,2
    /// to hold (eq. 38; <see cref="TallyDecryptionException"/> naming no guardian otherwise), exactly
    /// as for a challenged ballot.
    ///
    /// Trust boundary (S9 open question S9-6; see <c>PreEncryptedBallotNonceStatement</c>): these
    /// checks read only id_B, H_I and C_ξB, which every published ballot carries, regular ballots
    /// included, under the same construction (§4.2 "as shown in Section 3.3.4"). In an election with
    /// pre-encrypted ballots, a request built around any published ballot's values passes them, and k
    /// shares give that ballot's ξ_B and its votes, bypassing the challenged-only gate of
    /// <see cref="DecryptBallotNonce(EncryptedBallot, EncryptionRecord)"/>. A guardian in a distributed
    /// deployment must refuse a request whose id_B (or H_I, or C_ξB,0) matches any published ballot.
    /// </summary>
    public BallotNoncePartialDecryption DecryptBallotNonce(PreEncryption.PreEncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        var statement = PreEncryptedBallotNonceStatement.For(encryptionRecord, ballot);
        statement.RequireDecryptable($"guardian {_index.Index}");

        // ẑ_i is secret and a full-width element of Z_q: the constant-time path.
        var partialDecryption = MontgomeryModP.PowModP(statement.Nonce.C0, _shares.OtherBallotDataEncryptionKeyShare);
        if (PartialDecryptionTamperForTesting is { } tamper)
        {
            partialDecryption = tamper(0, 0, partialDecryption);
        }

        return new BallotNoncePartialDecryption
        {
            GuardianIndex = _index,
            BallotId = ballot.Id,
            Mi = partialDecryption,
        };
    }

    internal static VerifiableDecryption.ReceivedCommitment[] ReadContestDataCommitments(ContestDataStatement statement, IEnumerable<ContestDataPartialDecryption> messages, GuardianIndex[] participants)
    {
        const string round = "contest data round-1 (m_i, d_i)";
        return statement.Read(messages, x => x.GuardianIndex, x => (x.BallotId, x.ContestId), participants, round)
            .Select(x => x.CommitmentHash is null
                ? throw new TallyDecryptionException(x.GuardianIndex, $"Guardian {x.GuardianIndex.Index}'s {round} message has no commitment hash.")
                : new VerifiableDecryption.ReceivedCommitment { PartialDecryptions = [x.Mi], CommitmentHashes = [x.CommitmentHash] })
            .ToArray();
    }

    internal static VerifiableDecryption.ReceivedReveal[] ReadContestDataReveals(ContestDataStatement statement, IEnumerable<ContestDataCommitmentReveal> messages, GuardianIndex[] participants)
    {
        return statement.Read(messages, x => x.GuardianIndex, x => (x.BallotId, x.ContestId), participants, "contest data round-2 (a_i, b_i)")
            .Select(x => new VerifiableDecryption.ReceivedReveal { CommitmentsA = [x.CommitmentA], CommitmentsB = [x.CommitmentB] })
            .ToArray();
    }

    internal static IntegerModQ[][] ReadContestDataResponses(ContestDataStatement statement, IEnumerable<ContestDataDecryptionResponse> messages, GuardianIndex[] participants)
    {
        return statement.Read(messages, x => x.GuardianIndex, x => (x.BallotId, x.ContestId), participants, "contest data round-3 (v_i)")
            .Select(x => new[] { x.Response })
            .ToArray();
    }

    /// <summary>U, in ascending order, required to be a quorum that includes this guardian.</summary>
    private GuardianIndex[] RequireParticipant(IReadOnlyCollection<GuardianIndex> participants)
    {
        var sorted = TallyDecryptionHashes.RequireQuorum(participants);
        if (!sorted.Contains(_index))
        {
            throw new ArgumentException($"Guardian {_index.Index} is not among the participants, so it cannot take part in this decryption.", nameof(participants));
        }

        return sorted;
    }

    private Session<T> Begin<T>(
        T[] statements,
        GuardianIndex[] participants,
        IntegerModQ secretShare,
        Func<int, IntegerModQ?>? nonceSource,
        Func<int, IntegerModP, IntegerModP>? tamper,
        int maxDegreeOfParallelism)
        where T : IDecryptionStatement
    {
        var round1 = VerifiableDecryption.Commit(statements, secretShare, _index, participants, nonceSource, tamper,
            new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism });
        var session = new Session<T>
        {
            Participants = participants,
            Statements = statements,
            Round1 = round1,
        };
        _session = session;
        return session;
    }

    /// <summary>The decryption in progress, if it is of the kind <typeparamref name="T"/>.</summary>
    private Session<T> Current<T>(string step, string before)
        where T : IDecryptionStatement
    {
        return _session as Session<T>
            ?? throw new InvalidOperationException($"Guardian {_index.Index} has no {(typeof(T) == typeof(TallyOption) ? "tally " : "contest data ")}decryption awaiting {step}: call {before} first, and respond only once.");
    }

    /// <summary>
    /// Round 2's check: every participant's round-1 message, read by <paramref name="read"/>, this
    /// guardian's own among them unchanged. Any failure ends the decryption.
    /// </summary>
    private void Accept<T>(Session<T> session, Func<VerifiableDecryption.ReceivedCommitment[]> read)
        where T : IDecryptionStatement
    {
        if (session.Commitments is not null)
        {
            throw new InvalidOperationException($"Guardian {_index.Index} has already revealed its commitments for this decryption.");
        }

        try
        {
            var received = read();
            var own = received[Array.IndexOf(session.Participants, _index)];
            for (int o = 0; o < session.Statements.Length; o++)
            {
                if (own.PartialDecryptions[o] != session.Round1.PartialDecryptions[o] || !own.CommitmentHashes[o].AsSpan().SequenceEqual(session.Round1.CommitmentHashes[o]))
                {
                    throw new TallyDecryptionException(null, $"Guardian {_index.Index}'s own round-1 message came back altered for {session.Statements[o].Description}.");
                }
            }

            session.Commitments = received;
        }
        catch (TallyDecryptionException)
        {
            _session = null;
            throw;
        }
    }

    /// <summary>
    /// Round 3: ends the decryption, then checks this guardian's own reveal came back unchanged,
    /// checks every d_j and combines (<see cref="VerifiableDecryption.CheckAndCombine"/>), and
    /// responds.
    /// </summary>
    private IntegerModQ[] RespondTo<T>(Session<T> session, Func<VerifiableDecryption.ReceivedReveal[]> read, IntegerModQ secretShare, int maxDegreeOfParallelism)
        where T : IDecryptionStatement
    {
        var commitments = session.Commitments ?? throw new InvalidOperationException($"Guardian {_index.Index} has not revealed its commitments for this decryption: call the reveal step first.");

        // Whatever happens below, this decryption is finished: u_i is never used twice.
        _session = null;

        var revealed = read();
        int self = Array.IndexOf(session.Participants, _index);
        for (int o = 0; o < session.Statements.Length; o++)
        {
            if (revealed[self].CommitmentsA[o] != session.Round1.CommitmentsA[o] || revealed[self].CommitmentsB[o] != session.Round1.CommitmentsB[o])
            {
                throw new TallyDecryptionException(null, $"Guardian {_index.Index}'s own round-2 message came back altered for {session.Statements[o].Description}.");
            }
        }

        var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
        var proof = VerifiableDecryption.CheckAndCombine(session.Participants, session.Statements, commitments, revealed, options);
        return VerifiableDecryption.Respond(proof, self, session.Round1.Nonces, secretShare);
    }

    private sealed class Session<T>
        where T : IDecryptionStatement
    {
        public required GuardianIndex[] Participants { get; init; }
        public required T[] Statements { get; init; }
        public required VerifiableDecryption.GuardianCommitment Round1 { get; init; }

        /// <summary>Every participant's round-1 message, in <see cref="Participants"/> order; set by the reveal step.</summary>
        public VerifiableDecryption.ReceivedCommitment[]? Commitments { get; set; }
    }
}

/// <summary>
/// The administrator's side of verifiable decryption (§3.6.4-§3.6.7): mediating the guardians'
/// messages, combining them into M, T and the proof (c, v) and recovering each count t for a tally,
/// into β, the proof (c, v) and the data D for a contest data field, or, for a challenged ballot,
/// into ξ_B and from it the released encryption nonces, selections and contest data.
/// </summary>
public class TallyAdmin
{
    /// <summary>
    /// Test seam: when false, <see cref="Combine"/> and <see cref="CombineContestData"/> publish
    /// without first checking the combined proof, as a careless administrator would, so tests can
    /// show that Verifications 10 and 12 catch what the check would have. True outside tests.
    /// </summary>
    internal bool VerifyBeforePublishing { get; init; } = true;

    /// <summary>
    /// Drives <paramref name="guardians"/> (U, at least k of them) through the three rounds of
    /// <see cref="TallyGuardian"/> and combines the result with <see cref="Combine"/>. The guardians
    /// run one after another, each round's per-option work on up to
    /// <paramref name="maxDegreeOfParallelism"/> threads (-1, the default, for no limit), so 1
    /// keeps the whole decryption on one thread.
    /// </summary>
    public DecryptedTally Decrypt(IReadOnlyList<TallyGuardian> guardians, EncryptedTally encryptedTally, EncryptionRecord encryptionRecord, int maxDegreeOfParallelism = -1)
    {
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.Commit(encryptedTally, encryptionRecord, participants, maxDegreeOfParallelism)).ToList();
        var reveals = guardians.Select(x => x.Reveal(commitments)).ToList();
        var responses = guardians.Select(x => x.Respond(reveals, maxDegreeOfParallelism)).ToList();

        return Combine(encryptedTally, encryptionRecord, commitments, reveals, responses, maxDegreeOfParallelism);
    }

    /// <summary>
    /// Combines the three rounds' messages from the participating guardians into the decrypted
    /// tally (§3.6.2-§3.6.5), on up to <paramref name="maxDegreeOfParallelism"/> threads:
    /// <list type="number">
    /// <item>The round-1 senders must be a quorum, and every one of them must have sent exactly one
    /// well-formed message in rounds 1 and 2.</item>
    /// <item>No M_j may be 0, and each d_j is checked against what guardian j revealed (eq. 88).</item>
    /// <item>Only then is round 3 read: exactly one well-formed response per participant.</item>
    /// <item>M = ∏ M_j^{w_j} (eq. 86), a and b (eq. 89), c (eq. 90), v = Σ v_j (eq. 93) and
    /// T = B·M^-1 (eq. 82).</item>
    /// <item>Before anything is published, the proof is checked as Verification 10 will check it:
    /// g^v·K^c = a and A^v·M^c = b. If it fails, the per-guardian checks of Note 3.7 (eqs. 94, 95)
    /// find whose share is wrong.</item>
    /// <item>Each count t is recovered from T = K^t by a search over
    /// [0, the largest <see cref="EncryptedTally.EncryptedAggregateChoice.MaximumCount"/>].</item>
    /// </list>
    /// Any failure throws <see cref="TallyDecryptionException"/>, naming the guardian at fault when
    /// it can be identified.
    /// </summary>
    public DecryptedTally Combine(
        EncryptedTally encryptedTally,
        EncryptionRecord encryptionRecord,
        IReadOnlyCollection<PartialTallyDecryption> commitments,
        IReadOnlyCollection<TallyDecryptionCommitmentReveal> reveals,
        IReadOnlyCollection<TallyDecryptionResponse> responses,
        int maxDegreeOfParallelism = -1)
    {
        // Distinct senders: a guardian that sent two round-1 messages is named by ReadCommitments.
        var participants = TallyDecryptionHashes.RequireQuorum(commitments.Select(x => x.GuardianIndex).Distinct());
        var options = TallyOption.ForTally(encryptionRecord, encryptedTally);
        var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };

        // The rounds are checked in protocol order: a guardian whose d_j does not hold is named even
        // if, having halted, the others sent no round-3 message.
        var received = TallyDecryptionMessages.ReadCommitments(commitments, participants, options);
        var revealed = TallyDecryptionMessages.ReadReveals(reveals, participants, options);

        // A zero M_j has no inverse and makes M zero; only a corrupt share can be zero.
        if (VerifiableDecryption.FindZeroPartialDecryption(received) is { } zero)
        {
            var guardian = participants[zero.Participant];
            throw new TallyDecryptionException(guardian, $"Tally did not decrypt successfully: guardian {guardian.Index}'s partial decryption for contest {options[zero.Statement].ContestId}, option {options[zero.Statement].ChoiceId} is 0.");
        }

        var proof = VerifiableDecryption.CheckAndCombine(participants, options, received, revealed, parallelOptions);
        var responded = TallyDecryptionMessages.ReadResponses(responses, participants, options);
        var responseSums = VerifiableDecryption.SumResponses(responded, options.Length);

        // T = B / M. The combined partial decryptions are published, so the variable-time batch
        // inversion is safe here.
        var inverses = InvertAll(proof.CombinedDecryptions);
        var decryptedValues = new IntegerModP[options.Length];
        for (int o = 0; o < options.Length; o++)
        {
            decryptedValues[o] = options[o].B * inverses[o];
        }

        var voteEncryptionKey = encryptionRecord.ElectionPublicKeys.VoteEncryptionKey;
        if (VerifyBeforePublishing)
        {
            var failing = new bool[options.Length];
            Parallel.For(0, options.Length, parallelOptions, o =>
            {
                failing[o] = !VerifiableDecryption.ProofHolds(options[o].A, proof.CombinedDecryptions[o], voteEncryptionKey,
                    proof.CommitmentA[o], proof.CommitmentB[o], proof.Challenges[o], responseSums[o]);
            });

            if (failing.Any(x => x))
            {
                var culprit = VerifiableDecryption.IdentifyInvalidShare(participants, options, failing, proof, received, revealed, responded,
                    j => VerifiableDecryption.PublicKeyShare(encryptionRecord.Guardians.Select(x => x.VoteEncryptionCommitments), j));
                var first = options[Array.IndexOf(failing, true)];
                throw new TallyDecryptionException(culprit,
                    culprit is null
                        ? $"Tally did not decrypt successfully: the combined proof of correct decryption does not verify for contest {first.ContestId}, option {first.ChoiceId}, and Note 3.7's per-guardian checks find no single guardian at fault."
                        : $"Tally did not decrypt successfully: guardian {culprit.Index}'s share of the proof of correct decryption does not verify (Note 3.7, eqs. 94-95); the combined proof fails for contest {first.ContestId}, option {first.ChoiceId}.");
            }
        }

        // One table for every choice: K is the same base throughout, and every count lies in
        // [0, the largest choice's MaximumCount]: the sum over cast ballots of W·min(R, L) (G16).
        // The count is published once decrypted, so the variable-time search gives nothing away.
        long bound = options.Length == 0 ? 0 : options.Max(x => x.MaximumCount);
        if (bound > int.MaxValue)
        {
            throw new TallyDecryptionException(null, $"Tally did not decrypt successfully: a count may be as large as {bound}, beyond the discrete-log search this library performs.");
        }

        var counts = new int[options.Length];
        int failures = 0;
        if (options.Length > 0)
        {
            var discreteLog = new BoundedDiscreteLog(voteEncryptionKey, (int)bound, options.Length);
            Parallel.For(0, options.Length, parallelOptions, o =>
            {
                if (!discreteLog.TryFind(decryptedValues[o], out counts[o]))
                {
                    Interlocked.Increment(ref failures);
                }
            });
        }

        // Thrown here rather than inside the loop, where Parallel.For would wrap it in an
        // AggregateException.
        if (failures > 0)
        {
            throw new TallyDecryptionException(null, $"Tally did not decrypt successfully: {failures} count(s) are not in [0, {bound}].");
        }

        var decryptedTally = new DecryptedTally
        {
            Contests = new Dictionary<string, DecryptedContest>(),
        };

        for (int o = 0; o < options.Length; o++)
        {
            var option = options[o];
            if (!decryptedTally.Contests.TryGetValue(option.ContestId, out var decryptedContest))
            {
                decryptedContest = new DecryptedContest
                {
                    ContestIndex = option.ContestIndex,
                    Choices = new Dictionary<string, DecryptedChoice>(),
                };
                decryptedTally.Contests[option.ContestId] = decryptedContest;
            }

            decryptedContest.Choices[option.ChoiceId] = new DecryptedChoice
            {
                ChoiceIndex = option.ChoiceIndex,
                VoteCount = counts[o],
                T = decryptedValues[o],
                Challenge = proof.Challenges[o],
                Response = responseSums[o],
            };
        }

        return decryptedTally;
    }

    /// <summary>
    /// Drives <paramref name="guardians"/> (U, at least k of them) through the three rounds of a
    /// contest data decryption (§3.6.6) of contest <paramref name="contestId"/> on
    /// <paramref name="ballot"/>, and combines the result with <see cref="CombineContestData"/>.
    /// </summary>
    public DecryptedContestData DecryptContestData(IReadOnlyList<TallyGuardian> guardians, EncryptedBallot ballot, string contestId, EncryptionRecord encryptionRecord)
    {
        var participants = guardians.Select(x => x.Index).ToList();
        var commitments = guardians.Select(x => x.CommitContestData(ballot, contestId, encryptionRecord, participants)).ToList();
        var reveals = guardians.Select(x => x.RevealContestData(commitments)).ToList();
        var responses = guardians.Select(x => x.RespondContestData(reveals)).ToList();

        return CombineContestData(ballot, contestId, encryptionRecord, commitments, reveals, responses);
    }

    /// <summary>
    /// Combines the three rounds' messages of a contest data decryption (§3.6.6) into the published
    /// β, proof (c, v) and data D, in the order <see cref="Combine"/> follows:
    /// <list type="number">
    /// <item>C_0 must be in Z_p^r and the field's Schnorr proof C_2 (eq. 69) must hold, as the
    /// guardians required; otherwise the ballot is at fault and no guardian is named.</item>
    /// <item>The round-1 senders must be a quorum, each with exactly one message per round, all for
    /// this ballot contest; no m_j may be 0; each d_j is checked (eq. 99).</item>
    /// <item>β = ∏ m_j^{w_j} (eq. 97), a and b (eq. 100), c (eq. 101) and v = Σ v_j (eq. 103).</item>
    /// <item>Before anything is published, the proof is checked as Verification 12 will check it:
    /// g^v·K-hat^c = a and C_0^v·β^c = b; if it fails, Note 3.7's per-guardian checks, with the
    /// guardians' K-hat commitments, find whose share is wrong.</item>
    /// <item>h = H(H_I; 0x26, ind_c, C_0, β), the keys k_1..k_{b_Λ} (eq. 104) and D = C_1 ⊕ k
    /// (eqs. 105, 106).</item>
    /// </list>
    /// Any failure throws <see cref="TallyDecryptionException"/>, naming the guardian at fault when
    /// it can be identified.
    /// </summary>
    public DecryptedContestData CombineContestData(
        EncryptedBallot ballot,
        string contestId,
        EncryptionRecord encryptionRecord,
        IReadOnlyCollection<ContestDataPartialDecryption> commitments,
        IReadOnlyCollection<ContestDataCommitmentReveal> reveals,
        IReadOnlyCollection<ContestDataDecryptionResponse> responses)
    {
        var statement = ContestDataStatement.For(encryptionRecord, ballot, contestId);
        statement.RequireDecryptable("the administrator");

        var participants = TallyDecryptionHashes.RequireQuorum(commitments.Select(x => x.GuardianIndex).Distinct());
        ContestDataStatement[] statements = [statement];
        var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = 1 };

        var received = TallyGuardian.ReadContestDataCommitments(statement, commitments, participants);
        var revealed = TallyGuardian.ReadContestDataReveals(statement, reveals, participants);
        if (VerifiableDecryption.FindZeroPartialDecryption(received) is { } zero)
        {
            var guardian = participants[zero.Participant];
            throw new TallyDecryptionException(guardian, $"Contest data did not decrypt successfully: guardian {guardian.Index}'s partial decryption m_i of {statement.Description} is 0.");
        }

        var proof = VerifiableDecryption.CheckAndCombine(participants, statements, received, revealed, parallelOptions);
        var responded = TallyGuardian.ReadContestDataResponses(statement, responses, participants);
        var response = VerifiableDecryption.SumResponses(responded, 1)[0];
        var beta = proof.CombinedDecryptions[0];

        if (VerifyBeforePublishing)
        {
            var ballotDataKey = encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey;
            if (!VerifiableDecryption.ProofHolds(statement.Base, beta, ballotDataKey, proof.CommitmentA[0], proof.CommitmentB[0], proof.Challenges[0], response))
            {
                var culprit = VerifiableDecryption.IdentifyInvalidShare(participants, statements, [true], proof, received, revealed, responded,
                    j => VerifiableDecryption.PublicKeyShare(encryptionRecord.Guardians.Select(x => x.OtherBallotDataEncryptionCommitments), j));
                throw new TallyDecryptionException(culprit,
                    culprit is null
                        ? $"Contest data did not decrypt successfully: the combined proof of correct decryption of {statement.Description} does not verify, and Note 3.7's per-guardian checks find no single guardian at fault."
                        : $"Contest data did not decrypt successfully: guardian {culprit.Index}'s share of the proof of correct decryption does not verify (Note 3.7, eqs. 94-95 with C_0, m_i and K-hat); the combined proof of {statement.Description} fails.");
            }
        }

        return new DecryptedContestData
        {
            BallotId = statement.BallotId,
            ContestId = statement.ContestId,
            ContestIndex = statement.ContestIndex,
            Beta = beta,
            Challenge = proof.Challenges[0],
            Response = response,
            Data = ContestDataEncryption.Decrypt(statement.SelectionEncryptionIdentifierHash, statement.ContestIndex, statement.Blocks, statement.Data, beta),
        };
    }

    /// <summary>
    /// Has each of <paramref name="guardians"/> (U, at least k of them) partially decrypt the
    /// encrypted nonce of the challenged <paramref name="ballot"/> (§3.6.7, eq. 107) and combines the
    /// results with <see cref="CombineChallengedBallot"/>.
    /// </summary>
    public DecryptedChallengedBallot DecryptChallengedBallot(IReadOnlyList<TallyGuardian> guardians, EncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        var partialDecryptions = guardians.Select(x => x.DecryptBallotNonce(ballot, encryptionRecord)).ToList();
        return CombineChallengedBallot(ballot, encryptionRecord, partialDecryptions);
    }

    /// <summary>
    /// §3.6.7: opens the challenged <paramref name="ballot"/> from the guardians' partial
    /// decryptions of its encrypted nonce, and returns what is published: every field's σ and
    /// ξ_{i,j}, and every contest data field's ξ and D. In order:
    /// <list type="number">
    /// <item>The ballot must be recorded as challenged, not be a pre-encrypted ballot's record, and be
    /// well formed and keyed with
    /// H_I = H(H_E; 0x20, id_B) (<see cref="ArgumentException"/>), and C_ξB,0 must be in Z_p^r and
    /// the Schnorr proof C_ξB,2 must hold (eq. 38), as the guardians required; otherwise the ballot is
    /// at fault and no guardian is named.</item>
    /// <item>The senders must be a quorum, each with exactly one message, for this ballot; no m_j may
    /// be 0.</item>
    /// <item>β_B = ∏ m_j^{w_j} (eq. 108), h = H(H_I; 0x22, C_ξB,0, β_B) (eq. 35), k_1 (eq. 36) and
    /// ξ_B = C_ξB,1 ⊕ k_1. ξ_B is not returned (§3.6.7: it "should not be published").</item>
    /// <item>For every verifiable field (options and supplemental fields), ξ_{i,j} (eq. 33); the
    /// field's α must be g^ξ_{i,j}, and σ is the value in [0, the field's range bound] with
    /// β = K^{σ + ξ_{i,j}} (eq. 109, the small discrete logarithm).</item>
    /// <item>For every contest data field, ξ (eq. 64); C_0 must be g^ξ, and D follows from
    /// β = K-hat^ξ (eq. 110), h (eq. 65) and the keys of eq. (66) (eq. 111).</item>
    /// </list>
    /// A nonce that does not reproduce the ballot's ciphertexts throws
    /// <see cref="TallyDecryptionException"/> naming no guardian: either a guardian sent a wrong m_i
    /// or the device encrypted a wrong ξ_B (p.53), and with no proof of correct decryption defined
    /// for m_i (§3.6.7) the two cannot be told apart. Nothing is published unless every released
    /// value reproduces the ballot, so Verification 13 accepts what this returns.
    /// </summary>
    public DecryptedChallengedBallot CombineChallengedBallot(
        EncryptedBallot ballot,
        EncryptionRecord encryptionRecord,
        IReadOnlyCollection<BallotNoncePartialDecryption> partialDecryptions)
    {
        var statement = ChallengedBallotStatement.For(encryptionRecord, ballot);
        statement.RequireDecryptable("the administrator");

        var ballotNonce = CombineBallotNonce(ballot.Id, "Challenged ballot", statement.SelectionEncryptionIdentifierHash, statement.Nonce, partialDecryptions);
        try
        {
            return Open(statement, encryptionRecord, ballotNonce);
        }
        finally
        {
            Array.Clear(ballotNonce.ToByteArray());
        }
    }

    /// <summary>
    /// Has each of <paramref name="guardians"/> (at least k of them) partially decrypt the
    /// encrypted nonce of the pre-encrypted <paramref name="ballot"/> and combines the results with
    /// <see cref="CombinePreEncryptedBallotNonce"/>.
    /// </summary>
    public BallotNonce DecryptPreEncryptedBallotNonce(IReadOnlyList<TallyGuardian> guardians, PreEncryption.PreEncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        var partialDecryptions = guardians.Select(x => x.DecryptBallotNonce(ballot, encryptionRecord)).ToList();
        return CombinePreEncryptedBallotNonce(ballot, encryptionRecord, partialDecryptions);
    }

    /// <summary>
    /// §4.3.1 and §3.6.7: the ballot nonce ξ_B of the pre-encrypted <paramref name="ballot"/>, from
    /// the guardians' partial decryptions of its encrypted nonce (eq. 108, then eqs. 35-37), for the
    /// recording tool (<see cref="PreEncryption.BallotRecordingTool"/>), which needs it for a cast
    /// ballot as for an uncast one. The ballot is checked as the guardians checked it, the messages
    /// as <see cref="CombineChallengedBallot"/> checks them, and ξ_B is returned only if it
    /// regenerates the ballot exactly (every encryption by eq. 121, every selection and contest hash,
    /// the confirmation code); otherwise a <see cref="TallyDecryptionException"/> naming no guardian:
    /// a wrong m_i and a device that encrypted a wrong ξ_B cannot be told apart (§3.6.7 defines no
    /// proof for m_i).
    ///
    /// ξ_B is secret for a cast ballot: with it, the published selected vectors name the options
    /// chosen. The caller holds the recording tool's position (§4.3). The regeneration check protects
    /// what this method returns, not the shares: whoever collects k shares can combine them without
    /// it, so the guardians' refusal is what keeps a request built around another published ballot's
    /// id_B, H_I and C_ξB from yielding its ξ_B (S9 open question S9-6; see
    /// <see cref="TallyGuardian.DecryptBallotNonce(PreEncryption.PreEncryptedBallot, EncryptionRecord)"/>).
    /// </summary>
    public BallotNonce CombinePreEncryptedBallotNonce(
        PreEncryption.PreEncryptedBallot ballot,
        EncryptionRecord encryptionRecord,
        IReadOnlyCollection<BallotNoncePartialDecryption> partialDecryptions)
    {
        var statement = PreEncryptedBallotNonceStatement.For(encryptionRecord, ballot);
        statement.RequireDecryptable("the administrator");

        var ballotNonce = CombineBallotNonce(ballot.Id, "Pre-encrypted ballot", statement.SelectionEncryptionIdentifierHash, statement.Nonce, partialDecryptions);
        try
        {
            new PreEncryption.BallotRecordingTool(encryptionRecord).RecordUncast(ballot, ballotNonce);
        }
        catch (ArgumentException exception)
        {
            Array.Clear(ballotNonce.ToByteArray());
            throw new TallyDecryptionException(null, $"Pre-encrypted ballot {ballot.Id}'s nonce did not decrypt to a ξ_B that regenerates the ballot: either a guardian sent a wrong m_i or the device encrypted a wrong ξ_B (§3.6.7 defines no proof that tells them apart). {exception.Message}");
        }

        return ballotNonce;
    }

    /// <summary>
    /// The quorum, message and zero checks on the guardians' shares m_i of a ballot's encrypted nonce,
    /// then β_B = ∏ m_j^{w_j} (eq. 108) and ξ_B = C_ξB,1 ⊕ k_1 (eqs. 35-37).
    /// </summary>
    private static BallotNonce CombineBallotNonce(
        string ballotId,
        string kind,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        EncryptedBallotNonce nonce,
        IReadOnlyCollection<BallotNoncePartialDecryption> partialDecryptions)
    {
        // Distinct senders: a guardian that sent two messages is named by InParticipantOrder.
        var participants = TallyDecryptionHashes.RequireQuorum(partialDecryptions.Select(x => x.GuardianIndex).Distinct());
        var received = VerifiableDecryption.InParticipantOrder(partialDecryptions, x => x.GuardianIndex, participants, "ballot nonce (m_i)");
        foreach (var message in received)
        {
            if (message.BallotId != ballotId)
            {
                throw new TallyDecryptionException(message.GuardianIndex, $"Guardian {message.GuardianIndex.Index}'s ballot nonce message is for ballot {message.BallotId}, not for ballot {ballotId}.");
            }

            // A zero m_j has no inverse and makes β_B zero; only a corrupt share can be zero once
            // C_ξB,0 is known to be in Z_p^r.
            if (message.Mi == 0)
            {
                throw new TallyDecryptionException(message.GuardianIndex, $"{kind} {ballotId} did not decrypt: guardian {message.GuardianIndex.Index}'s partial decryption m_i of its nonce is 0.");
            }
        }

        // β_B = ∏ m_j^{w_j} (eq. 108). β_B yields ξ_B, which is secret: the constant-time path.
        IntegerModP betaB = 1;
        foreach (var message in received)
        {
            betaB *= MontgomeryModP.PowModP(message.Mi, TallyDecryptionHashes.LagrangeCoefficient(message.GuardianIndex, participants));
        }

        return BallotNonceEncryption.Decrypt(selectionEncryptionIdentifierHash, nonce, betaB);
    }

    /// <summary>Steps 4 and 5 of <see cref="CombineChallengedBallot"/>, from the decrypted ξ_B.</summary>
    private static DecryptedChallengedBallot Open(ChallengedBallotStatement statement, EncryptionRecord encryptionRecord, BallotNonce ballotNonce)
    {
        var ballot = statement.Ballot;
        var selectionHash = statement.SelectionEncryptionIdentifierHash;
        var voteEncryptionKey = encryptionRecord.ElectionPublicKeys.VoteEncryptionKey;
        var contests = new List<DecryptedChallengedContest>(ballot.Contests.Count);
        foreach (var contest in ballot.Contests)
        {
            // BallotStructure has required exactly the manifest's options and declared fields, each
            // once, and the contest data field exactly where it is declared.
            var manifestContest = encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);

            var choices = manifestContest.Choices
                .Select(option => OpenField(option, manifestContest.RangeBound(option), contest.Choices.Single(x => x.ChoiceId == option.Id)))
                .ToList();
            var fields = manifestContest.SupplementalFields
                .Select(field => OpenField(field, manifestContest.RangeBound(field), contest.SupplementalFields.Single(x => x.FieldId == field.Id)))
                .ToList();

            DecryptedChallengedContestData? contestData = null;
            if (contest.ContestData is { } encryptedData)
            {
                // Eq. (64); then (110), (65), (66) and (111). ξ is about to be published.
                var xi = ContestDataEncryption.Nonce(selectionHash, manifestContest.Index, ballotNonce);
                var alpha = MontgomeryModP.PowModP(EGParameters.G, xi);
                if (alpha != encryptedData.C0)
                {
                    throw Inconsistent($"contest {contest.Id}'s contest data nonce ξ (eq. 64) does not reproduce C_0 = g^ξ");
                }

                var beta = MontgomeryModP.PowModP(encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey, xi);
                var secretKey = ContestDataEncryption.SecretKey(selectionHash, manifestContest.Index, alpha, beta);
                contestData = new DecryptedChallengedContestData
                {
                    EncryptionNonce = xi,
                    Data = ContestDataEncryption.Apply(secretKey, manifestContest.Index, manifestContest.ContestDataBlocks, encryptedData.C1),
                };
            }

            contests.Add(new DecryptedChallengedContest
            {
                ContestId = contest.Id,
                Choices = choices,
                SupplementalFields = fields,
                ContestData = contestData,
            });

            DecryptedChallengedField OpenField(Choice field, int bound, EncryptedValueWithProofs encrypted)
            {
                // Eq. (33), then (109). ξ_{i,j} and σ are about to be published.
                IntegerModQ xi = new EncryptionNonce(selectionHash, ballotNonce, manifestContest.Index, field.Index);
                if (MontgomeryModP.PowModP(EGParameters.G, xi) != encrypted.Alpha)
                {
                    throw Inconsistent($"contest {contest.Id}, field {field.Id}'s nonce ξ_{{i,j}} (eq. 33) does not reproduce α = g^ξ");
                }

                // K^ξ·K^σ = β for the one σ in [0, bound]: a few multiplications by K.
                var candidate = MontgomeryModP.PowModP(voteEncryptionKey, xi);
                for (int sigma = 0; sigma <= bound; sigma++)
                {
                    if (candidate == encrypted.Beta)
                    {
                        return new DecryptedChallengedField { Id = field.Id, Value = sigma, EncryptionNonce = xi };
                    }

                    candidate *= voteEncryptionKey;
                }

                throw Inconsistent($"contest {contest.Id}, field {field.Id}'s β is not K^(σ + ξ) for any σ in [0, {bound}] (eq. 109)");
            }
        }

        return new DecryptedChallengedBallot
        {
            BallotId = ballot.Id,
            Contests = contests,
        };

        TallyDecryptionException Inconsistent(string what) => new(null,
            $"Challenged ballot {ballot.Id} did not decrypt consistently: {what}. Either a guardian's partial decryption m_i of the ballot nonce is wrong or the ballot's C_ξB does not encrypt the nonce its selections were encrypted with (§3.6.7 p.53); §3.6.7 defines no proof of correct decryption for m_i, so no guardian can be named. Nothing is published.");
    }

    /// <summary>
    /// The inverse of every value, all nonzero, for the price of one inversion and three
    /// multiplications per value (Montgomery's trick): invert the product of them all, then peel
    /// each value's inverse off it from the back. A Euclidean inversion of a 4096-bit residue costs
    /// about as much as 25 multiplications and allocates a BigInteger per division step, so inverting
    /// each choice separately allocated more than the rest of decryption put together.
    ///
    /// The values are combined partial decryptions or published decrypted values, so the
    /// variable-time inversion is safe here; never pass a secret.
    /// </summary>
    internal static IntegerModP[] InvertAll(IntegerModP[] values)
    {
        var inverses = new IntegerModP[values.Length];
        if (values.Length == 0)
        {
            return inverses;
        }

        // prefix[i] = values[0] * ... * values[i].
        var prefix = new IntegerModP[values.Length];
        prefix[0] = values[0];
        for (int i = 1; i < values.Length; i++)
        {
            prefix[i] = prefix[i - 1] * values[i];
        }

        // Invariant at the top of each iteration: remaining = (values[0] * ... * values[i])^-1.
        var remaining = new IntegerModP(prefix[^1].ToBigInteger().ModInverseVariableTime(EGParameters.P));
        for (int i = values.Length - 1; i > 0; i--)
        {
            inverses[i] = remaining * prefix[i - 1];
            remaining *= values[i];
        }

        inverses[0] = remaining;
        return inverses;
    }
}

/// <summary>
/// One option of one contest, in manifest order, with its manifest indices and a snapshot of its
/// encrypted aggregate (A, B): the statement of one tally decryption (§3.6.5), whose hashes are
/// eqs. (88) and (90) keyed with H_E.
/// </summary>
internal sealed record TallyOption(string ContestId, string ChoiceId, int ContestIndex, int ChoiceIndex, IntegerModP A, IntegerModP B, long MaximumCount, ExtendedBaseHash ExtendedBaseHash)
    : IDecryptionStatement
{
    public IntegerModP Base => A;

    public string Description => $"contest {ContestId}, option {ChoiceId}";

    public string CommitmentEquation => "eq. 88";

    public byte[] CommitmentHash(GuardianIndex guardian, IntegerModP commitmentA, IntegerModP commitmentB, IntegerModP partialDecryption, IReadOnlyCollection<GuardianIndex> participants) =>
        TallyDecryptionHashes.CommitmentHash(ExtendedBaseHash, ContestIndex, ChoiceIndex, guardian, A, B, commitmentA, commitmentB, partialDecryption, participants);

    public IntegerModQ Challenge(IntegerModP commitmentA, IntegerModP commitmentB, IntegerModP combinedDecryption) =>
        TallyDecryptionHashes.Challenge(ExtendedBaseHash, ContestIndex, ChoiceIndex, A, B, commitmentA, commitmentB, combinedDecryption);

    /// <summary>
    /// Every option of every contest of <paramref name="encryptionRecord"/>'s manifest, in manifest
    /// order, with its aggregate in <paramref name="encryptedTally"/> and the record's H_E. The tally
    /// must hold exactly the manifest's contests and options: an <see cref="ArgumentException"/>
    /// otherwise.
    /// </summary>
    public static TallyOption[] ForTally(EncryptionRecord encryptionRecord, EncryptedTally encryptedTally)
    {
        var manifest = encryptionRecord.Manifest;
        var options = new List<TallyOption>();
        foreach (var contest in manifest.Contests)
        {
            if (!encryptedTally.Contests.TryGetValue(contest.Id, out var aggregateContest)
                || aggregateContest.Choices.Count != contest.VerifiableFieldCount())
            {
                throw new ArgumentException($"The tally's options for contest {contest.Id} are not the manifest's.", nameof(encryptedTally));
            }

            // Every verifiable field: the options, then the declared supplemental fields (§3.3.9),
            // each decrypted with its own proof under its own option index.
            foreach (var choice in contest.VerifiableFields())
            {
                if (!aggregateContest.Choices.TryGetValue(choice.Id, out var aggregate))
                {
                    throw new ArgumentException($"The tally has no aggregate for option {choice.Id} of contest {contest.Id}.", nameof(encryptedTally));
                }

                options.Add(new TallyOption(contest.Id, choice.Id, contest.Index, choice.Index, aggregate.A, aggregate.B, aggregate.MaximumCount, encryptionRecord.ExtendedBaseHash));
            }
        }

        if (encryptedTally.Contests.Count != manifest.Contests.Count)
        {
            throw new ArgumentException("The tally has contests the manifest does not list.", nameof(encryptedTally));
        }

        return options.ToArray();
    }
}
