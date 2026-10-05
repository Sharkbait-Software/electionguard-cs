using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Numerics;
using static ElectionGuard.Core.Tally.DecryptedTally;
using static ElectionGuard.Core.Tally.PartialTallyDecryption;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// A guardian's side of verifiable tally decryption (§3.6.3-§3.6.5). For every option of every
/// contest, the participating guardians U jointly compute M = A^s (eq. 86) and a Chaum-Pedersen
/// proof (c, v) that they did (eqs. 87-93), in three rounds, each a method here:
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
/// The administrator mediates every message (<see cref="TallyAdmin"/>). There is no network layer
/// in this library: <see cref="TallyAdmin.Decrypt"/> drives in-process guardians through the three
/// rounds, and a distributed deployment carries the same three messages between machines and hands
/// them to <see cref="TallyAdmin.Combine"/>.
///
/// The guardian never accepts a challenge from anyone. It computes c from values that every
/// participant committed to before any was revealed, so no one can choose c after seeing a
/// commitment. Each u_i is used for exactly one response: <see cref="Respond"/> discards the
/// decryption in progress, and a second call throws. Two responses with one u_i to two different
/// challenges would give away z_i.
///
/// A guardian works on one decryption at a time. <see cref="Commit"/> starts a new one and
/// discards any unfinished one, which is safe: nothing is ever responded with an old u_i.
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
    private Session? _session;

    public GuardianIndex Index => _index;

    /// <summary>
    /// Test seam: supplies u_i for an option, given (ind_c, ind_o), in place of a fresh random
    /// value. Lets the known-answer tests reproduce the spec oracle's proofs exactly. Null outside
    /// tests.
    /// </summary>
    internal Func<int, int, IntegerModQ>? NonceSourceForTesting { get; set; }

    /// <summary>
    /// Test seam: replaces this guardian's M_i for an option, given (ind_c, ind_o, M_i), before it is
    /// hashed into d_i and sent: a dishonest guardian that is consistent about its wrong share, such
    /// as M_i·K^(-δ/w_i), which would shift the count by δ if nothing checked the proof. Null
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

        var sorted = TallyDecryptionHashes.RequireQuorum(participants);
        if (!sorted.Contains(_index))
        {
            throw new ArgumentException($"Guardian {_index.Index} is not among the participants, so it cannot take part in this decryption.", nameof(participants));
        }

        var options = TallyOption.ForTally(encryptionRecord.Manifest, encryptedTally);
        var extendedBaseHash = encryptionRecord.ExtendedBaseHash;
        var secretShare = _shares.VoteEncryptionKeyShare;
        var nonceSource = NonceSourceForTesting;
        var tamper = PartialDecryptionTamperForTesting;

        var nonces = new IntegerModQ[options.Length];
        var partialDecryptions = new IntegerModP[options.Length];
        var commitmentsA = new IntegerModP[options.Length];
        var commitmentsB = new IntegerModP[options.Length];
        var commitmentHashes = new byte[options.Length][];

        Parallel.For(0, options.Length, new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism }, o =>
        {
            var option = options[o];
            var u = nonceSource?.Invoke(option.ContestIndex, option.ChoiceIndex) ?? ElectionGuardRandom.GetIntegerModQ();

            // u_i and z_i are secrets and full-width elements of Z_q: the constant-time path.
            var partialDecryption = MontgomeryModP.PowModP(option.A, secretShare);
            if (tamper is not null)
            {
                partialDecryption = tamper(option.ContestIndex, option.ChoiceIndex, partialDecryption);
            }

            var commitmentA = MontgomeryModP.PowModP(EGParameters.G, u);
            var commitmentB = MontgomeryModP.PowModP(option.A, u);

            nonces[o] = u;
            partialDecryptions[o] = partialDecryption;
            commitmentsA[o] = commitmentA;
            commitmentsB[o] = commitmentB;
            commitmentHashes[o] = TallyDecryptionHashes.CommitmentHash(
                extendedBaseHash, option.ContestIndex, option.ChoiceIndex, _index,
                option.A, option.B, commitmentA, commitmentB, partialDecryption, sorted);
        });

        _session = new Session
        {
            ExtendedBaseHash = extendedBaseHash,
            Participants = sorted,
            Options = options,
            Nonces = nonces,
            PartialDecryptions = partialDecryptions,
            CommitmentsA = commitmentsA,
            CommitmentsB = commitmentsB,
            CommitmentHashes = commitmentHashes,
        };

        return TallyDecryptionMessages.Commitment(_index, options, partialDecryptions, commitmentHashes);
    }

    /// <summary>
    /// Round 2. Given every participant's round-1 message, this guardian's included unchanged,
    /// returns its commitment pairs (a_i, b_i). Refuses, with a <see cref="TallyDecryptionException"/>
    /// naming the guardian, if a participant's message is missing, repeated or malformed, or comes
    /// from a guardian outside U: (a_i, b_i) may be revealed only after every d_j is in (p.47).
    /// </summary>
    public TallyDecryptionCommitmentReveal Reveal(IReadOnlyCollection<PartialTallyDecryption> commitments)
    {
        var session = _session ?? throw new InvalidOperationException($"Guardian {_index.Index} has no decryption awaiting a reveal: call Commit first.");
        if (session.Commitments is not null)
        {
            throw new InvalidOperationException($"Guardian {_index.Index} has already revealed its commitments for this decryption.");
        }

        try
        {
            var received = TallyDecryptionMessages.ReadCommitments(commitments, session.Participants, session.Options);
            var own = received[Array.IndexOf(session.Participants, _index)];
            for (int o = 0; o < session.Options.Length; o++)
            {
                if (own.PartialDecryptions[o] != session.PartialDecryptions[o] || !own.CommitmentHashes[o].AsSpan().SequenceEqual(session.CommitmentHashes[o]))
                {
                    throw new TallyDecryptionException(null, $"Guardian {_index.Index}'s own round-1 message came back altered for contest {session.Options[o].ContestId}, option {session.Options[o].ChoiceId}.");
                }
            }

            session.Commitments = received;
        }
        catch (TallyDecryptionException)
        {
            _session = null;
            throw;
        }

        return TallyDecryptionMessages.Reveal(_index, session.Options, session.CommitmentsA, session.CommitmentsB);
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
        var session = _session ?? throw new InvalidOperationException($"Guardian {_index.Index} has no decryption awaiting a response: call Commit and Reveal first, and respond only once.");
        var commitments = session.Commitments ?? throw new InvalidOperationException($"Guardian {_index.Index} has not revealed its commitments for this decryption: call Reveal first.");

        // Whatever happens below, this decryption is finished: u_i is never used twice.
        _session = null;

        var revealed = TallyDecryptionMessages.ReadReveals(reveals, session.Participants, session.Options);
        int self = Array.IndexOf(session.Participants, _index);
        for (int o = 0; o < session.Options.Length; o++)
        {
            if (revealed[self].CommitmentsA[o] != session.CommitmentsA[o] || revealed[self].CommitmentsB[o] != session.CommitmentsB[o])
            {
                throw new TallyDecryptionException(null, $"Guardian {_index.Index}'s own round-2 message came back altered for contest {session.Options[o].ContestId}, option {session.Options[o].ChoiceId}.");
            }
        }

        var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
        var proof = TallyDecryptionMessages.CheckAndCombine(session.ExtendedBaseHash, session.Participants, session.Options, commitments, revealed, options);

        var lagrangeCoefficient = proof.LagrangeCoefficients[self];
        var secretShare = _shares.VoteEncryptionKeyShare;
        var responses = new IntegerModQ[session.Options.Length];
        for (int o = 0; o < session.Options.Length; o++)
        {
            var challenge = proof.Challenges[o] * lagrangeCoefficient;
            responses[o] = session.Nonces[o] - challenge * secretShare;
            session.Nonces[o] = default;
        }

        return TallyDecryptionMessages.Response(_index, session.Options, responses);
    }

    private sealed class Session
    {
        public required ExtendedBaseHash ExtendedBaseHash { get; init; }
        public required GuardianIndex[] Participants { get; init; }
        public required TallyOption[] Options { get; init; }
        public required IntegerModQ[] Nonces { get; init; }
        public required IntegerModP[] PartialDecryptions { get; init; }
        public required IntegerModP[] CommitmentsA { get; init; }
        public required IntegerModP[] CommitmentsB { get; init; }
        public required byte[][] CommitmentHashes { get; init; }

        /// <summary>Every participant's round-1 message, in <see cref="Participants"/> order; set by Reveal.</summary>
        public TallyDecryptionMessages.ReceivedCommitment[]? Commitments { get; set; }
    }
}

/// <summary>
/// The administrator's side of tally decryption (§3.6.4, §3.6.5): mediating the guardians'
/// messages, combining them into M, T and the proof (c, v), and recovering each count t.
/// </summary>
public class TallyAdmin
{
    /// <summary>
    /// Test seam: when false, <see cref="Combine"/> publishes without first checking the combined
    /// proof, as a careless administrator would, so tests can show that Verification 10 catches
    /// what the check would have. True outside tests.
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
        var options = TallyOption.ForTally(encryptionRecord.Manifest, encryptedTally);
        var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };

        // The rounds are checked in protocol order: a guardian whose d_j does not hold is named even
        // if, having halted, the others sent no round-3 message.
        var received = TallyDecryptionMessages.ReadCommitments(commitments, participants, options);
        var revealed = TallyDecryptionMessages.ReadReveals(reveals, participants, options);

        // A zero M_j has no inverse and makes M zero; only a corrupt share can be zero.
        for (int j = 0; j < participants.Length; j++)
        {
            int zero = Array.FindIndex(received[j].PartialDecryptions, m => m == 0);
            if (zero >= 0)
            {
                throw new TallyDecryptionException(participants[j], $"Tally did not decrypt successfully: guardian {participants[j].Index}'s partial decryption for contest {options[zero].ContestId}, option {options[zero].ChoiceId} is 0.");
            }
        }

        var proof = TallyDecryptionMessages.CheckAndCombine(encryptionRecord.ExtendedBaseHash, participants, options, received, revealed, parallelOptions);
        var responded = TallyDecryptionMessages.ReadResponses(responses, participants, options);

        var responseSums = new IntegerModQ[options.Length];
        for (int o = 0; o < options.Length; o++)
        {
            IntegerModQ v = 0;
            for (int j = 0; j < participants.Length; j++)
            {
                v += responded[j][o];
            }

            responseSums[o] = v;
        }

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
                failing[o] = !ProofHolds(options[o].A, proof.CombinedDecryptions[o], voteEncryptionKey,
                    proof.CommitmentA[o], proof.CommitmentB[o], proof.Challenges[o], responseSums[o]);
            });

            if (failing.Any(x => x))
            {
                var culprit = IdentifyInvalidShare(encryptionRecord, participants, options, failing, proof, received, revealed, responded);
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

    /// <summary>g^v·K^c = a and A^v·M^c = b: Verification 10.2/10.3 against the commitments the guardians revealed.</summary>
    private static bool ProofHolds(IntegerModP a, IntegerModP combinedDecryption, IntegerModP voteEncryptionKey, IntegerModP commitmentA, IntegerModP commitmentB, IntegerModQ challenge, IntegerModQ response)
    {
        var expectedA = MontgomeryModP.PowModP(EGParameters.G, response) * MontgomeryModP.PowModP(voteEncryptionKey, challenge);
        if (expectedA != commitmentA)
        {
            return false;
        }

        var expectedB = MontgomeryModP.PowModP(a, response) * MontgomeryModP.PowModP(combinedDecryption, challenge);
        return expectedB == commitmentB;
    }

    /// <summary>
    /// Note 3.7: for each participant j and each failing option, recomputes
    /// a'_j = (∏_l ∏_m K_{l,m}^{j^m})^{c_j}·g^{v_j} (eq. 94) and b'_j = A^{v_j}·M_j^{c_j} (eq. 95), with
    /// c_j = c·w_j, and returns the first guardian for which either differs from what it revealed.
    /// The product of commitments is g^{z_j}, guardian j's public key share. Runs only once the
    /// combined proof has failed.
    /// </summary>
    private static GuardianIndex? IdentifyInvalidShare(
        EncryptionRecord encryptionRecord,
        GuardianIndex[] participants,
        TallyOption[] options,
        bool[] failing,
        TallyDecryptionMessages.CombinedProof proof,
        TallyDecryptionMessages.ReceivedCommitment[] received,
        TallyDecryptionMessages.ReceivedReveal[] revealed,
        IntegerModQ[][] responded)
    {
        for (int j = 0; j < participants.Length; j++)
        {
            // j^m is a small public exponent: BigInteger.ModPow scales with it and wins here.
            IntegerModP publicKeyShare = 1;
            foreach (var guardian in encryptionRecord.Guardians)
            {
                for (int m = 0; m < guardian.VoteEncryptionCommitments.Count; m++)
                {
                    publicKeyShare *= IntegerModP.PowModP(guardian.VoteEncryptionCommitments[m], BigInteger.Pow(participants[j].Index, m));
                }
            }

            for (int o = 0; o < options.Length; o++)
            {
                if (!failing[o])
                {
                    continue;
                }

                var challenge = proof.Challenges[o] * proof.LagrangeCoefficients[j];
                var response = responded[j][o];
                var expectedA = MontgomeryModP.PowModP(publicKeyShare, challenge) * MontgomeryModP.PowModP(EGParameters.G, response);
                var expectedB = MontgomeryModP.PowModP(options[o].A, response) * MontgomeryModP.PowModP(received[j].PartialDecryptions[o], challenge);
                if (expectedA != revealed[j].CommitmentsA[o] || expectedB != revealed[j].CommitmentsB[o])
                {
                    return participants[j];
                }
            }
        }

        return null;
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
/// encrypted aggregate (A, B).
/// </summary>
internal sealed record TallyOption(string ContestId, string ChoiceId, int ContestIndex, int ChoiceIndex, IntegerModP A, IntegerModP B, long MaximumCount)
{
    /// <summary>
    /// Every option of every contest of <paramref name="manifest"/>, in manifest order, with its
    /// aggregate in <paramref name="encryptedTally"/>. The tally must hold exactly the manifest's
    /// contests and options: an <see cref="ArgumentException"/> otherwise.
    /// </summary>
    public static TallyOption[] ForTally(Manifest manifest, EncryptedTally encryptedTally)
    {
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

                options.Add(new TallyOption(contest.Id, choice.Id, contest.Index, choice.Index, aggregate.A, aggregate.B, aggregate.MaximumCount));
            }
        }

        if (encryptedTally.Contests.Count != manifest.Contests.Count)
        {
            throw new ArgumentException("The tally has contests the manifest does not list.", nameof(encryptedTally));
        }

        return options.ToArray();
    }
}
