using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using static ElectionGuard.Core.Tally.PartialTallyDecryption;
using static ElectionGuard.Core.Tally.TallyDecryptionCommitmentReveal;
using static ElectionGuard.Core.Tally.TallyDecryptionResponse;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// Builds and reads the three §3.6.5 protocol messages, and the part of the protocol the guardians
/// and the administrator share: checking each d_j and combining a, b, M and c. Each message is
/// flattened into arrays in manifest option order (<see cref="TallyOption"/>) and participant
/// order (ascending index), and a missing, repeated, unexpected or malformed message is a
/// <see cref="TallyDecryptionException"/> naming its sender.
/// </summary>
internal static class TallyDecryptionMessages
{
    internal sealed class ReceivedCommitment
    {
        public required IntegerModP[] PartialDecryptions { get; init; }
        public required byte[][] CommitmentHashes { get; init; }
    }

    internal sealed class ReceivedReveal
    {
        public required IntegerModP[] CommitmentsA { get; init; }
        public required IntegerModP[] CommitmentsB { get; init; }
    }

    internal sealed class CombinedProof
    {
        /// <summary>w_j (eq. 85), in participant order.</summary>
        public required IntegerModQ[] LagrangeCoefficients { get; init; }

        /// <summary>a = ∏ a_j (eq. 89), per option.</summary>
        public required IntegerModP[] CommitmentA { get; init; }

        /// <summary>b = ∏ b_j (eq. 89), per option.</summary>
        public required IntegerModP[] CommitmentB { get; init; }

        /// <summary>M = ∏ M_j^{w_j} (eq. 86), per option.</summary>
        public required IntegerModP[] CombinedDecryptions { get; init; }

        /// <summary>c (eq. 90), per option.</summary>
        public required IntegerModQ[] Challenges { get; init; }
    }

    public static PartialTallyDecryption Commitment(GuardianIndex sender, TallyOption[] options, IntegerModP[] partialDecryptions, byte[][] commitmentHashes)
    {
        return new PartialTallyDecryption
        {
            GuardianIndex = sender,
            Contests = Nest(options,
                o => new PartialTallyChoiceDecryption { Mi = partialDecryptions[o], CommitmentHash = commitmentHashes[o] },
                choices => new PartialTallyContestDecryption { Choices = choices }),
        };
    }

    public static TallyDecryptionCommitmentReveal Reveal(GuardianIndex sender, TallyOption[] options, IntegerModP[] commitmentsA, IntegerModP[] commitmentsB)
    {
        return new TallyDecryptionCommitmentReveal
        {
            GuardianIndex = sender,
            Contests = Nest(options,
                o => new ChoiceReveal { CommitmentA = commitmentsA[o], CommitmentB = commitmentsB[o] },
                choices => new ContestReveal { Choices = choices }),
        };
    }

    public static TallyDecryptionResponse Response(GuardianIndex sender, TallyOption[] options, IntegerModQ[] responses)
    {
        return new TallyDecryptionResponse
        {
            GuardianIndex = sender,
            Contests = Nest(options,
                o => new ChoiceResponse { Response = responses[o] },
                choices => new ContestResponse { Choices = choices }),
        };
    }

    public static ReceivedCommitment[] ReadCommitments(IEnumerable<PartialTallyDecryption> messages, GuardianIndex[] participants, TallyOption[] options)
    {
        return InParticipantOrder(messages, x => x.GuardianIndex, participants, "round-1 (M_i, d_i)")
            .Select(message =>
            {
                var values = InOptionOrder(options, message.Contests, x => x.Choices, message.GuardianIndex, "round-1 (M_i, d_i)");
                if (values.Any(x => x.CommitmentHash is null))
                {
                    throw new TallyDecryptionException(message.GuardianIndex, $"Guardian {message.GuardianIndex.Index}'s round-1 message has an option with no commitment hash.");
                }

                return new ReceivedCommitment
                {
                    PartialDecryptions = values.Select(x => x.Mi).ToArray(),
                    CommitmentHashes = values.Select(x => x.CommitmentHash).ToArray(),
                };
            })
            .ToArray();
    }

    public static ReceivedReveal[] ReadReveals(IEnumerable<TallyDecryptionCommitmentReveal> messages, GuardianIndex[] participants, TallyOption[] options)
    {
        return InParticipantOrder(messages, x => x.GuardianIndex, participants, "round-2 (a_i, b_i)")
            .Select(message =>
            {
                var values = InOptionOrder(options, message.Contests, x => x.Choices, message.GuardianIndex, "round-2 (a_i, b_i)");
                return new ReceivedReveal
                {
                    CommitmentsA = values.Select(x => x.CommitmentA).ToArray(),
                    CommitmentsB = values.Select(x => x.CommitmentB).ToArray(),
                };
            })
            .ToArray();
    }

    public static IntegerModQ[][] ReadResponses(IEnumerable<TallyDecryptionResponse> messages, GuardianIndex[] participants, TallyOption[] options)
    {
        return InParticipantOrder(messages, x => x.GuardianIndex, participants, "round-3 (v_i)")
            .Select(message => InOptionOrder(options, message.Contests, x => x.Choices, message.GuardianIndex, "round-3 (v_i)")
                .Select(x => x.Response)
                .ToArray())
            .ToArray();
    }

    /// <summary>
    /// Checks every participant's d_j against eq. (88), recomputed from the caller's own
    /// <paramref name="options"/> (A, B and the manifest indices) and U, and the M_j and (a_j, b_j)
    /// the guardian sent; then forms a and b (eq. 89), M (eq. 86) and c (eq. 90) for every option.
    /// A mismatch throws <see cref="TallyDecryptionException"/> naming the first guardian, in
    /// option order, whose d_j does not hold: the complaint of p.48.
    /// </summary>
    public static CombinedProof CheckAndCombine(
        ExtendedBaseHash extendedBaseHash,
        GuardianIndex[] participants,
        TallyOption[] options,
        ReceivedCommitment[] commitments,
        ReceivedReveal[] reveals,
        ParallelOptions parallelOptions)
    {
        var lagrangeCoefficients = participants.Select(j => TallyDecryptionHashes.LagrangeCoefficient(j, participants)).ToArray();

        var mismatch = new int[options.Length];
        var commitmentA = new IntegerModP[options.Length];
        var commitmentB = new IntegerModP[options.Length];
        var combined = new IntegerModP[options.Length];
        var challenges = new IntegerModQ[options.Length];

        Parallel.For(0, options.Length, parallelOptions, o =>
        {
            var option = options[o];
            mismatch[o] = -1;
            for (int j = 0; j < participants.Length; j++)
            {
                var expected = TallyDecryptionHashes.CommitmentHash(
                    extendedBaseHash, option.ContestIndex, option.ChoiceIndex, participants[j],
                    option.A, option.B, reveals[j].CommitmentsA[o], reveals[j].CommitmentsB[o],
                    commitments[j].PartialDecryptions[o], participants);
                if (!expected.AsSpan().SequenceEqual(commitments[j].CommitmentHashes[o]))
                {
                    mismatch[o] = j;
                    return;
                }
            }

            IntegerModP a = 1;
            IntegerModP b = 1;
            IntegerModP m = 1;
            for (int j = 0; j < participants.Length; j++)
            {
                a *= reveals[j].CommitmentsA[o];
                b *= reveals[j].CommitmentsB[o];

                // w_j is public, but a full-width element of Z_q.
                m *= MontgomeryModP.PowModP(commitments[j].PartialDecryptions[o], lagrangeCoefficients[j]);
            }

            commitmentA[o] = a;
            commitmentB[o] = b;
            combined[o] = m;
            challenges[o] = TallyDecryptionHashes.Challenge(extendedBaseHash, option.ContestIndex, option.ChoiceIndex, option.A, option.B, a, b, m);
        });

        for (int o = 0; o < options.Length; o++)
        {
            if (mismatch[o] >= 0)
            {
                var offender = participants[mismatch[o]];
                throw new TallyDecryptionException(offender,
                    $"Guardian {offender.Index}'s commitment hash d_{offender.Index} (eq. 88) does not match the (a, b) it revealed and the M it sent for contest {options[o].ContestId}, option {options[o].ChoiceId}; the protocol halts.");
            }
        }

        return new CombinedProof
        {
            LagrangeCoefficients = lagrangeCoefficients,
            CommitmentA = commitmentA,
            CommitmentB = commitmentB,
            CombinedDecryptions = combined,
            Challenges = challenges,
        };
    }

    private static Dictionary<string, TContest> Nest<TContest, TValue>(TallyOption[] options, Func<int, TValue> value, Func<Dictionary<string, TValue>, TContest> contest)
    {
        var byContest = new Dictionary<string, Dictionary<string, TValue>>();
        for (int o = 0; o < options.Length; o++)
        {
            if (!byContest.TryGetValue(options[o].ContestId, out var choices))
            {
                choices = new Dictionary<string, TValue>();
                byContest[options[o].ContestId] = choices;
            }

            choices[options[o].ChoiceId] = value(o);
        }

        return byContest.ToDictionary(x => x.Key, x => contest(x.Value));
    }

    private static T[] InParticipantOrder<T>(IEnumerable<T> messages, Func<T, GuardianIndex> sender, GuardianIndex[] participants, string round)
        where T : class
    {
        var ordered = new T[participants.Length];
        foreach (var message in messages)
        {
            var from = sender(message);
            int position = Array.IndexOf(participants, from);
            if (position < 0)
            {
                throw new TallyDecryptionException(from, $"Guardian {from.Index} sent a {round} message but is not a participant in this decryption.");
            }

            if (ordered[position] is not null)
            {
                throw new TallyDecryptionException(from, $"Guardian {from.Index} sent more than one {round} message.");
            }

            ordered[position] = message;
        }

        for (int j = 0; j < participants.Length; j++)
        {
            if (ordered[j] is null)
            {
                throw new TallyDecryptionException(participants[j], $"Guardian {participants[j].Index} sent no {round} message; the protocol halts.");
            }
        }

        return ordered;
    }

    private static TValue[] InOptionOrder<TContest, TValue>(
        TallyOption[] options,
        Dictionary<string, TContest>? contests,
        Func<TContest, Dictionary<string, TValue>?> choices,
        GuardianIndex sender,
        string round)
        where TValue : class
    {
        TallyDecryptionException Malformed(string detail) =>
            new(sender, $"Guardian {sender.Index}'s {round} message {detail}; it must cover exactly the manifest's options.");

        if (contests is null)
        {
            throw Malformed("has no contests");
        }

        int contestCount = options.Select(x => x.ContestId).Distinct().Count();
        if (contests.Count != contestCount)
        {
            throw Malformed($"has {contests.Count} contests, not {contestCount}");
        }

        var values = new TValue[options.Length];
        for (int o = 0; o < options.Length; o++)
        {
            if (!contests.TryGetValue(options[o].ContestId, out var contest)
                || choices(contest) is not { } contestChoices
                || !contestChoices.TryGetValue(options[o].ChoiceId, out var value)
                || value is null)
            {
                throw Malformed($"has no value for contest {options[o].ContestId}, option {options[o].ChoiceId}");
            }

            values[o] = value;
        }

        int total = contests.Values.Sum(x => choices(x)?.Count ?? 0);
        if (total != options.Length)
        {
            throw Malformed($"has {total} options, not {options.Length}");
        }

        return values;
    }
}
