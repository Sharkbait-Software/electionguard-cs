using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using static ElectionGuard.Core.Tally.PartialTallyDecryption;
using static ElectionGuard.Core.Tally.TallyDecryptionCommitmentReveal;
using static ElectionGuard.Core.Tally.TallyDecryptionResponse;

namespace ElectionGuard.Core.Tally;

/// <summary>
/// Builds and reads the three §3.6.5 protocol messages of a tally decryption. The part of the
/// protocol the guardians and the administrator share, checking each d_j and combining a, b, M and
/// c, is <see cref="VerifiableDecryption"/>. Each message is flattened into arrays in manifest option order (<see cref="TallyOption"/>) and participant
/// order (ascending index), and a missing, repeated, unexpected or malformed message is a
/// <see cref="TallyDecryptionException"/> naming its sender.
/// </summary>
internal static class TallyDecryptionMessages
{
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

    public static VerifiableDecryption.ReceivedCommitment[] ReadCommitments(IEnumerable<PartialTallyDecryption> messages, GuardianIndex[] participants, TallyOption[] options)
    {
        return VerifiableDecryption.InParticipantOrder(messages, x => x.GuardianIndex, participants, "round-1 (M_i, d_i)")
            .Select(message =>
            {
                var values = InOptionOrder(options, message.Contests, x => x.Choices, message.GuardianIndex, "round-1 (M_i, d_i)");
                if (values.Any(x => x.CommitmentHash is null))
                {
                    throw new TallyDecryptionException(message.GuardianIndex, $"Guardian {message.GuardianIndex.Index}'s round-1 message has an option with no commitment hash.");
                }

                return new VerifiableDecryption.ReceivedCommitment
                {
                    PartialDecryptions = values.Select(x => x.Mi).ToArray(),
                    CommitmentHashes = values.Select(x => x.CommitmentHash).ToArray(),
                };
            })
            .ToArray();
    }

    public static VerifiableDecryption.ReceivedReveal[] ReadReveals(IEnumerable<TallyDecryptionCommitmentReveal> messages, GuardianIndex[] participants, TallyOption[] options)
    {
        return VerifiableDecryption.InParticipantOrder(messages, x => x.GuardianIndex, participants, "round-2 (a_i, b_i)")
            .Select(message =>
            {
                var values = InOptionOrder(options, message.Contests, x => x.Choices, message.GuardianIndex, "round-2 (a_i, b_i)");
                return new VerifiableDecryption.ReceivedReveal
                {
                    CommitmentsA = values.Select(x => x.CommitmentA).ToArray(),
                    CommitmentsB = values.Select(x => x.CommitmentB).ToArray(),
                };
            })
            .ToArray();
    }

    public static IntegerModQ[][] ReadResponses(IEnumerable<TallyDecryptionResponse> messages, GuardianIndex[] participants, TallyOption[] options)
    {
        return VerifiableDecryption.InParticipantOrder(messages, x => x.GuardianIndex, participants, "round-3 (v_i)")
            .Select(message => InOptionOrder(options, message.Contests, x => x.Choices, message.GuardianIndex, "round-3 (v_i)")
                .Select(x => x.Response)
                .ToArray())
            .ToArray();
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
