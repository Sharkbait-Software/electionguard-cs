using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Verify;
using System.Buffers;
using System.Buffers.Binary;

namespace ElectionGuard.Core.Tally;

// The three messages each participating guardian sends to decrypt one ballot contest's contest data
// field (§3.6.6), through the administrator, exactly as for a tally (§3.6.5). Each names the ballot
// and contest it is for, and a guardian or administrator refuses a message for any other.

/// <summary>
/// Round 1 (<see cref="TallyGuardian.CommitContestData"/>): guardian i's partial decryption
/// m_i = C_0^{ẑ_i} (eq. 96) and its commitment hash d_i (eq. 99) to the commitment pair (a_i, b_i)
/// that it reveals only in round 2.
/// </summary>
public class ContestDataPartialDecryption
{
    public required GuardianIndex GuardianIndex { get; init; }
    public required string BallotId { get; init; }
    public required string ContestId { get; init; }

    /// <summary>m_i = C_0^{ẑ_i} mod p (eq. 96).</summary>
    public required IntegerModP Mi { get; init; }

    /// <summary>d_i (eq. 99), 32 bytes.</summary>
    public required byte[] CommitmentHash { get; init; }
}

/// <summary>
/// Round 2 (<see cref="TallyGuardian.RevealContestData"/>), sent only once guardian i holds every
/// participant's round-1 message: (a_i, b_i) = (g^{u_i}, C_0^{u_i}) (eq. 98).
/// </summary>
public class ContestDataCommitmentReveal
{
    public required GuardianIndex GuardianIndex { get; init; }
    public required string BallotId { get; init; }
    public required string ContestId { get; init; }

    /// <summary>a_i = g^{u_i} mod p.</summary>
    public required IntegerModP CommitmentA { get; init; }

    /// <summary>b_i = C_0^{u_i} mod p.</summary>
    public required IntegerModP CommitmentB { get; init; }
}

/// <summary>
/// Round 3 (<see cref="TallyGuardian.RespondContestData"/>): v_i = (u_i - c_i·ẑ_i) mod q (eq. 102),
/// c_i = c·w_i, c being the eq. (101) challenge the guardian computed itself.
/// </summary>
public class ContestDataDecryptionResponse
{
    public required GuardianIndex GuardianIndex { get; init; }
    public required string BallotId { get; init; }
    public required string ContestId { get; init; }

    /// <summary>v_i (eq. 102).</summary>
    public required IntegerModQ Response { get; init; }
}

/// <summary>
/// A decrypted contest data field as published (§3.6.6 p.51: "the decryption value β is published
/// along with the proof (c, v)"), with the decrypted bytes D (eq. 106), which Verification 12 checks
/// against the ballot's (C_0, C_1, C_2) (12.A-12.C). D is 32·b_Λ bytes;
/// <see cref="DecodeText"/> reads the library's string encoding (user decision Q7) from it.
/// </summary>
public class DecryptedContestData
{
    public required string BallotId { get; init; }
    public required string ContestId { get; init; }

    /// <summary>ind_c(Λ), the contest's manifest index, as hashed by eqs. (99), (101) and (104).</summary>
    public required int ContestIndex { get; init; }

    /// <summary>β = ∏ m_i^{w_i} mod p (eq. 97), = C_0^ŝ.</summary>
    public required IntegerModP Beta { get; init; }

    /// <summary>The proof challenge c (eq. 101).</summary>
    public required IntegerModQ Challenge { get; init; }

    /// <summary>The proof response v = (Σ v_i) mod q (eq. 103).</summary>
    public required IntegerModQ Response { get; init; }

    /// <summary>D = C_{1,1} ⊕ k_1 ‖ ... ‖ C_{1,b_Λ} ⊕ k_{b_Λ} (eq. 106).</summary>
    public required byte[] Data { get; init; }

    /// <summary>
    /// The string <see cref="ContestDataEncoding.Encode"/> wrote into <see cref="Data"/>; throws
    /// <see cref="FormatException"/> if the device used another encoding.
    /// </summary>
    public string DecodeText() => ContestDataEncoding.Decode(Data);
}

/// <summary>
/// The hashes of the §3.6.6 proof of correct contest data decryption (§5.5.4 table, p.77). The
/// guardians, the administrator and Verification 12 all compute them here.
/// <para>
/// Both are keyed with H_I, as eq. (99) and the body of §3.6.6 say; the table's B0 = H_E for eq. (99)
/// is treated as an erratum (user decision Q5). C_2 is hashed as b(C_2, 64) = b(c, 32) ‖ b(v, 32).
/// </para>
/// </summary>
public static class ContestDataDecryptionHashes
{
    /// <summary>
    /// Eq. (99): d_i = H(H_I; 0x32, ind_c(Λ), i, C_0, C_1, C_2, a_i, b_i, m_i, U), with
    /// B1 = 0x32 ‖ b(ind_c, 4) ‖ b(i, 4) ‖ b(C_0, 512) ‖ C_1 ‖ b(C_2, 64) ‖ b(a_i, 512) ‖ b(b_i, 512) ‖
    /// b(m_i, 512) ‖ b(#U, 4) ‖ b(j_1, 4) ‖ ... ‖ b(j_#U, 4), len(B1) = 2125 + 32·b_Λ + 4·#U. U's
    /// indices are listed in ascending order, as for eq. (88) (user decision Q10).
    /// </summary>
    public static byte[] CommitmentHash(
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        int contestIndex,
        GuardianIndex guardianIndex,
        EncryptedContestData contestData,
        IntegerModP commitmentA,
        IntegerModP commitmentB,
        IntegerModP partialDecryption,
        IReadOnlyCollection<GuardianIndex> participants)
    {
        var sorted = TallyDecryptionHashes.Canonical(participants);
        int length = 1 + 2 * sizeof(int) + CiphertextLength(contestData) + 3 * IntegerModP.ByteLength + sizeof(int) + sizeof(int) * sorted.Length;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x32;
            int offset = 1;
            TallyDecryptionHashes.WriteIndex(message, ref offset, contestIndex);
            TallyDecryptionHashes.WriteIndex(message, ref offset, guardianIndex.Index);
            WriteCiphertext(message, ref offset, contestData);
            TallyDecryptionHashes.WriteElement(message, ref offset, commitmentA);
            TallyDecryptionHashes.WriteElement(message, ref offset, commitmentB);
            TallyDecryptionHashes.WriteElement(message, ref offset, partialDecryption);
            TallyDecryptionHashes.WriteIndex(message, ref offset, sorted.Length);
            foreach (var participant in sorted)
            {
                TallyDecryptionHashes.WriteIndex(message, ref offset, participant.Index);
            }

            var digest = new byte[EGHash.HashBytes];
            EGHash.HashConcatenated(selectionEncryptionIdentifierHash, message, digest);
            return digest;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Eq. (101) and Verification 12.B: c = H_q(H_I; 0x33, ind_c(Λ), C_0, C_1, C_2, a, b, β), with
    /// B1 = 0x33 ‖ b(ind_c, 4) ‖ b(C_0, 512) ‖ C_1 ‖ b(C_2, 64) ‖ b(a, 512) ‖ b(b, 512) ‖ b(β, 512),
    /// len(B1) = 2117 + 32·b_Λ.
    /// </summary>
    public static IntegerModQ Challenge(
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        int contestIndex,
        EncryptedContestData contestData,
        IntegerModP commitmentA,
        IntegerModP commitmentB,
        IntegerModP beta)
    {
        int length = 1 + sizeof(int) + CiphertextLength(contestData) + 3 * IntegerModP.ByteLength;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x33;
            int offset = 1;
            TallyDecryptionHashes.WriteIndex(message, ref offset, contestIndex);
            WriteCiphertext(message, ref offset, contestData);
            TallyDecryptionHashes.WriteElement(message, ref offset, commitmentA);
            TallyDecryptionHashes.WriteElement(message, ref offset, commitmentB);
            TallyDecryptionHashes.WriteElement(message, ref offset, beta);
            return EGHash.HashModQConcatenated(selectionEncryptionIdentifierHash, message);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>b(C_0, 512) ‖ C_1 ‖ b(C_2, 64).</summary>
    private static int CiphertextLength(EncryptedContestData contestData) =>
        IntegerModP.ByteLength + contestData.C1.Length + 2 * IntegerModQ.ByteLength;

    private static void WriteCiphertext(Span<byte> message, ref int offset, EncryptedContestData contestData)
    {
        TallyDecryptionHashes.WriteElement(message, ref offset, contestData.C0);
        contestData.C1.CopyTo(message[offset..]);
        offset += contestData.C1.Length;
        contestData.Challenge.WriteBigEndian(message.Slice(offset, IntegerModQ.ByteLength));
        offset += IntegerModQ.ByteLength;
        contestData.Response.WriteBigEndian(message.Slice(offset, IntegerModQ.ByteLength));
        offset += IntegerModQ.ByteLength;
    }
}

/// <summary>
/// The contest data field of one contest of one ballot, as the guardians decrypt it: the base C_0,
/// and the eq. (99)/(101) hashes over the ballot's own (C_0, C_1, C_2) under its H_I.
/// </summary>
internal sealed class ContestDataStatement : IDecryptionStatement
{
    public required string BallotId { get; init; }
    public required string ContestId { get; init; }
    public required int ContestIndex { get; init; }

    /// <summary>b_Λ, from the manifest.</summary>
    public required int Blocks { get; init; }

    /// <summary>H_I, recomputed from H_E and the ballot's id_B (eq. 32).</summary>
    public required SelectionEncryptionIdentifierHash SelectionEncryptionIdentifierHash { get; init; }

    public required EncryptedContestData Data { get; init; }

    public IntegerModP Base => Data.C0;

    public string Description => $"ballot {BallotId}, contest {ContestId}'s contest data";

    public string CommitmentEquation => "eq. 99";

    public byte[] CommitmentHash(GuardianIndex guardian, IntegerModP commitmentA, IntegerModP commitmentB, IntegerModP partialDecryption, IReadOnlyCollection<GuardianIndex> participants) =>
        ContestDataDecryptionHashes.CommitmentHash(SelectionEncryptionIdentifierHash, ContestIndex, guardian, Data, commitmentA, commitmentB, partialDecryption, participants);

    public IntegerModQ Challenge(IntegerModP commitmentA, IntegerModP commitmentB, IntegerModP combinedDecryption) =>
        ContestDataDecryptionHashes.Challenge(SelectionEncryptionIdentifierHash, ContestIndex, Data, commitmentA, commitmentB, combinedDecryption);

    /// <summary>
    /// The contest data field of contest <paramref name="contestId"/> on <paramref name="ballot"/>,
    /// with ind_c and b_Λ from <paramref name="encryptionRecord"/>'s manifest, never from the ballot.
    /// Throws <see cref="ArgumentException"/> if the ballot is malformed (<see cref="BallotStructure"/>),
    /// the contest declares no contest data, or the ballot's H_I is not H(H_E; 0x20, id_B)
    /// (Verification 5.B), since every hash of the decryption is keyed with H_I.
    /// </summary>
    public static ContestDataStatement For(EncryptionRecord encryptionRecord, EncryptedBallot ballot, string contestId)
    {
        ArgumentNullException.ThrowIfNull(encryptionRecord);
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(contestId);

        var manifestContest = encryptionRecord.Manifest.Contests.FirstOrDefault(x => x.Id == contestId)
            ?? throw new ArgumentException($"Contest {contestId} is not in the manifest.", nameof(contestId));
        if (manifestContest.ContestDataBlocks == 0)
        {
            throw new ArgumentException($"Contest {contestId} declares no contest data (b_Λ = 0); there is nothing to decrypt.", nameof(contestId));
        }

        if (BallotStructure.FindViolation(ballot, encryptionRecord.Manifest) is string violation)
        {
            throw new ArgumentException($"Ballot {ballot.Id} is malformed, so its contest data is not decrypted: {violation}", nameof(ballot));
        }

        var contest = ballot.Contests.FirstOrDefault(x => x.Id == contestId)
            ?? throw new ArgumentException($"Ballot {ballot.Id} has no contest {contestId}.", nameof(contestId));

        var selectionHash = new SelectionEncryptionIdentifierHash(encryptionRecord.ExtendedBaseHash, ballot.SelectionEncryptionIdentifier);
        if (!((byte[])selectionHash).AsSpan().SequenceEqual((byte[])ballot.SelectionEncryptionIdentifierHash))
        {
            throw new ArgumentException($"Ballot {ballot.Id}'s H_I is not H(H_E; 0x20, id_B) (Verification 5.B), so its contest data is not decrypted.", nameof(ballot));
        }

        return new ContestDataStatement
        {
            BallotId = ballot.Id,
            ContestId = contestId,
            ContestIndex = manifestContest.Index,
            Blocks = manifestContest.ContestDataBlocks,
            SelectionEncryptionIdentifierHash = selectionHash,
            // BallotStructure has required the field, with C_1 of 32·b_Λ bytes.
            Data = contest.ContestData!,
        };
    }

    /// <summary>
    /// What must hold of the field before anyone computes a partial decryption with it. Throws
    /// <see cref="TallyDecryptionException"/> naming no guardian: the fault is the ballot's.
    /// <list type="number">
    /// <item>C_0 is in Z_p^r: 0 &lt; C_0 &lt; p and C_0^q mod p = 1. The spec does not state this
    /// check; it is a library hardening (S6 review). In §3.6.5 the base A of a partial decryption is a
    /// member because Verifications 6.A/7.A checked every α, and §3.6.6 says its proof is "exactly the
    /// same", but nothing checks C_0, and the eq. (69) proof below does not exclude non-members:
    /// C_0 = 0 passes it with a = 0 and makes every m_i zero, so that the zero-share check would
    /// blame an honest guardian; C_0 = -g^ξ passes it whenever c is even, and then m_i = C_0^{ẑ_i}
    /// leaks the parity of each guardian's share ẑ_i (p ≡ 3 mod 4, so -1 has order 2).</item>
    /// <item>§3.6.6 p.49-50: the Schnorr proof C_2 holds: a = g^v·C_0^c and
    /// c = H_q(H_I; 0x27, ind_c, a, C_0, C_1) (eq. 69).</item>
    /// </list>
    /// </summary>
    public void RequireDecryptable(string who)
    {
        // IsMember also rejects 0, and raises C_0 to q as a BigInteger, never as a (zero) IntegerModQ.
        if (!SubgroupMembership.IsMember(Data.C0))
        {
            throw new TallyDecryptionException(null,
                $"C_0 of {Description} is not in the order-q subgroup Z_p^r (it must satisfy 0 < C_0 < p and C_0^q mod p = 1); {who} does not decrypt it.");
        }

        if (!ContestDataEncryption.ProofHolds(SelectionEncryptionIdentifierHash, ContestIndex, Data))
        {
            throw new TallyDecryptionException(null,
                $"The Schnorr proof C_2 of {Description} does not verify (eq. 69: c = H_q(H_I; 0x27, ind_c, g^v·C_0^c, C_0, C_1)); {who} does not decrypt it (§3.6.6).");
        }
    }

    /// <summary>
    /// Reads one message per participant, in participant order, each for this ballot contest.
    /// </summary>
    public T[] Read<T>(IEnumerable<T> messages, Func<T, GuardianIndex> sender, Func<T, (string BallotId, string ContestId)> target, GuardianIndex[] participants, string round)
        where T : class
    {
        var ordered = VerifiableDecryption.InParticipantOrder(messages, sender, participants, round);
        foreach (var message in ordered)
        {
            var (ballotId, contestId) = target(message);
            if (ballotId != BallotId || contestId != ContestId)
            {
                var from = sender(message);
                throw new TallyDecryptionException(from, $"Guardian {from.Index}'s {round} message is for ballot {ballotId}, contest {contestId}, not for ballot {BallotId}, contest {ContestId}.");
            }
        }

        return ordered;
    }
}
