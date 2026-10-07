using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ElectionGuard.Core.BallotEncryption;

/// <summary>
/// An encrypted contest data field C = (C_0, C_1, C_2) (§3.3.10 eqs. 67-69): C_0 = g^ξ,
/// C_1 = D_1 ⊕ k_1 ‖ ... ‖ D_{b_Λ} ⊕ k_{b_Λ}, exactly 32·b_Λ bytes, and C_2 = (c, v), a Schnorr
/// proof of knowledge of ξ. Eq. (70) hashes C_2 as b(C_2, 64) = b(c, 32) ‖ b(v, 32).
/// </summary>
public class EncryptedContestData
{
    /// <summary>C_0 = α = g^ξ mod p (eq. 67).</summary>
    public required IntegerModP C0 { get; init; }

    /// <summary>C_1 (eq. 68): 32·b_Λ bytes, b_Λ being the manifest's <see cref="Contest.ContestDataBlocks"/>.</summary>
    public required byte[] C1 { get; init; }

    /// <summary>c of C_2 (eq. 69).</summary>
    public required IntegerModQ Challenge { get; init; }

    /// <summary>v = (u - c·ξ) mod q of C_2.</summary>
    public required IntegerModQ Response { get; init; }
}

/// <summary>
/// The hashed ElGamal encryption of a contest data field (§3.3.10, eqs. 63-69) and the derivations
/// that its decryption (§3.6.6, eqs. 104-106) and Verification 12 (12.3, 12.4, 12.C) repeat. The
/// encryptor, the guardians, the administrator and the verifier all compute these here, so that no
/// two of them can encode an input differently. The §5.5.3 table (p.76) fixes every layout:
/// <list type="bullet">
/// <item>eq. (64): ξ = H_q(H_I; 0x25, ind_c(Λ), ξ_B), B1 = 0x25 ‖ b(ind_c, 4) ‖ b(ξ_B, 32), 37 bytes;</item>
/// <item>eq. (65): h = H(H_I; 0x26, ind_c(Λ), α, β), B1 = 0x26 ‖ b(ind_c, 4) ‖ b(α, 512) ‖ b(β, 512), 1029 bytes;</item>
/// <item>eq. (66): k_i = HMAC(h, b(i, 4) ‖ Label ‖ 0x00 ‖ Context ‖ b(b_Λ·256, 4)) for 1 &lt;= i &lt;= b_Λ,
/// with Label = "data_enc_keys" and Context = "contest_data" ‖ b(ind_c, 4) (p.40; the page image
/// shows the underscores). The counter i counts blocks from 1 (user decision Q6: Verification 13.7's
/// 0 &lt;= l &lt; b_Λ is an erratum), and the length field is the whole key stream's length in bits,
/// the same for every block;</item>
/// <item>eq. (69): c = H_q(H_I; 0x27, ind_c(Λ), a, C_0, C_1), B1 = 0x27 ‖ b(ind_c, 4) ‖ b(a, 512) ‖
/// b(C_0, 512) ‖ C_1, 1029 + 32·b_Λ bytes.</item>
/// </list>
/// The known-answer tests (test/kat, families contest_data_*) pin every one of these.
/// </summary>
public static class ContestDataEncryption
{
    /// <summary>The KDF label of eq. (66): b("data_enc_keys", 13), the UTF-8 bytes with no length prefix.</summary>
    private static ReadOnlySpan<byte> Label => "data_enc_keys"u8;

    /// <summary>The fixed part of the KDF context of eq. (66): b("contest_data", 12).</summary>
    private static ReadOnlySpan<byte> ContextPrefix => "contest_data"u8;

    /// <summary>Bytes of one block D_i, C_{1,i} and key k_i.</summary>
    public const int BlockBytes = 32;

    /// <summary>Eq. (64): the encryption nonce ξ = H_q(H_I; 0x25, ind_c(Λ), ξ_B).</summary>
    public static IntegerModQ Nonce(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, int contestIndex, BallotNonce ballotNonce)
    {
        // b(ξ_B, 32): the ballot nonce is a 256-bit value, hashed as drawn, never reduced mod q.
        byte[] nonce = ballotNonce;
        if (nonce is null || nonce.Length != 32)
        {
            throw new ArgumentException("The ballot nonce ξ_B is 32 bytes (§3.3.3).", nameof(ballotNonce));
        }

        Span<byte> message = stackalloc byte[1 + sizeof(int) + 32];
        message[0] = 0x25;
        BinaryPrimitives.WriteInt32BigEndian(message.Slice(1, sizeof(int)), contestIndex);
        nonce.AsSpan().CopyTo(message[(1 + sizeof(int))..]);
        return EGHash.HashModQConcatenated(selectionEncryptionIdentifierHash, message);
    }

    /// <summary>
    /// Eq. (65), and (12.3) on the decryption side: h = H(H_I; 0x26, ind_c(Λ), α, β), with α = C_0
    /// and β = K-hat^ξ (encryption) or the combined decryption β = C_0^ŝ (eq. 97).
    /// </summary>
    public static byte[] SecretKey(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, int contestIndex, IntegerModP alpha, IntegerModP beta)
    {
        const int length = 1 + sizeof(int) + 2 * IntegerModP.ByteLength;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x26;
            BinaryPrimitives.WriteInt32BigEndian(message.Slice(1, sizeof(int)), contestIndex);
            alpha.WriteBigEndian(message.Slice(1 + sizeof(int), IntegerModP.ByteLength));
            beta.WriteBigEndian(message.Slice(1 + sizeof(int) + IntegerModP.ByteLength, IntegerModP.ByteLength));
            var h = new byte[EGHash.HashBytes];
            EGHash.HashConcatenated(selectionEncryptionIdentifierHash, message, h);
            return h;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Eq. (66), and (104)/(12.4) on the decryption side: the key k_i for block
    /// <paramref name="blockNumber"/> (1-based, 1 &lt;= i &lt;= b_Λ) of a field of
    /// <paramref name="blocks"/> = b_Λ blocks, written into <paramref name="destination"/> (32 bytes).
    /// </summary>
    public static void BlockKey(byte[] secretKey, int contestIndex, int blocks, int blockNumber, Span<byte> destination)
    {
        if (blocks < 1 || blocks >= Contest.ContestDataBlocksLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(blocks), blocks, "b_Λ satisfies 1 <= b_Λ < 2^24 (§3.3.10 p.40).");
        }

        if (blockNumber < 1 || blockNumber > blocks)
        {
            throw new ArgumentOutOfRangeException(nameof(blockNumber), blockNumber, $"The block counter i runs over 1..b_Λ = 1..{blocks} (eq. 66).");
        }

        // b(i, 4) ‖ Label ‖ 0x00 ‖ "contest_data" ‖ b(ind_c, 4) ‖ b(b_Λ·256, 4): 38 bytes.
        Span<byte> message = stackalloc byte[sizeof(int) + 13 + 1 + 12 + sizeof(int) + sizeof(int)];
        int offset = 0;
        BinaryPrimitives.WriteInt32BigEndian(message.Slice(offset, sizeof(int)), blockNumber);
        offset += sizeof(int);
        Label.CopyTo(message[offset..]);
        offset += Label.Length;
        message[offset++] = 0x00;
        ContextPrefix.CopyTo(message[offset..]);
        offset += ContextPrefix.Length;
        BinaryPrimitives.WriteInt32BigEndian(message.Slice(offset, sizeof(int)), contestIndex);
        offset += sizeof(int);

        // b_Λ < 2^24, so b_Λ·256 < 2^32: an unsigned 4-byte field.
        BinaryPrimitives.WriteUInt32BigEndian(message.Slice(offset, sizeof(int)), (uint)blocks * 256u);

        if (secretKey is null || secretKey.Length != EGHash.HashBytes)
        {
            throw new ArgumentException("The secret key h is a 32-byte hash (eq. 65).", nameof(secretKey));
        }

        HMACSHA256.HashData(secretKey, message, destination[..BlockBytes]);
    }

    /// <summary>
    /// Eqs. (68) and (106): <paramref name="input"/> XOR k_1 ‖ ... ‖ k_{b_Λ}, block by block, the key
    /// stream derived from <paramref name="secretKey"/>. Encrypts D into C_1 and decrypts C_1 into D.
    /// <paramref name="input"/> must be exactly 32·<paramref name="blocks"/> bytes.
    /// </summary>
    public static byte[] Apply(byte[] secretKey, int contestIndex, int blocks, ReadOnlySpan<byte> input)
    {
        if (input.Length != BlockBytes * blocks)
        {
            throw new ArgumentException($"A contest data field of b_Λ = {blocks} blocks is exactly {BlockBytes * blocks} bytes; got {input.Length} (§3.3.10).", nameof(input));
        }

        var output = new byte[input.Length];
        Span<byte> key = stackalloc byte[BlockBytes];
        for (int i = 1; i <= blocks; i++)
        {
            BlockKey(secretKey, contestIndex, blocks, i, key);
            var block = input.Slice((i - 1) * BlockBytes, BlockBytes);
            var target = output.AsSpan((i - 1) * BlockBytes, BlockBytes);
            for (int b = 0; b < BlockBytes; b++)
            {
                target[b] = (byte)(block[b] ^ key[b]);
            }
        }

        return output;
    }

    /// <summary>Eq. (69): c = H_q(H_I; 0x27, ind_c(Λ), a, C_0, C_1).</summary>
    public static IntegerModQ ProofChallenge(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, int contestIndex, IntegerModP commitment, IntegerModP c0, byte[] c1)
    {
        int length = 1 + sizeof(int) + 2 * IntegerModP.ByteLength + c1.Length;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> message = buffer.AsSpan(0, length);
            message[0] = 0x27;
            int offset = 1;
            BinaryPrimitives.WriteInt32BigEndian(message.Slice(offset, sizeof(int)), contestIndex);
            offset += sizeof(int);
            commitment.WriteBigEndian(message.Slice(offset, IntegerModP.ByteLength));
            offset += IntegerModP.ByteLength;
            c0.WriteBigEndian(message.Slice(offset, IntegerModP.ByteLength));
            offset += IntegerModP.ByteLength;
            c1.CopyTo(message[offset..]);
            return EGHash.HashModQConcatenated(selectionEncryptionIdentifierHash, message);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// §3.6.6 p.49-50, the check each guardian makes before it computes a partial decryption: parse
    /// C_2 = (c, v), compute a = g^v·C_0^c and confirm c = H_q(H_I; 0x27, ind_c(Λ), a, C_0, C_1)
    /// (eq. 69). The values are all public.
    /// </summary>
    public static bool ProofHolds(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, int contestIndex, EncryptedContestData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.C1 is null)
        {
            return false;
        }

        var commitment = MontgomeryModP.PowModP(EGParameters.G, data.Response) * MontgomeryModP.PowModP(data.C0, data.Challenge);
        return ProofChallenge(selectionEncryptionIdentifierHash, contestIndex, commitment, data.C0, data.C1) == data.Challenge;
    }

    /// <summary>
    /// §3.3.10: encrypts the contest data field <paramref name="data"/> (D_Λ, exactly 32·b_Λ bytes)
    /// of the contest with index <paramref name="contestIndex"/> to the ballot data encryption key
    /// K-hat, with ξ from eq. (64) and a Schnorr proof of knowledge of ξ under a fresh random u
    /// (<paramref name="proofNonce"/> only in tests).
    /// </summary>
    internal static EncryptedContestData Encrypt(
        ReadOnlySpan<byte> data,
        int contestIndex,
        int blocks,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash,
        BallotNonce ballotNonce,
        IntegerModP otherBallotDataEncryptionKey,
        IntegerModQ? proofNonce = null)
    {
        // ξ, u and their powers are secret: full-width exponents of Z_q on the constant-time path.
        var xi = Nonce(selectionEncryptionIdentifierHash, contestIndex, ballotNonce);
        var alpha = MontgomeryModP.PowModP(EGParameters.G, xi);
        var beta = MontgomeryModP.PowModP(otherBallotDataEncryptionKey, xi);
        var secretKey = SecretKey(selectionEncryptionIdentifierHash, contestIndex, alpha, beta);
        var c1 = Apply(secretKey, contestIndex, blocks, data);

        var u = proofNonce ?? ElectionGuardRandom.GetIntegerModQ();
        var commitment = MontgomeryModP.PowModP(EGParameters.G, u);
        var challenge = ProofChallenge(selectionEncryptionIdentifierHash, contestIndex, commitment, alpha, c1);

        return new EncryptedContestData
        {
            C0 = alpha,
            C1 = c1,
            Challenge = challenge,
            Response = u - challenge * xi,
        };
    }

    /// <summary>
    /// Eqs. (104)-(106), and Verification 12.3, 12.4 and 12.C: D = C_1 ⊕ k from the combined
    /// decryption β, with h = H(H_I; 0x26, ind_c(Λ), C_0, β).
    /// </summary>
    public static byte[] Decrypt(SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, int contestIndex, int blocks, EncryptedContestData data, IntegerModP beta)
    {
        ArgumentNullException.ThrowIfNull(data);
        var secretKey = SecretKey(selectionEncryptionIdentifierHash, contestIndex, data.C0, beta);
        return Apply(secretKey, contestIndex, blocks, data.C1);
    }
}
