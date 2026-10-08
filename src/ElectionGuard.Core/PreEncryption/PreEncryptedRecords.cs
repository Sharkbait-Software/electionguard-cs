using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.PreEncryption;

/// <summary>
/// The pre-encryption part of one contest of a cast pre-encrypted ballot's record (§4.3.1, §4.4). It
/// rides on the ballot's <see cref="EncryptedBallot.PreEncryptedContests"/>; the contest's standard
/// part (the combined selection vector with its proofs, and the contest hash χ of eq. 115) is the
/// ballot's <see cref="EncryptedContest"/> of the same label.
///
/// It carries what §4.4 lists for a cast ballot beyond the standard data: "the selection hashes for
/// every option on the ballot (including null options) – sorted numerically within each contest" and
/// "the short codes and pre-encryption selection vectors associated with all selectable options
/// (including null options) on the ballot made by the voter". Nothing in it says which option a
/// selected vector stands for: that would publish the vote.
/// </summary>
public record PreEncryptedCastContest
{
    /// <summary>The contest's label; the ballot's <see cref="EncryptedContest.Id"/> of the same contest.</summary>
    public required string ContestId { get; init; }

    /// <summary>
    /// All m + L selection hashes of the contest (eqs. 113, 114), options and null vectors alike,
    /// in strictly increasing numerical order (§4.4; big-endian, §4.1.2). Verification 16.B hashes
    /// them into χ (eq. 115).
    /// </summary>
    public required List<SelectionHash> SelectionHashes { get; init; }

    /// <summary>
    /// The L pre-encryption vectors the recording tool combined (§4.3): one per option the voter
    /// selected, padded with the contest's first null vectors to L, so that the record does not show
    /// an undervote (§4.1.5 "the use of null short codes allows the election record to not reveal
    /// undervotes"). Listed in increasing order of their selection hashes, so that their order says
    /// nothing either. Their componentwise product is the contest's combined vector (Verification 15).
    /// </summary>
    public required List<PreEncryptedCastSelection> SelectedVectors { get; init; }
}

/// <summary>
/// One pre-encryption vector Ψ chosen by the voter (or a null vector padding the selection), as a
/// cast ballot's record publishes it (§4.3.1): its m encryptions, its selection hash ψ and its short
/// code ω = Ω(ψ). Never its nonces, and never the option it stands for.
/// </summary>
public record PreEncryptedCastSelection
{
    /// <summary>The m encryptions (α_k, β_k) in option position order (eq. 112).</summary>
    public required IReadOnlyList<EncryptedValue> Vector { get; init; }

    /// <summary>ψ = H(H_I; 0x40, α_1, β_1, ..., α_m, β_m) (eqs. 113, 114; Verification 16.A).</summary>
    public required SelectionHash SelectionHash { get; init; }

    /// <summary>ω = Ω(ψ) (§4.1.5; Verification 17.A).</summary>
    public required ShortCode ShortCode { get; init; }
}

/// <summary>
/// The election record of an uncast (spoiled or challenged) pre-encrypted ballot (§4.3, §4.3.1,
/// §4.4): the whole pre-encrypted ballot -- every pre-encryption vector, selection hash and short
/// code, under its option label -- and the encryption nonces ξ_{i,j,k} (eq. 121) that open every
/// encryption on it, which is what Verification 18 checks the ballot with. Verification 19 checks
/// its labels against the manifest.
///
/// §4.4 also says the ballot nonce ξ_B "is published"; §4.3 and Verification 18 release the
/// encryption nonces instead, which "enables selective decryption of specific contests". The
/// record therefore always holds the nonces and holds ξ_B only when the recording tool (out of this
/// library's scope, user decision Q35) chose to release it; when it is present Verification 18
/// also checks that every released nonce derives from it.
/// </summary>
public record PreEncryptedUncastBallot
{
    /// <summary>The pre-encrypted ballot as the encrypting tool produced it (§4.2).</summary>
    public required PreEncryptedBallot Ballot { get; init; }

    /// <summary>The ballot nonce ξ_B (§4.4), 32 bytes as the device drew them, or null when it is not released.</summary>
    public BallotNonce? BallotNonce { get; init; }

    /// <summary>The released encryption nonces, one entry per contest of <see cref="Ballot"/>, in its order.</summary>
    public required List<PreEncryptedReleasedContest> Contests { get; init; }
}

/// <summary>The released encryption nonces of one contest of an uncast pre-encrypted ballot.</summary>
public record PreEncryptedReleasedContest
{
    public required string ContestId { get; init; }

    /// <summary>One entry per selection vector of the contest (options, then null vectors), in the ballot's order.</summary>
    public required List<PreEncryptedReleasedSelection> Selections { get; init; }
}

/// <summary>The released nonces ξ_{i,j,1..m} of one selection vector j (eq. 121).</summary>
public record PreEncryptedReleasedSelection
{
    /// <summary>j, the vector's <see cref="PreEncryptedSelection.SelectionIndex"/>.</summary>
    public required int SelectionIndex { get; init; }

    /// <summary>ξ_{i,j,k} for k = 1..m, the nonce of the vector's k-th encryption.</summary>
    public required List<IntegerModQ> Nonces { get; init; }
}
