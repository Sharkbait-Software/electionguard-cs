namespace ElectionGuard.Core.BallotEncryption;

public record Ballot
{
    public required string Id { get; init; }
    public required string BallotStyleId { get; init; }
    public required List<BallotContest> Contests { get; init; }
}

public record BallotContest
{
    public required string Id { get; init; }
    /// <summary>The voter's selection for each selectable option of the contest.</summary>
    public required List<BallotChoice> Choices { get; init; }

    /// <summary>
    /// The number of the contest's write-in fields the voter used: 0 (the default) up to the
    /// manifest's <see cref="Models.Contest.WriteInFieldCount"/>. The supplemental fields
    /// (§3.3.9) are not given here: the encryptor derives every one the contest declares from the
    /// selections and this number.
    /// </summary>
    public int NumWriteinsSelected { get; init; }

    /// <summary>
    /// The contest data field D_Λ (§3.3.10): exactly 32·b_Λ raw bytes, b_Λ being the manifest's
    /// <see cref="Models.Contest.ContestDataBlocks"/> for the contest (user decision Q7), filled
    /// unambiguously by the caller; <see cref="ContestDataEncoding.Encode"/> builds one from a string.
    /// Null for none: in a contest that declares contest data the encryptor then encrypts 32·b_Λ zero
    /// bytes (the encoding of the empty string), so every ballot carries the field and its presence
    /// reveals nothing. A contest that declares no contest data (b_Λ = 0) must leave this null.
    /// </summary>
    public byte[]? ContestData { get; init; }
}

public record BallotChoice
{
    public required string Id { get; init; }
    public required int SelectionValue { get; set; }
}

/// <summary>
/// A plaintext ballot the encryptor refuses: a contest listed twice or not in the manifest, a
/// contest that does not list exactly the manifest's options, a negative selection value, a number
/// of write-ins outside [0, the contest's write-in field count], contest data in a contest that
/// declares none or of a length other than 32·b_Λ, or a ballot that does not list exactly its
/// ballot style's contests. (A selection above the option selection limit is not
/// refused: it overvotes the contest, §3.3.5.)
/// </summary>
public class InvalidBallotException : ArgumentException
{
    public InvalidBallotException(string message) : base(message)
    {
    }
}

//public class Ballot
//{
//    public Ballot(IntegerModP electionPublicKey)
//    {
//        _electionPublicKey = electionPublicKey;
//    }

//    private IntegerModP _electionPublicKey;

//    public EncryptedSelection EncryptSelection(int voteWeight, IntegerModQ selectionNonce)
//    {
//        IntegerModP alpha = IntegerModP.PowModP(EGParameters.CryptographicParameters.G, selectionNonce);
//        IntegerModP beta = IntegerModP.PowModP(_electionPublicKey, selectionNonce + voteWeight);

//        return new EncryptedSelection
//        {
//            Alpha = alpha,
//            Beta = beta,
//        };
//    }

//    public int DecryptSelection(EncryptedSelection selection, IntegerModQ selectionNonce, int maxWeight)
//    {
//        var publicKeyPow = selection.Beta / IntegerModP.PowModP(_electionPublicKey, selectionNonce);

//        for (int i = 0; i <= maxWeight; i++)
//        {
//            IntegerModP p = IntegerModP.PowModP(_electionPublicKey, new IntegerModQ(i));
//            if (publicKeyPow == p)
//            {
//                return i;
//            }
//        }

//        throw new Exception("Could not decrypt selection");
//    }
//}

//public class EncryptedSelection
//{
//    public required IntegerModP Alpha { get; init; }
//    public required IntegerModP Beta { get; init; }
//}