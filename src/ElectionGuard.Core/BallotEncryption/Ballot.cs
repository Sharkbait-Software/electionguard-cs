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
    public required List<BallotChoice> Choices { get; init; }
    public required int NumWriteinsSelected { get; init; }
    public string? ContestData { get; init; }
}

public record BallotChoice
{
    public required string Id { get; init; }
    public required int SelectionValue { get; set; }
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