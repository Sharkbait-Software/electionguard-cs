using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.KeyGeneration;

public class SchnorrProofTests
{
    public SchnorrProofTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    [Fact]
    public void Equals_SameChallengeAndSameResponsesArrayReference_ReturnsTrue()
    {
        var responses = new[] { new IntegerModQ(1), new IntegerModQ(2) };
        var challenge = new IntegerModQ(3);

        var proof1 = new SchnorrProof { Challenge = challenge, Responses = responses };
        var proof2 = new SchnorrProof { Challenge = challenge, Responses = responses };

        Assert.Equal(proof1, proof2);
        Assert.True(proof1 == proof2);
    }

    [Fact]
    public void Equals_DifferentChallenge_ReturnsFalse()
    {
        var responses = new[] { new IntegerModQ(1), new IntegerModQ(2) };

        var proof1 = new SchnorrProof { Challenge = new IntegerModQ(3), Responses = responses };
        var proof2 = new SchnorrProof { Challenge = new IntegerModQ(4), Responses = responses };

        Assert.NotEqual(proof1, proof2);
        Assert.False(proof1 == proof2);
    }

    // Quirk-pinning test: SchnorrProof is a record, so its compiler-generated Equals compares the
    // Responses field (IntegerModQ[]) with the default equality comparer for arrays -- arrays do
    // not override Equals, so this is reference equality, not element-wise value equality. Two
    // proofs with the same Challenge and equal-valued-but-distinctly-allocated Responses arrays
    // are therefore NOT equal via record equality. This pins actual behavior rather than the
    // (plausible but incorrect) assumption that record equality is deep for array fields.
    [Fact]
    public void Equals_SameValuesButDifferentResponsesArrayInstances_ReturnsFalse()
    {
        var challenge = new IntegerModQ(3);

        var proof1 = new SchnorrProof { Challenge = challenge, Responses = new[] { new IntegerModQ(1), new IntegerModQ(2) } };
        var proof2 = new SchnorrProof { Challenge = challenge, Responses = new[] { new IntegerModQ(1), new IntegerModQ(2) } };

        Assert.NotEqual(proof1, proof2);
    }
}
