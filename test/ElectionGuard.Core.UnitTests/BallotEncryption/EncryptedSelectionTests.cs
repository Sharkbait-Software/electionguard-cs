using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.UnitTests.BallotEncryption;

public class EncryptedSelectionTests
{
    public EncryptedSelectionTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static EncryptedSelection CreateSampleSelection()
    {
        return new EncryptedSelection
        {
            ChoiceId = "choice-1",
            Alpha = new IntegerModP(7),
            Beta = new IntegerModP(11),
            EncryptionNonce = new IntegerModQ(13),
            Proofs = new[]
            {
                new ChallengeResponsePair { Challenge = new IntegerModQ(1), Response = new IntegerModQ(2) },
                new ChallengeResponsePair { Challenge = new IntegerModQ(3), Response = new IntegerModQ(4) },
            },
        };
    }

    [Fact]
    public void ImplicitConversion_EncryptedValueWithProofsToEncryptedValue_PreservesAlphaBeta()
    {
        var selection = CreateSampleSelection();

        EncryptedValue converted = selection;

        Assert.Equal(selection.Alpha, converted.Alpha);
        Assert.Equal(selection.Beta, converted.Beta);
        Assert.Equal(selection.EncryptionNonce, converted.EncryptionNonce);

        // Secondary observable: a selection built from a *different* Alpha/Beta must convert to a
        // distinguishable EncryptedValue rather than the conversion collapsing to a fixed result.
        var otherSelection = selection with { Alpha = new IntegerModP(99) };
        EncryptedValue otherConverted = otherSelection;
        Assert.NotEqual(converted.Alpha, otherConverted.Alpha);
    }

    [Fact]
    public void ToEncryptedValue_ReturnsEquivalentEncryptedValue()
    {
        var selection = CreateSampleSelection();

        var converted = selection.ToEncryptedValue();

        Assert.Equal(selection.Alpha, converted.Alpha);
        Assert.Equal(selection.Beta, converted.Beta);
        Assert.Equal(selection.EncryptionNonce, converted.EncryptionNonce);

        // The named method and the implicit operator must agree on the same input.
        EncryptedValue viaImplicitConversion = selection;
        Assert.Equal(viaImplicitConversion, converted);
    }
}
