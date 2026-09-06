using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.UnitTests.KeyGeneration;

public class GuardianIndexTests
{
    [Fact]
    public void EqualityOperator_SameIndex_ReturnsTrue()
    {
        var index1 = new GuardianIndex(1);
        var index2 = new GuardianIndex(1);

        Assert.True(index1 == index2);
        Assert.True(index1.Equals(index2));
    }

    [Fact]
    public void EqualityOperator_DifferentIndex_ReturnsFalse()
    {
        var index1 = new GuardianIndex(1);
        var index2 = new GuardianIndex(2);

        Assert.False(index1 == index2);
        Assert.False(index1.Equals(index2));
    }

    [Fact]
    public void InequalityOperator_BehavesAsExpected()
    {
        var index1 = new GuardianIndex(1);
        var index2 = new GuardianIndex(2);
        var index3 = new GuardianIndex(1);

        Assert.True(index1 != index2);
        Assert.False(index1 != index3);
    }

    [Fact]
    public void ImplicitConversion_ToByteArray_RoundTrips()
    {
        var index = new GuardianIndex(2);

        byte[] bytes = index;

        Assert.Equal(2.ToByteArray(), bytes);
    }

    [Fact]
    public void ImplicitConversion_ToInt_RoundTrips()
    {
        var index = new GuardianIndex(3);

        int value = index;

        Assert.Equal(3, value);
    }

    [Fact]
    public void GetHashCode_IsConsistentWithEquals()
    {
        var index1 = new GuardianIndex(1);
        var index2 = new GuardianIndex(1);

        Assert.Equal(index1.GetHashCode(), index2.GetHashCode());
    }
}
