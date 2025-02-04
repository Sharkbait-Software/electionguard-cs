using ElectionGuard.Core.Crypto;

namespace ElectionGuard.Core.KeyGeneration;

public record SchnorrProof
{
    public required IntegerModQ Challenge { get; init; }
    public required IntegerModQ[] Responses { get; init; }
}