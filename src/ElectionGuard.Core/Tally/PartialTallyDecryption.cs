using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;

namespace ElectionGuard.Core.Tally;

public class PartialTallyDecryption
{
    public required GuardianIndex GuardianIndex { get; init; }
    public required Dictionary<string, PartialTallyContestDecryption> Contests { get; init; }

    public class PartialTallyContestDecryption
    {
        public required Dictionary<string, PartialTallyChoiceDecryption> Choices { get; init; }
    }

    public class PartialTallyChoiceDecryption
    {
        public required IntegerModP Mi { get; init; }
    }
}