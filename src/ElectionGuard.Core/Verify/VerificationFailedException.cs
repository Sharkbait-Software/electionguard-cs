namespace ElectionGuard.Core.Verify;

public class VerificationFailedException : Exception
{
    public string SubSection { get; private set; }

    public VerificationFailedException(string subSection, string? message) : base(message)
    {
        SubSection = subSection;
    }
}