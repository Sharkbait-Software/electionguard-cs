using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;

namespace ElectionGuard.Core.Verify.PreEncryption;

/// <summary>
/// Verification 17 (Validation of short codes in pre-encrypted ballots) over every selectable
/// option of a pre-encrypted ballot, null vectors included. That each selection hash matches its
/// pre-encryption vector is 16.A.
/// </summary>
public class ShortCodeVerification
{
    public void Verify(PreEncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        // §4.1.5: Ω must be specified in the manifest so that a verifier can match it.
        var hashTrimmingFunction = encryptionRecord.Manifest.HashTrimmingFunction
            ?? throw new VerificationFailedException("17.A", $"The manifest specifies no hash-trimming function, so the short codes on ballot {ballot.Id} cannot be checked.");

        foreach (var contest in ballot.Contests)
        {
            foreach (var selection in contest.Selections)
            {
                // 17.A: omega = Ω(psi).
                var expectedShortCode = HashTrimming.Trim(hashTrimmingFunction, selection.SelectionHash);
                if (expectedShortCode != selection.ShortCode)
                {
                    throw new VerificationFailedException("17.A", $"Short code {selection.ShortCode} for ballot {ballot.Id}, contest {contest.ContestId}, selection index {selection.SelectionIndex} does not match its selection hash; expected {expectedShortCode}.");
                }
            }
        }
    }
}
