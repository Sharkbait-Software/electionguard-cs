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

    /// <summary>
    /// Verification 17 for a cast pre-encrypted ballot's record: "for cast ballots, this includes all
    /// short codes that are published in the election record whose associated selection hashes
    /// correspond to selection vectors that are accumulated to form tallies", that is, the short code
    /// of every selected vector (null vectors padding an undervote included). The structure is
    /// checked first ("17.structure", <see cref="BallotStructure.RequirePreEncryptedCast"/>); that
    /// each hash matches its vector is 16.A.
    /// </summary>
    public void Verify(BallotEncryption.EncryptedBallot ballot, EncryptionRecord encryptionRecord)
    {
        ArgumentNullException.ThrowIfNull(ballot);
        ArgumentNullException.ThrowIfNull(encryptionRecord);

        BallotStructure.RequirePreEncryptedCast(ballot, encryptionRecord.Manifest, 17);
        var hashTrimmingFunction = encryptionRecord.Manifest.HashTrimmingFunction!.Value;

        foreach (var contest in ballot.PreEncryptedContests!)
        {
            foreach (var selected in contest.SelectedVectors)
            {
                // 17.A: omega = Ω(psi).
                var expectedShortCode = HashTrimming.Trim(hashTrimmingFunction, selected.SelectionHash);
                if (expectedShortCode != selected.ShortCode)
                {
                    throw new VerificationFailedException("17.A", $"Short code {selected.ShortCode} of a selected vector of ballot {ballot.Id}, contest {contest.ContestId}, does not match its selection hash {selected.SelectionHash}; expected {expectedShortCode}.");
                }
            }
        }
    }
}
