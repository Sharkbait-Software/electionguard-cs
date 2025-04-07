using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Core.Verify.Ballot;

/// <summary>
/// Verification 5 (Uniqueness of selection encryption identifiers)
/// </summary>
public class SelectionEncryptionIdentifierVerification
{
    public void Verify(List<SelectionEncryptionIdentifier> identifiers)
    {
        HashSet<SelectionEncryptionIdentifier> hashSet = new HashSet<SelectionEncryptionIdentifier>(identifiers);

        if (hashSet.Count != identifiers.Count)
        {
            var duplicateIdentifiers = identifiers.GroupBy(x => x).Where(x => x.Count() > 1).ToList();
            throw new VerificationFailedException("5.A", $"Duplicate selection encryption identifier detected. {string.Join(",", duplicateIdentifiers)}");
        }
    }

    public void Verify(SelectionEncryptionIdentifier identifier, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, ExtendedBaseHash extendedBaseHash)
    {
        var expected = EGHash.Hash(extendedBaseHash,
            [0x20],
            identifier);

        if (expected != (byte[])selectionEncryptionIdentifierHash)
        {
            throw new VerificationFailedException("5.B", "Selection encryption identifier hash was not calculated correctly.");
        }
    }
}
