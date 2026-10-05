using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;

namespace ElectionGuard.Testing.Common;

/// <summary>
/// Finds a contest's supplemental field encryption by kind, for contests whose manifest was built
/// with <see cref="ElectionFixtureBuilder.SupplementalFields"/> (which labels each kind with
/// <see cref="ElectionFixtureBuilder.SupplementalFieldId"/>).
/// </summary>
public static class SupplementalFieldExtensions
{
    public static EncryptedSupplementalField Field(this EncryptedContest contest, SupplementalFieldKind kind)
    {
        var id = ElectionFixtureBuilder.SupplementalFieldId(kind);
        return contest.SupplementalFields.Single(field => field.FieldId == id);
    }

    /// <summary>
    /// <paramref name="value"/>'s ciphertext and proofs as a supplemental field of each of
    /// <paramref name="kinds"/>, labelled as the fixtures label them: placeholder fields for
    /// hand-built ballots.
    /// </summary>
    public static List<EncryptedSupplementalField> AsFields(this EncryptedValueWithProofs value, params SupplementalFieldKind[] kinds)
    {
        return kinds.Select(kind => new EncryptedSupplementalField
        {
            FieldId = ElectionFixtureBuilder.SupplementalFieldId(kind),
            Alpha = value.Alpha,
            Beta = value.Beta,
            Proofs = value.Proofs,
        }).ToList();
    }

    /// <summary>A copy of <paramref name="contest"/> with the field of <paramref name="kind"/> replaced.</summary>
    public static EncryptedContest WithField(this EncryptedContest contest, SupplementalFieldKind kind, EncryptedSupplementalField replacement)
    {
        var id = ElectionFixtureBuilder.SupplementalFieldId(kind);
        return contest with
        {
            SupplementalFields = contest.SupplementalFields.Select(field => field.FieldId == id ? replacement : field).ToList(),
        };
    }
}
