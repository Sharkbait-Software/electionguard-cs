namespace ElectionGuard.Core.Serialization;

/// <summary>
/// A published value whose byte encoding is not the canonical fixed-width one: an element of Z_p
/// that is not exactly 512 bytes holding a value below p, an element of Z_q that is not exactly 32
/// bytes holding a value below q, a selection encryption identifier or hash value that is not
/// exactly 32 bytes (§5.1.1, §5.1.2, eq. 32), an encryption timestamp not in its one written form,
/// or a required scalar part of a ballot (an id, a label, H_I, a contest data C_1) that the document
/// leaves out or nulls (S10a).
///
/// The reducing constructors of <see cref="Crypto.IntegerModP"/> and <see cref="Crypto.IntegerModQ"/>
/// would silently turn alpha + p into alpha, or c + q into c, which makes the 0 &lt;= x &lt; p and
/// 0 &lt;= x &lt; q halves of Verifications 2.A/2.B, 6.A-6.C and 7.A-7.C unenforceable on anything
/// read from a record. The deserializers therefore decode through the strict
/// <c>FromCanonicalBytes</c> paths, which throw this instead.
///
/// It is reported as a deserialization error, not as a verification sub-section, because the
/// decoder cannot know which check a value feeds (one alpha enters 6.A, 7.A and Verification 9),
/// and because once decoded, the in-memory types can hold only canonical values, so the range
/// halves of those checks are invariants of the types rather than something left to verify. A
/// record that does not decode does not verify.
/// </summary>
public class NonCanonicalEncodingException : FormatException
{
    public NonCanonicalEncodingException(string message) : base(message)
    {
    }
}
