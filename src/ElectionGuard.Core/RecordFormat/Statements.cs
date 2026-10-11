using ElectionGuard.Core.Models;
using ElectionGuard.Core.RecordFormat.Mappers;
using ElectionGuard.Core.Verify;
using Google.Protobuf;
using System.Security.Cryptography;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat;

/// <summary>
/// A signed statement (design §4.9): the canonical <c>RecordItem</c> bytes of a statement exactly as
/// signed, the algorithm, the signer's key id and (optionally) public key, the signature, and an
/// optional RFC 3161 token. Stored as a <c>device_attestation</c> (statements 40-42, inside R_sealed)
/// or a detached <c>record_signature</c> (statement 43, outside every root).
/// </summary>
public sealed record SignedStatement(ReadOnlyMemory<byte> Statement, string Algorithm, ReadOnlyMemory<byte> KeyId, ReadOnlyMemory<byte> SignerKey, ReadOnlyMemory<byte> Signature, ReadOnlyMemory<byte> TimestampToken = default)
{
    internal Pb.SignedStatement ToMessage() => new()
    {
        Statement = ByteString.CopyFrom(Statement.Span),
        Algorithm = Algorithm,
        KeyId = ByteString.CopyFrom(KeyId.Span),
        SignerKey = ByteString.CopyFrom(SignerKey.Span),
        Signature = ByteString.CopyFrom(Signature.Span),
        TimestampToken = ByteString.CopyFrom(TimestampToken.Span),
    };

    internal static SignedStatement FromMessage(Pb.SignedStatement signed) =>
        new(signed.Statement.ToByteArray(), signed.Algorithm, signed.KeyId.ToByteArray(), signed.SignerKey.ToByteArray(), signed.Signature.ToByteArray(), signed.TimestampToken.ToByteArray());

    /// <summary>The canonical <c>RecordItem{device_attestation}</c> bytes of this statement.</summary>
    public byte[] ToDeviceAttestationItem() => new Pb.RecordItem { DeviceAttestation = ToMessage() }.ToByteArray();

    /// <summary>The canonical <c>RecordItem{record_signature}</c> bytes of this statement.</summary>
    public byte[] ToRecordSignatureItem() => new Pb.RecordItem { RecordSignature = ToMessage() }.ToByteArray();

    /// <summary>SHA-256 of the statement, which orders attestations and names a signature's file.</summary>
    public Sha256Digest StatementDigest => Sha256Digest.Of(Statement.Span);
}

/// <summary>Signs a statement's canonical bytes (design §4.9: the algorithm applies its own digest).</summary>
public interface IStatementSigner
{
    /// <summary>The registry name, for example <see cref="SignatureAlgorithms.EcdsaP256Sha256"/>.</summary>
    string Algorithm { get; }

    ValueTask<SignedStatement> SignAsync(ReadOnlyMemory<byte> statement, CancellationToken ct = default);
}

/// <summary>
/// Checks signatures of one algorithm against the keys it was configured to trust (the trust
/// anchors). A key carried in the signed statement itself is never trusted on its own: a statement
/// signed by a key no anchor holds is <see cref="SignatureStatus.NotChecked"/>.
/// </summary>
public interface ISignatureVerifier
{
    string Algorithm { get; }

    /// <summary>
    /// A stable identity of the trust anchors this verifier holds (for example its sorted key ids):
    /// equal for two verifiers that accept exactly the same keys. A verifier checkpoint records it, so
    /// a run resumed under other trust anchors starts over instead of reusing verdicts reached under
    /// the old ones (design §6.8).
    /// </summary>
    string TrustAnchorsIdentity { get; }

    SignatureCheck Verify(SignedStatement signed);
}

/// <summary>The signature algorithm registry of design §4.9.</summary>
public static class SignatureAlgorithms
{
    /// <summary>ECDSA on P-256 with SHA-256, DER signatures (RFC 3279); mandatory to implement.</summary>
    public const string EcdsaP256Sha256 = "ecdsa-p256-sha256";

    public const string RsaPssSha256 = "rsa-pss-sha256";

    public const string Ed25519 = "ed25519";

    public const string X509CmsDetached = "x509-cms-detached";

    /// <summary>The key id this library gives a public key: SHA-256 of its DER SubjectPublicKeyInfo.</summary>
    public static byte[] KeyIdOf(ReadOnlySpan<byte> subjectPublicKeyInfo) => SHA256.HashData(subjectPublicKeyInfo);
}

/// <summary>
/// <c>ecdsa-p256-sha256</c> signing with a P-256 key: DER signatures (RFC 3279), the key id
/// SHA-256(SubjectPublicKeyInfo), and the public key carried as its DER SubjectPublicKeyInfo.
/// </summary>
public sealed class EcdsaP256Sha256Signer : IStatementSigner, IDisposable
{
    private readonly ECDsa _key;

    /// <summary>Signs with <paramref name="key"/>, which must be a P-256 key with its private part; the signer takes ownership.</summary>
    public EcdsaP256Sha256Signer(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        EcdsaP256Sha256Verifier.RequireP256(key);
        _key = key;
        SubjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
        KeyId = SignatureAlgorithms.KeyIdOf(SubjectPublicKeyInfo);
    }

    /// <summary>A signer with a freshly generated P-256 key.</summary>
    public static EcdsaP256Sha256Signer Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    public string Algorithm => SignatureAlgorithms.EcdsaP256Sha256;

    /// <summary>The public key, DER SubjectPublicKeyInfo: what a verifier is configured with.</summary>
    public byte[] SubjectPublicKeyInfo { get; }

    public byte[] KeyId { get; }

    public ValueTask<SignedStatement> SignAsync(ReadOnlyMemory<byte> statement, CancellationToken ct = default)
    {
        byte[] signature = _key.SignData(statement.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return ValueTask.FromResult(new SignedStatement(statement.ToArray(), Algorithm, KeyId, SubjectPublicKeyInfo, signature));
    }

    public void Dispose() => _key.Dispose();
}

/// <summary>
/// <c>ecdsa-p256-sha256</c> verification against trusted P-256 public keys (DER
/// SubjectPublicKeyInfo). A statement names its key by key id; a key the verifier does not hold
/// leaves the signature <see cref="SignatureStatus.NotChecked"/>. Every key is checked to be on
/// P-256 (OID 1.2.840.10045.3.1.7), so a key of another curve cannot pass under this name.
/// </summary>
public sealed class EcdsaP256Sha256Verifier : ISignatureVerifier
{
    private const string P256Oid = "1.2.840.10045.3.1.7";

    private readonly Dictionary<string, byte[]> _trusted = new(StringComparer.Ordinal);

    public EcdsaP256Sha256Verifier(IEnumerable<ReadOnlyMemory<byte>> trustedSubjectPublicKeyInfos)
    {
        ArgumentNullException.ThrowIfNull(trustedSubjectPublicKeyInfos);
        foreach (var info in trustedSubjectPublicKeyInfos)
        {
            using var key = Import(info.Span) ?? throw new ArgumentException("A trusted key is not a P-256 SubjectPublicKeyInfo.", nameof(trustedSubjectPublicKeyInfos));
            _trusted[Convert.ToHexStringLower(SignatureAlgorithms.KeyIdOf(info.Span))] = info.ToArray();
        }
    }

    public string Algorithm => SignatureAlgorithms.EcdsaP256Sha256;

    /// <summary>The trusted key ids (SHA-256 of each SubjectPublicKeyInfo), lowercase hex, sorted and comma-separated.</summary>
    public string TrustAnchorsIdentity => string.Join(",", _trusted.Keys.Order(StringComparer.Ordinal));

    public SignatureCheck Verify(SignedStatement signed)
    {
        ArgumentNullException.ThrowIfNull(signed);
        string keyId = Convert.ToHexStringLower(signed.KeyId.Span);
        if (signed.Algorithm != Algorithm)
        {
            return new SignatureCheck(SignatureStatus.NotChecked, signed.Algorithm, keyId, $"This verifier checks {Algorithm}, not {signed.Algorithm}.");
        }

        if (!_trusted.TryGetValue(keyId, out var info))
        {
            return new SignatureCheck(SignatureStatus.NotChecked, signed.Algorithm, keyId, $"No trusted {Algorithm} key has id {keyId}: present, not checked.");
        }

        if (!signed.SignerKey.IsEmpty && !signed.SignerKey.Span.SequenceEqual(info))
        {
            return new SignatureCheck(SignatureStatus.Invalid, signed.Algorithm, keyId, $"The statement carries a public key that is not the trusted key with id {keyId}.");
        }

        using var key = Import(info)!;
        bool valid;
        try
        {
            valid = key.VerifyData(signed.Statement.Span, signed.Signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            valid = false;
        }

        return valid
            ? new SignatureCheck(SignatureStatus.Valid, signed.Algorithm, keyId, $"Signed by trusted key {keyId}.")
            : new SignatureCheck(SignatureStatus.Invalid, signed.Algorithm, keyId, $"The signature does not verify under trusted key {keyId}.");
    }

    internal static void RequireP256(ECDsa key)
    {
        var parameters = key.ExportParameters(false);
        if (parameters.Curve.Oid?.Value != P256Oid && parameters.Curve.Oid?.FriendlyName is not ("nistP256" or "ECDSA_P256"))
        {
            throw new ArgumentException("The key is not on P-256.", nameof(key));
        }
    }

    private static ECDsa? Import(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out int read);
            if (read != subjectPublicKeyInfo.Length)
            {
                key.Dispose();
                return null;
            }

            RequireP256(key);
            return key;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            key.Dispose();
            return null;
        }
    }
}

/// <summary>
/// The statements of design §4.9 as canonical <c>RecordItem</c> bytes, ready to sign: the device
/// chain-close attestation over codes_root (status-independent; under both chaining modes it fixes the
/// order and the count, S8b), the optional section seal over the section root, the optional prefix
/// checkpoint, and the record statement over a phase root (§3.7, "together with the date").
/// </summary>
public static class RecordStatements
{
    /// <summary>
    /// A <c>ChainCloseStatement</c>: H_E, the device key, S_device, the chaining mode, ℓ, codes_root
    /// over the ℓ confirmation codes in chain order, H̄ (simple chaining only) and when the chain closed.
    /// </summary>
    public static byte[] ChainClose(ExtendedBaseHash extendedBaseHash, DeviceKey device, string deviceId, ChainingMode chainingMode, long ballotCount, Sha256Digest codesRoot, ConfirmationCode? closingHash, DateTimeOffset? closedAt)
    {
        ArgumentNullException.ThrowIfNull(extendedBaseHash);
        ArgumentNullException.ThrowIfNull(deviceId);
        ArgumentOutOfRangeException.ThrowIfNegative(ballotCount);
        return new Pb.RecordItem
        {
            ChainCloseStatement = new Pb.ChainCloseStatement
            {
                HE = WireValues.Bytes(extendedBaseHash),
                DeviceKey = ByteString.CopyFrom(device.ToBytes()),
                DeviceId = deviceId,
                ChainingMode = (uint)chainingMode,
                BallotCount = (ulong)ballotCount,
                CodesRoot = ByteString.CopyFrom(codesRoot.ToArray()),
                ClosingHash = closingHash is { } hash ? WireValues.Bytes(hash) : ByteString.Empty,
                ClosedAt = closedAt is { } time ? WireValues.Time(time, "closed_at") : null,
            },
        }.ToByteArray();
    }

    /// <summary>A <c>SectionSealStatement</c>: H_E, the device key, the section's item count (ℓ + 2) and its root, which commits every byte of it (status, weight and time included).</summary>
    public static byte[] SectionSeal(ExtendedBaseHash extendedBaseHash, DeviceKey device, long itemCount, Sha256Digest sectionRoot)
    {
        ArgumentNullException.ThrowIfNull(extendedBaseHash);
        ArgumentOutOfRangeException.ThrowIfNegative(itemCount);
        return new Pb.RecordItem
        {
            SectionSealStatement = new Pb.SectionSealStatement
            {
                HE = WireValues.Bytes(extendedBaseHash),
                DeviceKey = ByteString.CopyFrom(device.ToBytes()),
                ItemCount = (ulong)itemCount,
                SectionRoot = ByteString.CopyFrom(sectionRoot.ToArray()),
            },
        }.ToByteArray();
    }

    /// <summary>A <c>PrefixCheckpointStatement</c>: the codes root of a device's first <paramref name="ballotCount"/> ballots, at <paramref name="at"/>.</summary>
    public static byte[] PrefixCheckpoint(ExtendedBaseHash extendedBaseHash, DeviceKey device, long ballotCount, Sha256Digest codesRoot, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(extendedBaseHash);
        ArgumentOutOfRangeException.ThrowIfNegative(ballotCount);
        return new Pb.RecordItem
        {
            PrefixCheckpointStatement = new Pb.PrefixCheckpointStatement
            {
                HE = WireValues.Bytes(extendedBaseHash),
                DeviceKey = ByteString.CopyFrom(device.ToBytes()),
                BallotCount = (ulong)ballotCount,
                CodesRoot = ByteString.CopyFrom(codesRoot.ToArray()),
                At = WireValues.Time(at, "at"),
            },
        }.ToByteArray();
    }

    /// <summary>A <c>RecordStatement</c> over the phase root <paramref name="root"/> of <paramref name="phase"/>, binding H_E and this library's format version.</summary>
    public static byte[] Record(RecordPhase phase, Sha256Digest root, ExtendedBaseHash extendedBaseHash, DateTimeOffset signedAt, string signerRole)
    {
        ArgumentNullException.ThrowIfNull(extendedBaseHash);
        ArgumentNullException.ThrowIfNull(signerRole);
        return new Pb.RecordItem
        {
            RecordStatement = new Pb.RecordStatement
            {
                Phase = (Pb.RecordPhase)(int)phase,
                Root = ByteString.CopyFrom(root.ToArray()),
                HE = WireValues.Bytes(extendedBaseHash),
                FormatMajor = RecordFormatVersion.Library.Major,
                FormatMinor = RecordFormatVersion.Library.Minor,
                SignedAt = WireValues.Time(signedAt, "signed_at"),
                SignerRole = signerRole,
            },
        }.ToByteArray();
    }
}
