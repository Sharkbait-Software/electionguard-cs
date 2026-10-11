using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using Google.Protobuf;
using static ElectionGuard.Core.RecordFormat.Mappers.WireValues;
using Pb = ElectionGuard.Core.RecordFormat.Protobuf;

namespace ElectionGuard.Core.RecordFormat.Mappers;

/// <summary>
/// <see cref="RecordSetup"/> to and from the setup items (design §3.1, §4.5): <c>record_header</c>,
/// <c>parameters</c>, <c>manifest_file</c>, one <c>guardian_public_key</c> per guardian in index
/// order, and <c>election_keys</c>. p, q, r and g are raw fixed-width bytes, never
/// <see cref="IntegerModP"/>/<see cref="IntegerModQ"/> (decision G1: those would reduce p and q to
/// 0); every hash is a claim, kept as read. The manifest file is stored byte for byte (#19).
/// </summary>
internal static class SetupMapper
{
    public static IReadOnlyList<Pb.RecordItem> ToItems(RecordSetup setup)
    {
        ArgumentNullException.ThrowIfNull(setup);
        var items = new List<Pb.RecordItem>
        {
            new() { RecordHeader = new Pb.RecordHeader { FormatMajor = setup.Format.Major, FormatMinor = setup.Format.Minor } },
            new()
            {
                Parameters = new Pb.Parameters
                {
                    Version = Bytes(setup.Parameters.Version),
                    P = Bytes(Fixed(setup.Parameters.P, 512, "p")),
                    Q = Bytes(Fixed(setup.Parameters.Q, 32, "q")),
                    R = Bytes(Fixed(setup.Parameters.R, 512, "r")),
                    G = Bytes(Fixed(setup.Parameters.G, 512, "g")),
                    N = (uint)setup.GuardianParameters.N,
                    K = (uint)setup.GuardianParameters.K,
                    HP = Bytes(setup.ParameterBaseHash),
                },
            },
            new()
            {
                ManifestFile = new Pb.ManifestFile
                {
                    MediaType = setup.ManifestMediaType,
                    Content = Bytes(setup.ManifestFile.Bytes),
                    HB = Bytes(setup.ElectionBaseHash),
                },
            },
        };

        foreach (var guardian in setup.Guardians.OrderBy(x => x.Index.Index))
        {
            items.Add(new Pb.RecordItem { GuardianPublicKey = ToItem(guardian) });
        }

        items.Add(new Pb.RecordItem
        {
            ElectionKeys = new Pb.ElectionKeys
            {
                K = Zp(setup.Keys.VoteEncryptionKey),
                KHat = Zp(setup.Keys.OtherBallotDataEncryptionKey),
                HE = Bytes(setup.ExtendedBaseHash),
            },
        });

        return items;
    }

    public static Pb.GuardianPublicKey ToItem(GuardianPublicView guardian) => new()
    {
        Index = (uint)guardian.Index.Index,
        VoteCommitments = Bytes(guardian.VoteEncryptionCommitments.SelectMany(x => x.ToByteArray()).ToArray()),
        DataCommitments = Bytes(guardian.OtherBallotDataEncryptionCommitments.SelectMany(x => x.ToByteArray()).ToArray()),
        Kappa = Zp(guardian.CommunicationPublicKey),
        VoteProof = Bytes(Proof(guardian.VoteEncryptionProof)),
        DataProof = Bytes(Proof(guardian.OtherDataEncryptionProof)),
    };

    private static byte[] Proof(SchnorrProof proof) => [.. proof.Challenge.ToByteArray(), .. proof.Responses.SelectMany(x => x.ToByteArray())];

    /// <summary>The <c>RecordItem</c> members whose findings each setup verification's gate considers (design §4.8: not evaluable only "on the item").</summary>
    public const string ParametersItem = "parameters", GuardianItem = "guardian_public_key", ElectionKeysItem = "election_keys";

    /// <summary>Verification 1 reads the parameters and the manifest file (H_B).</summary>
    public static readonly IReadOnlyCollection<string> ReadByVerification1 = [ParametersItem, "manifest_file"];

    /// <summary>Verification 2 reads the guardian keys only (n and k from <see cref="EGParameters"/>).</summary>
    public static readonly IReadOnlyCollection<string> ReadByVerification2 = [GuardianItem];

    /// <summary>Verification 3 reads the guardian keys and the election keys.</summary>
    public static readonly IReadOnlyCollection<string> ReadByVerification3 = [GuardianItem, ElectionKeysItem];

    /// <summary>
    /// The setup sections from their items, in canonical order. Range findings: commitments and κ
    /// 2.A, responses 2.B, challenges 2.C, K 3.A and K-hat 3.B; a version that is not a string
    /// padded with zero bytes 1.A; n or k that no <see cref="GuardianParameters"/> can hold
    /// 1.structure; a guardian index of 0 2.A. Each finding names its item
    /// (<see cref="RecordFinding.Item"/>), so a finding on a guardian's key leaves Verification 1
    /// evaluable (<see cref="ReadByVerification1"/>).
    /// </summary>
    public static RecordDecoded<RecordSetup> FromItems(IReadOnlyList<Pb.RecordItem> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (items.Count < 4
            || items[0].ItemCase != Pb.RecordItem.ItemOneofCase.RecordHeader
            || items[1].ItemCase != Pb.RecordItem.ItemOneofCase.Parameters
            || items[2].ItemCase != Pb.RecordItem.ItemOneofCase.ManifestFile
            || items[^1].ItemCase != Pb.RecordItem.ItemOneofCase.ElectionKeys
            || items.Skip(3).SkipLast(1).Any(x => x.ItemCase != Pb.RecordItem.ItemOneofCase.GuardianPublicKey))
        {
            throw new ArgumentException("The setup items are record_header, parameters, manifest_file, guardian_public_key per guardian, then election_keys.", nameof(items));
        }

        var context = new RecordDecodeContext();
        var header = items[0].RecordHeader;
        var parameters = items[1].Parameters;
        var manifest = items[2].ManifestFile;
        var keys = items[^1].ElectionKeys;

        context.Item = ParametersItem;
        var version = DecodeVersion(RequireArray(parameters.Version, 32, "ver"), context);
        var cryptographic = new CryptographicParameters(
            version,
            Convert.ToHexString(RequireArray(parameters.Q, 32, "q")),
            Convert.ToHexString(RequireArray(parameters.P, 512, "p")),
            Convert.ToHexString(RequireArray(parameters.R, 512, "r")),
            Convert.ToHexString(RequireArray(parameters.G, 512, "g")));

        GuardianParameters guardianParameters;
        if (parameters.N is >= 1 and <= int.MaxValue && parameters.K >= 1 && parameters.K <= parameters.N)
        {
            guardianParameters = new GuardianParameters((int)parameters.N, (int)parameters.K);
        }
        else
        {
            context.Add("1.structure", $"The record's guardian parameters n = {parameters.N}, k = {parameters.K} are not a threshold scheme (1 <= k <= n).");
            guardianParameters = new GuardianParameters();
        }

        context.Item = GuardianItem;
        var guardians = items.Skip(3).SkipLast(1).Select(x => FromItem(x.GuardianPublicKey, context)).ToList();

        context.Item = ElectionKeysItem;
        var electionKeys = ElectionPublicKeys.FromKeys(
            context.Zp(Require(keys.K, 512, "K"), RecordValueRanges.ElectionKey, "K"),
            context.Zp(Require(keys.KHat, 512, "K-hat"), RecordValueRanges.ElectionKeyHat, "K-hat"));

        var setup = new RecordSetup(
            new RecordFormatVersion((ushort)Math.Min(header.FormatMajor, ushort.MaxValue), (ushort)Math.Min(header.FormatMinor, ushort.MaxValue)),
            cryptographic,
            guardianParameters,
            ParameterBaseHash.FromCanonicalBytes(RequireArray(parameters.HP, 32, "H_P")),
            new ManifestFile { Bytes = manifest.Content.ToByteArray() },
            manifest.MediaType,
            ElectionBaseHash.FromCanonicalBytes(RequireArray(manifest.HB, 32, "H_B")),
            guardians,
            electionKeys,
            ExtendedBaseHash.FromCanonicalBytes(RequireArray(keys.HE, 32, "H_E")));

        return context.Result(setup);
    }

    /// <summary>
    /// ver of eq. (4) is a version string followed by zero bytes up to 32. Bytes that are not that
    /// (a zero byte inside the string, bytes that are not UTF-8) cannot be a <see cref="Models.Version"/>
    /// whose bytes are the same, so they fail 1.A, which compares ver.
    /// </summary>
    private static string DecodeVersion(byte[] bytes, RecordDecodeContext context)
    {
        int end = Array.IndexOf(bytes, (byte)0);
        if (end < 0)
        {
            end = bytes.Length;
        }

        string text;
        try
        {
            text = new System.Text.UTF8Encoding(false, true).GetString(bytes, 0, end);
        }
        catch (System.Text.DecoderFallbackException)
        {
            context.Add("1.A", "The record's ver is not a UTF-8 string padded with zero bytes (eq. 4).");
            return "";
        }

        if (!((byte[])new Models.Version(text)).AsSpan().SequenceEqual(bytes))
        {
            context.Add("1.A", "The record's ver is not a version string padded with zero bytes to 32 (eq. 4).");
        }

        return text;
    }

    private static GuardianPublicView FromItem(Pb.GuardianPublicKey item, RecordDecodeContext context)
    {
        string who = $"guardian {item.Index}";
        if (item.Index is 0 or > int.MaxValue)
        {
            context.Add(RecordValueRanges.GuardianIndex, $"A guardian's index is {item.Index}; indices are 1..n (§3.2.1).");
        }

        return new GuardianPublicView
        {
            Index = new GuardianIndex(item.Index is 0 or > int.MaxValue ? 1 : (int)item.Index),
            VoteEncryptionCommitments = Values(item.VoteCommitments, context, $"{who}: K_i,j"),
            OtherBallotDataEncryptionCommitments = Values(item.DataCommitments, context, $"{who}: K-hat_i,j"),
            CommunicationPublicKey = context.Zp(Require(item.Kappa, 512, $"{who}: κ_i"), RecordValueRanges.GuardianKey, $"{who}: κ_i"),
            VoteEncryptionProof = Proof(item.VoteProof, context, $"{who}: vote encryption proof"),
            OtherDataEncryptionProof = Proof(item.DataProof, context, $"{who}: ballot data encryption proof"),
        };
    }

    private static List<IntegerModP> Values(ByteString bytes, RecordDecodeContext context, string what) =>
        Chunks(bytes, 512, what).Select((x, j) => context.Zp(x, RecordValueRanges.GuardianKey, $"{what}, j = {j}")).ToList();

    private static SchnorrProof Proof(ByteString bytes, RecordDecodeContext context, string what)
    {
        var values = Chunks(bytes, 32, what).ToList();
        return new SchnorrProof
        {
            Challenge = context.Zq(values[0], RecordValueRanges.GuardianChallenge, $"{what}: c"),
            Responses = values.Skip(1).Select((x, j) => context.Zq(x, RecordValueRanges.GuardianResponse, $"{what}: v_{j}")).ToArray(),
        };
    }
}
