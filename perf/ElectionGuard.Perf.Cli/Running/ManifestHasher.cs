using System.Security.Cryptography;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.Serialization;

namespace ElectionGuard.Perf.Cli.Running;

public static class ManifestHasher
{
    /// <summary>
    /// The manifest in Core's written form (ManifestSerializer), the file the encryption record
    /// parses its manifest from. The same bytes feed the ElectionBaseHash and the run record's
    /// manifestHash, so a manifest edit is always visible in the result. (Before S10a these were
    /// PerfJson.LineOptions bytes: camelCase, compact, declaration order, the same bytes for every
    /// committed manifest.)
    /// </summary>
    public static byte[] Serialize(Manifest manifest) =>
        ManifestSerializer.Serialize(manifest);

    public static string Hash(Manifest manifest) =>
        "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Serialize(manifest)));
}
