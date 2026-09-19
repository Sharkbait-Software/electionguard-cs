using System.Security.Cryptography;
using System.Text.Json;
using ElectionGuard.Core.Models;
using ElectionGuard.Perf.Cli.Configuration;

namespace ElectionGuard.Perf.Cli.Running;

public static class ManifestHasher
{
    /// <summary>
    /// Canonical manifest bytes. The same bytes feed the ElectionBaseHash and the run record's
    /// manifestHash, so a manifest edit is always visible in the result.
    /// </summary>
    public static byte[] Serialize(Manifest manifest) =>
        JsonSerializer.SerializeToUtf8Bytes(manifest, PerfJson.LineOptions);

    public static string Hash(Manifest manifest) =>
        "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Serialize(manifest)));
}
