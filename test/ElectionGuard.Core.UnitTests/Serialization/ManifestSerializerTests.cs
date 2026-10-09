using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Verify;
using ElectionGuard.Core.Verify.KeyGeneration;
using ElectionGuard.Testing.Common;
using System.Text;

namespace ElectionGuard.Core.UnitTests.Serialization;

/// <summary>
/// S10a (S2 review R1): the library's one manifest format, and the binding of an
/// <see cref="EncryptionRecord"/>'s parsed manifest to the manifest file H_B is computed over.
/// </summary>
public class ManifestSerializerTests
{
    public ManifestSerializerTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static Manifest Full() => ElectionFixtureBuilder.CreateMinimalManifest(
        includeWriteIns: true,
        chainingMode: ChainingMode.Simple,
        supplementalFields: ElectionFixtureBuilder.AllSupplementalFields).Manifest;

    private static string Text(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    [Fact]
    public void Serialize_IsDeterministic_AndRoundTripsToTheSameBytes()
    {
        var manifest = Full();

        byte[] first = ManifestSerializer.Serialize(manifest);
        byte[] second = ManifestSerializer.Serialize(Full());
        var read = ManifestSerializer.Deserialize(first);

        Assert.Equal(first, second);
        Assert.Equal(first, ManifestSerializer.Serialize(read));
        Assert.Equal(manifest.ElectionId, read.ElectionId);
        Assert.Equal(ChainingMode.Simple, read.ChainingMode);
        var contest = Assert.Single(read.Contests);
        Assert.Equal(manifest.Contests[0].Choices.Select(x => (x.Id, x.Name, x.Index)), contest.Choices.Select(x => (x.Id, x.Name, x.Index)));
        Assert.Equal(manifest.Contests[0].SupplementalFields.Select(x => (x.Id, x.Index, x.Kind)), contest.SupplementalFields.Select(x => (x.Id, x.Index, x.Kind)));
        Assert.Equal(1, contest.WriteInFieldCount);
        Assert.Equal(ElectionFixtureBuilder.DefaultContestDataBlocks, contest.ContestDataBlocks);
    }

    /// <summary>The written form documented on <see cref="ManifestSerializer"/>: compact, camelCase, declaration order, every optional member, kinds by name.</summary>
    [Fact]
    public void Serialize_WritesTheDocumentedForm()
    {
        var manifest = new Manifest
        {
            ElectionId = "e",
            Contests =
            [
                new Contest
                {
                    Id = "c", Name = "C", SelectionLimit = 1, OptionSelectionLimit = 1, Index = 1,
                    Choices = [new Choice { Id = "o", Name = "O", Index = 1 }],
                    SupplementalFields = [new SupplementalField { Id = "ov", Name = "Ov", Index = 2, Kind = SupplementalFieldKind.OvervoteIndicator }],
                },
            ],
            BallotStyles = [new BallotStyle { Id = "s", Name = "S", ContestIds = ["c"] }],
        };

        Assert.Equal(
            "{\"electionId\":\"e\",\"contests\":[{\"id\":\"c\",\"name\":\"C\",\"selectionLimit\":1,\"optionSelectionLimit\":1,\"index\":1," +
            "\"choices\":[{\"id\":\"o\",\"name\":\"O\",\"index\":1}]," +
            "\"supplementalFields\":[{\"kind\":\"OvervoteIndicator\",\"id\":\"ov\",\"name\":\"Ov\",\"index\":2}]," +
            "\"writeInFieldCount\":0,\"contestDataBlocks\":0}]," +
            "\"ballotStyles\":[{\"id\":\"s\",\"name\":\"S\",\"contestIds\":[\"c\"]}],\"chainingMode\":0}",
            Text(ManifestSerializer.Serialize(manifest)));

        // The hash-trimming function is written only when set, as its Ω subscript.
        Assert.EndsWith(",\"chainingMode\":0,\"hashTrimmingFunction\":1}",
            Text(ManifestSerializer.Serialize(manifest with { Contests = [manifest.Contests[0] with { SupplementalFields = [] }], HashTrimmingFunction = HashTrimmingFunction.TwoHex })));
    }

    /// <summary>Every manifest committed under test/data (the perf harness and console inputs) is in the library's format.</summary>
    [Fact]
    public void CommittedManifests_ParseStrictly()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "electionguard-cs.sln")))
        {
            directory = directory.Parent;
        }

        var manifests = Directory.GetFiles(Path.Combine(directory!.FullName, "test", "data"), "manifest.json", SearchOption.AllDirectories);
        Assert.NotEmpty(manifests);
        foreach (var path in manifests)
        {
            var exception = Record.Exception(() => ManifestSerializer.Deserialize(File.ReadAllBytes(path)));
            Assert.True(exception is null, $"{path}: {exception?.Message}");
        }
    }

    /// <summary>Whitespace and member order are the file's own business: the reader accepts any document that meets the rules; H_B hashes it as it is.</summary>
    [Fact]
    public void Deserialize_AcceptsIndentationAndAnotherMemberOrder()
    {
        string json = """
            {
              "chainingMode": 1,
              "ballotStyles": [ { "contestIds": [ "c" ], "name": "S", "id": "s" } ],
              "contests": [
                { "index": 1, "id": "c", "name": "C", "optionSelectionLimit": 1, "selectionLimit": 1,
                  "choices": [ { "index": 1, "name": "O", "id": "o" } ] }
              ],
              "electionId": "e"
            }
            """;

        var manifest = ManifestSerializer.Deserialize(Encoding.UTF8.GetBytes(json));

        Assert.Equal(ChainingMode.Simple, manifest.ChainingMode);
        Assert.Empty(manifest.Contests[0].SupplementalFields);
        Assert.Equal(0, manifest.Contests[0].ContestDataBlocks);
    }

    public static TheoryData<string, Func<string, string>> Malformations() => new()
    {
        { "byte order mark", json => "\uFEFF" + json },
        { "duplicate property", json => json.Replace("{\"electionId\":\"e\",", "{\"electionId\":\"e\",\"electionId\":\"f\",") },
        { "duplicate property, escaped", json => json.Replace("{\"electionId\":\"e\",", "{\"electionId\":\"e\",\"\\u0065lectionId\":\"f\",") },
        { "unknown property", json => json.Replace("{\"electionId\":\"e\",", "{\"electionId\":\"e\",\"extra\":1,") },
        { "property in another case", json => json.Replace("\"electionId\"", "\"ElectionId\"") },
        { "null election id", json => json.Replace("\"electionId\":\"e\"", "\"electionId\":null") },
        { "missing contests", json => json.Replace("\"contests\":", "\"contestz\":") },
        { "null contest list", json => ReplaceContests(json, "null") },
        { "null contest entry", json => ReplaceContests(json, "[null]") },
        { "null option entry", json => json.Replace("\"choices\":[{\"id\":\"o\",\"name\":\"O\",\"index\":1}]", "\"choices\":[null]") },
        { "null supplemental field list", json => json.Replace("\"supplementalFields\":[]", "\"supplementalFields\":null") },
        { "null ballot style contest id", json => json.Replace("\"contestIds\":[\"c\"]", "\"contestIds\":[null]") },
        { "kind in another case", json => json.Replace("\"supplementalFields\":[]", "\"supplementalFields\":[{\"kind\":\"overvoteindicator\",\"id\":\"ov\",\"name\":\"Ov\",\"index\":2}]") },
        { "kind as a number", json => json.Replace("\"supplementalFields\":[]", "\"supplementalFields\":[{\"kind\":1,\"id\":\"ov\",\"name\":\"Ov\",\"index\":2}]") },
        { "index as a string", json => json.Replace("\"index\":1,\"choices\"", "\"index\":\"1\",\"choices\"") },
        { "index as a fraction", json => json.Replace("\"index\":1,\"choices\"", "\"index\":1.0,\"choices\"") },
        { "comment", json => "/* c */" + json },
        { "trailing comma", json => json.Replace("\"chainingMode\":0}", "\"chainingMode\":0,}") },
        { "trailing content", json => json + "{}" },
        { "the value null", _ => "null" },
        { "undefined chaining mode", json => json.Replace("\"chainingMode\":0", "\"chainingMode\":2") },
        { "zero-based contest index", json => json.Replace("\"index\":1,\"choices\"", "\"index\":0,\"choices\"") },
        // S10a review round 1: the reader's GetString throws InvalidOperationException for these, which
        // StrictJson.RejectAmbiguity now reports as JsonException (so InvalidManifestException here).
        { "property name a lone high surrogate", json => json.Replace("\"chainingMode\":", "\"\\uD800\":") },
        { "property name a lone low surrogate", json => json.Replace("\"electionId\":", "\"\\uDC00\":") },
    };

    /// <summary>S10a review round 1: a property name that is not valid UTF-8 (the byte 0xFF) is an <see cref="InvalidManifestException"/>.</summary>
    [Fact]
    public void Deserialize_PropertyNameNotUtf8_ThrowsInvalidManifestException()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(MinimalJson().Replace("\"chainingMode\":", "\"#\":"));
        bytes[Array.IndexOf(bytes, (byte)'#')] = 0xFF;

        var exception = Assert.Throws<InvalidManifestException>(() => ManifestSerializer.Deserialize(bytes));

        Assert.IsType<System.Text.Json.JsonException>(exception.InnerException);
    }

    private static string ReplaceContests(string json, string replacement)
    {
        int start = json.IndexOf("\"contests\":", StringComparison.Ordinal) + "\"contests\":".Length;
        int end = json.IndexOf(",\"ballotStyles\"", StringComparison.Ordinal);
        return json[..start] + replacement + json[end..];
    }

    private static string MinimalJson() => Text(ManifestSerializer.Serialize(new Manifest
    {
        ElectionId = "e",
        Contests =
        [
            new Contest
            {
                Id = "c", Name = "C", SelectionLimit = 1, OptionSelectionLimit = 1, Index = 1,
                Choices = [new Choice { Id = "o", Name = "O", Index = 1 }],
            },
        ],
        BallotStyles = [new BallotStyle { Id = "s", Name = "S", ContestIds = ["c"] }],
    }));

    [Theory]
    [MemberData(nameof(Malformations))]
    public void Deserialize_MalformedOrInvalid_ThrowsInvalidManifestException(string description, Func<string, string> malform)
    {
        string json = MinimalJson();
        Assert.Null(Record.Exception(() => ManifestSerializer.Deserialize(Encoding.UTF8.GetBytes(json))));
        string malformed = malform(json);
        Assert.NotEqual(json, malformed);

        var exception = Assert.Throws<InvalidManifestException>(() => ManifestSerializer.Deserialize(Encoding.UTF8.GetBytes(malformed)));

        Assert.False(string.IsNullOrEmpty(exception.Message), description);
    }

    // --- The record's manifest is its manifest file's (S2 review R1) ------------------------------

    [Fact]
    public void EncryptionRecord_ManifestIsParsedFromItsFile_AndCannotBeSetApart()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;

        Assert.Equal(ManifestSerializer.Serialize(manifest), ManifestSerializer.Serialize(record.Manifest));
        Assert.NotSame(manifest, record.Manifest);

        // No setter, init accessor or constructor takes a parsed manifest.
        var property = typeof(EncryptionRecord).GetProperty(nameof(EncryptionRecord.Manifest))!;
        Assert.Null(property.SetMethod);
        Assert.DoesNotContain(typeof(EncryptionRecord).GetConstructors().SelectMany(x => x.GetParameters()), x => x.ParameterType == typeof(Manifest));
    }

    /// <summary>
    /// S10a review round 1: the record keeps its own copy of the manifest bytes, so a caller that
    /// changes the array it passed in changes neither what 1.F hashes nor the parsed manifest.
    /// </summary>
    [Fact]
    public void EncryptionRecord_CopiesTheManifestFile_SoTheCallersArrayCannotSplitTheBinding()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        byte[] original = manifestFile.Bytes.ToArray();
        Assert.NotSame(manifestFile, record.ManifestFile);
        Assert.NotSame(manifestFile.Bytes, record.ManifestFile.Bytes);

        Array.Fill(manifestFile.Bytes, (byte)' ');

        Assert.Equal(original, record.ManifestFile.Bytes);
        Assert.Null(Record.Exception(() => new ParameterVerification().Verify(record)));
        Assert.Equal(ManifestSerializer.Serialize(manifest), ManifestSerializer.Serialize(record.Manifest));
    }

    [Fact]
    public void EncryptionRecord_ManifestFileThatIsNotAManifest_Throws()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var file = new ManifestFile { Bytes = Encoding.UTF8.GetBytes("{\"election\":\"kat\"}") };

        Assert.Throws<InvalidManifestException>(() => new EncryptionRecord
        {
            CryptographicParameters = EGParameters.CryptographicParameters,
            GuardianParameters = EGParameters.GuardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = file,
            ElectionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, file),
            Guardians = guardianSet.GuardianPublicViews,
            ElectionPublicKeys = guardianSet.ElectionPublicKeys,
            ExtendedBaseHash = new ExtendedBaseHash(new ElectionBaseHash(EGParameters.ParameterBaseHash, file), guardianSet.ElectionPublicKeys),
        });
    }

    /// <summary>
    /// The attack S2 review R1 described: keep the hashed manifest, give the verifiers different
    /// limits. The limits can only come from the file now, and a different file fails 1.F against
    /// the record's H_B.
    /// </summary>
    [Fact]
    public void EncryptionRecord_ManifestWithOtherLimits_ComesWithItsOwnFile_AndFails1F()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        Assert.Null(Record.Exception(() => new ParameterVerification().Verify(record)));

        var widened = manifest with { Contests = [manifest.Contests[0] with { SelectionLimit = 2 }] };
        var forged = new EncryptionRecord
        {
            CryptographicParameters = record.CryptographicParameters,
            GuardianParameters = record.GuardianParameters,
            ParameterBaseHash = record.ParameterBaseHash,
            ManifestFile = ManifestSerializer.ToManifestFile(widened),
            ElectionBaseHash = record.ElectionBaseHash,
            Guardians = record.Guardians,
            ElectionPublicKeys = record.ElectionPublicKeys,
            ExtendedBaseHash = record.ExtendedBaseHash,
        };

        Assert.Equal(2, forged.Manifest.Contests[0].SelectionLimit);
        var exception = Assert.Throws<VerificationFailedException>(() => new ParameterVerification().Verify(forged));
        Assert.Equal("1.F", exception.SubSection);
    }

    [Fact]
    public void FixtureBuilder_ManifestThatIsNotTheFilesManifest_IsRefused()
    {
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet(manifestFile: manifestFile);
        var other = manifest with { ElectionId = "another-election" };

        Assert.Throws<ArgumentException>(() => ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, other, manifestFile));
    }
}
