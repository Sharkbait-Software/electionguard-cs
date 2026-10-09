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
        // Unknown properties are ignored (NQ-1; Deserialize_IgnoresUnknownProperties_WhichH_BStillBinds),
        // but not when named twice: duplicate keys are refused whether the model knows the name or not.
        { "unknown property named twice", json => json.Replace("{\"electionId\":\"e\",", "{\"electionId\":\"e\",\"x-vendor\":1,\"x-vendor\":2,") },
        // Member names in another case or spelling: see NearMisses_AreRefused_ReadingR3.
        { "null election id", json => json.Replace("\"electionId\":\"e\"", "\"electionId\":null") },
        // "contestz" is an unknown property, ignored; the required "contests" is then missing.
        { "missing contests", json => json.Replace("\"contests\":", "\"contestz\":") },
        { "election fact of the wrong type", json => json.Replace("{\"electionId\":\"e\",", "{\"electionId\":\"e\",\"electionDate\":20261103,") },
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
        // S10b-A review round 2: an ignored property's value is skipped without being decoded, so
        // StrictJson checks every escaped string itself. A file is a manifest or not whatever
        // properties a reader knows (another reader may know this one).
        { "known value a lone high surrogate", json => json.Replace("\"electionId\":\"e\"", "\"electionId\":\"e\\uD800\"") },
        { "unknown value a lone high surrogate", json => json.Replace("{\"electionId\":\"e\",", "{\"x-vendor\":\"\\uD800\",\"electionId\":\"e\",") },
        { "unknown nested value a lone low surrogate", json => json.Replace("{\"electionId\":\"e\",", "{\"x-vendor\":{\"a\":[\"ok\",\"\\uDC00\"]},\"electionId\":\"e\",") },
    };

    /// <summary>
    /// S10b-A review round 2: the lone-surrogate refusal does not reach a surrogate pair. The writer
    /// escapes non-ASCII as <c>\uXXXX</c>, so a character outside the BMP is written as a pair, and
    /// it reads back, in a known member and in an unknown one.
    /// </summary>
    [Fact]
    public void Deserialize_AcceptsEscapedSurrogatePairs_KnownAndUnknown()
    {
        var manifest = Full() with { ElectionName = "Ballot \U0001F5F3 2026" };
        byte[] written = ManifestSerializer.Serialize(manifest);
        Assert.Contains("\\uD83D\\uDDF3", Text(written), StringComparison.OrdinalIgnoreCase);

        Assert.Equal("Ballot \U0001F5F3 2026", ManifestSerializer.Deserialize(written).ElectionName);

        string json = MinimalJson().Replace("{\"electionId\":\"e\",", "{\"x-vendor\":\"\\uD83D\\uDE00\",\"electionId\":\"e\",", StringComparison.Ordinal);
        Assert.Equal("e", ManifestSerializer.Deserialize(Encoding.UTF8.GetBytes(json)).ElectionId);
    }

    /// <summary>
    /// S10b-A review round 2: nesting up to 64 levels, the top-level object being level 1, is read,
    /// vendor data included, and one level more is refused for its depth. Pins the limit the class
    /// remarks state (RFC 8259 §9 lets a parser set one; other readers' limits differ).
    /// </summary>
    [Fact]
    public void Deserialize_UnknownValueNestedTo64Levels_IsRead_And65AreRefused()
    {
        static byte[] Nested(int arrays) => Encoding.UTF8.GetBytes(MinimalJson().Replace("{\"electionId\":\"e\",", "{\"x-vendor\":" + new string('[', arrays) + new string(']', arrays) + ",\"electionId\":\"e\",", StringComparison.Ordinal));

        Assert.Equal("e", ManifestSerializer.Deserialize(Nested(63)).ElectionId);
        var exception = Assert.Throws<InvalidManifestException>(() => ManifestSerializer.Deserialize(Nested(64)));
        var inner = Assert.IsAssignableFrom<System.Text.Json.JsonException>(exception.InnerException);
        Assert.Contains("depth of 64", inner.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// S10b-A review round 2: bytes that are not well-formed UTF-8 (RFC 3629) are refused wherever
    /// they are, including in the value of a property the reader ignores, which the deserializer
    /// skips without decoding. RFC 8259 §8.1 requires UTF-8, and other readers (Python's
    /// <c>json.loads</c> on bytes, Rust's <c>serde_json::from_slice</c>) refuse these files.
    /// </summary>
    [Theory]
    [InlineData("unknown value", "\"x-vendor\":\"#\",", new byte[] { 0xFF, 0xFE })]
    [InlineData("unknown value, an encoded surrogate", "\"x-vendor\":\"#\",", new byte[] { 0xED, 0xA0, 0x80 })]
    [InlineData("unknown value, an overlong form", "\"x-vendor\":\"#\",", new byte[] { 0xC0, 0xAF })]
    [InlineData("unknown value, a truncated sequence", "\"x-vendor\":[\"#\"],", new byte[] { 0xE2, 0x82 })]
    [InlineData("unknown property name", "\"#\":1,", new byte[] { 0xFF })]
    [InlineData("known value", "\"electionName\":\"#\",", new byte[] { 0xFF })]
    public void Deserialize_NotUtf8_ThrowsInvalidManifestException(string description, string inserted, byte[] invalid)
    {
        byte[] template = Encoding.UTF8.GetBytes(MinimalJson().Replace("{\"electionId\":", "{" + inserted + "\"electionId\":", StringComparison.Ordinal));
        int at = Array.IndexOf(template, (byte)'#');
        byte[] valid = [.. template[..at], (byte)'x', .. template[(at + 1)..]];
        byte[] bytes = [.. template[..at], .. invalid, .. template[(at + 1)..]];
        Assert.Null(Record.Exception(() => ManifestSerializer.Deserialize(valid)));

        var exception = Assert.Throws<InvalidManifestException>(() => ManifestSerializer.Deserialize(bytes));

        Assert.IsType<System.Text.Json.JsonException>(exception.InnerException);
        Assert.True(exception.InnerException.Message.Contains("UTF-8", StringComparison.Ordinal), $"{description}: {exception.Message}");
    }

    /// <summary>
    /// User decision NQ-1 (2026-10-09): "The manifest is really the only field I would ever expect a
    /// vendor to provide additional data". The reader ignores properties the model does not have, at
    /// every level and whatever their value, so the parsed manifest is the one without them. The
    /// S10a reader refused them; this test replaces that row of <see cref="Malformations"/>. They
    /// stay in the file, so H_B (eq. 5), computed over the bytes as they are, binds them.
    /// </summary>
    [Fact]
    public void Deserialize_IgnoresUnknownProperties_WhichH_BStillBinds()
    {
        string plain = Text(ManifestSerializer.Serialize(Full()));
        string withVendorData = plain
            .Replace("{\"electionId\":", "{\"x-vendor\":{\"precincts\":[1,2,3],\"note\":null},\"electionId\":", StringComparison.Ordinal)
            .Replace("\"selectionLimit\":", "\"description\":\"Vote for one\",\"selectionLimit\":", StringComparison.Ordinal)
            .Replace("{\"id\":\"choice-1\",", "{\"party\":\"P\",\"id\":\"choice-1\",", StringComparison.Ordinal)
            .Replace("\"contestIds\":", "\"precinctIds\":[\"p-1\"],\"contestIds\":", StringComparison.Ordinal);
        foreach (var marker in new[] { "x-vendor", "description", "party", "precinctIds" })
        {
            Assert.Contains(marker, withVendorData);
        }

        var supplemental = Full().Contests[0].SupplementalFields[0];
        withVendorData = withVendorData.Replace($"{{\"kind\":\"{supplemental.Kind}\",", $"{{\"kind\":\"{supplemental.Kind}\",\"x-n\":7,", StringComparison.Ordinal);
        Assert.Contains("x-n", withVendorData);

        byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
        byte[] vendorBytes = Encoding.UTF8.GetBytes(withVendorData);
        var read = ManifestSerializer.Deserialize(vendorBytes);

        // The same manifest: writing it back gives the plain bytes (unknown properties are not kept).
        Assert.Equal(plainBytes, ManifestSerializer.Serialize(read));

        // But another manifest file, so another H_B.
        var parameterBaseHash = EGParameters.ParameterBaseHash;
        Assert.NotEqual(
            (byte[])new ElectionBaseHash(parameterBaseHash, new ManifestFile { Bytes = plainBytes }),
            (byte[])new ElectionBaseHash(parameterBaseHash, new ManifestFile { Bytes = vendorBytes }));
    }

    /// <summary>
    /// User decision NQ-4 (2026-10-09): §3.7's election facts are optional manifest fields. They are
    /// written after the hash-trimming function, only when set, and read back as written.
    /// </summary>
    [Fact]
    public void ElectionFacts_AreOptional_WrittenWhenSet_AndRoundTrip()
    {
        var manifest = Full() with
        {
            ElectionName = "General Election",
            ElectionDate = "2026-11-03",
            ElectionType = "general",
            Jurisdiction = "Example County",
            Location = "Example City",
        };

        byte[] written = ManifestSerializer.Serialize(manifest);
        var read = ManifestSerializer.Deserialize(written);

        Assert.EndsWith(",\"chainingMode\":1,\"electionName\":\"General Election\",\"electionDate\":\"2026-11-03\",\"electionType\":\"general\",\"jurisdiction\":\"Example County\",\"location\":\"Example City\"}", Text(written));
        Assert.Equal(("General Election", "2026-11-03", "general", "Example County", "Example City"),
            (read.ElectionName, read.ElectionDate, read.ElectionType, read.Jurisdiction, read.Location));
        Assert.Equal(written, ManifestSerializer.Serialize(read));

        // Absent, and written as null, both read as absent; neither is written back.
        var plain = ManifestSerializer.Deserialize(ManifestSerializer.Serialize(Full()));
        Assert.Null(plain.ElectionName);
        string withNull = Text(ManifestSerializer.Serialize(Full())).Replace("{\"electionId\":", "{\"location\":null,\"electionId\":", StringComparison.Ordinal);
        Assert.Null(ManifestSerializer.Deserialize(Encoding.UTF8.GetBytes(withNull)).Location);
        Assert.DoesNotContain("location", Text(ManifestSerializer.Serialize(plain)));
    }

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

    // --- Reading R-3 (design §12; awaiting the user's confirmation) -------------------------------
    // These rows pin reading R-3(a): an unknown property whose name equals a member's once case, '_'
    // and '-' are disregarded is refused as a near miss (a reader in another language matching names
    // loosely would read it as that member), not ignored like other unknown properties (NQ-1). If the
    // user chooses R-3(b), delete this block together with ManifestSerializer.RejectNearMisses.

    public static TheoryData<string, Func<string, string>> NearMisses() => new()
    {
        // Without the near-miss check this would still fail, as the required electionId would then be
        // missing; the message assertion shows the near-miss check is what refuses it.
        { "property in another case", json => json.Replace("\"electionId\"", "\"ElectionId\"") },
        { "optional property in another case", json => json.Replace("\"chainingMode\":0", "\"ChainingMode\":1") },
        { "optional property in snake case", json => json.Replace("\"chainingMode\":0", "\"chaining_mode\":1") },
        { "nested property in kebab case", json => json.Replace("\"selectionLimit\":1", "\"selectionLimit\":1,\"Selection-Limit\":2") },
    };

    [Theory]
    [MemberData(nameof(NearMisses))]
    public void NearMisses_AreRefused_ReadingR3(string description, Func<string, string> malform)
    {
        string json = MinimalJson();
        string malformed = malform(json);
        Assert.NotEqual(json, malformed);

        var exception = Assert.Throws<InvalidManifestException>(() => ManifestSerializer.Deserialize(Encoding.UTF8.GetBytes(malformed)));

        Assert.IsType<System.Text.Json.JsonException>(exception.InnerException);
        Assert.True(exception.InnerException.Message.Contains("reads as its member", StringComparison.Ordinal), $"{description}: {exception.Message}");
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
