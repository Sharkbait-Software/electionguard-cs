using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Core.UnitTests.Models;

/// <summary>
/// §3.1.3: contest and option indices are 1-based list positions, and contest, option (within a
/// contest) and ballot style labels are unique.
/// </summary>
public class ManifestValidationTests
{
    public ManifestValidationTests()
    {
        EGParameters.Init(new CryptographicParameters(), new GuardianParameters());
    }

    private static Manifest Minimal() => ElectionFixtureBuilder.CreateMinimalManifest().Manifest;

    private static Contest SecondContest(int index) => new()
    {
        Id = "contest-2",
        Name = "Second Contest",
        SelectionLimit = 1,
        OptionSelectionLimit = 1,
        Index = index,
        Choices = [new Choice { Id = "choice-1", Name = "Choice 1", Index = 1 }],
    };

    [Fact]
    public void Validate_PositionalOneBasedIndices_DoesNotThrow()
    {
        var manifest = Minimal() with { Contests = [Minimal().Contests[0], SecondContest(2)] };

        var exception = Record.Exception(manifest.Validate);

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_FixtureManifestsInTestData_DoNotThrow()
    {
        // The JSON manifests checked into test/data feed the perf harness and the console; each
        // must satisfy §3.1.3 as written.
        var options = new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var dataDirectory = Path.Combine(FindRepositoryRoot(), "test", "data");
        var manifests = Directory.GetFiles(dataDirectory, "manifest.json", SearchOption.AllDirectories);
        Assert.NotEmpty(manifests);

        foreach (var path in manifests)
        {
            var manifest = System.Text.Json.JsonSerializer.Deserialize<Manifest>(File.ReadAllBytes(path), options)!;
            manifest.Validate();
        }
    }

    [Fact]
    public void Validate_ZeroBasedContestIndex_Throws()
    {
        var template = Minimal();
        var manifest = template with { Contests = [template.Contests[0] with { Index = 0 }] };

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains("contest-1", exception.Message);
    }

    [Fact]
    public void Validate_ZeroBasedOptionIndices_Throws()
    {
        var template = Minimal();
        var contest = template.Contests[0];
        var manifest = template with
        {
            Contests = [contest with { Choices = contest.Choices.Select(x => x with { Index = x.Index - 1 }).ToList() }],
        };

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains("choice-1", exception.Message);
    }

    [Fact]
    public void Validate_ContestIndexNotItsPosition_Throws()
    {
        // Unique and 1-based, but not the list position: the second contest claims index 3.
        var manifest = Minimal() with { Contests = [Minimal().Contests[0], SecondContest(3)] };

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains("contest-2", exception.Message);
    }

    [Fact]
    public void Validate_OptionsListedOutOfIndexOrder_Throws()
    {
        var template = Minimal();
        var contest = template.Contests[0];
        var manifest = template with { Contests = [contest with { Choices = Enumerable.Reverse(contest.Choices).ToList() }] };

        Assert.Throws<InvalidManifestException>(manifest.Validate);
    }

    [Fact]
    public void Validate_DuplicateContestId_Throws()
    {
        var first = Minimal().Contests[0];
        var manifest = Minimal() with { Contests = [first, first with { Index = 2 }] };

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains("more than once", exception.Message);
    }

    [Fact]
    public void Validate_DuplicateOptionIdWithinAContest_Throws()
    {
        var template = Minimal();
        var contest = template.Contests[0];
        var manifest = template with
        {
            Contests =
            [
                contest with
                {
                    Choices =
                    [
                        new Choice { Id = "choice-1", Name = "Choice 1", Index = 1 },
                        new Choice { Id = "choice-1", Name = "Choice 1 again", Index = 2 },
                    ],
                },
            ],
        };

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains("choice-1", exception.Message);
    }

    [Fact]
    public void Validate_SameOptionIdInDifferentContests_DoesNotThrow()
    {
        // Option labels are unique within a contest, not across the election.
        var manifest = Minimal() with { Contests = [Minimal().Contests[0], SecondContest(2)] };
        Assert.Equal("choice-1", manifest.Contests[1].Choices[0].Id);

        var exception = Record.Exception(manifest.Validate);

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_DuplicateBallotStyleId_Throws()
    {
        var template = Minimal();
        var manifest = template with { BallotStyles = [template.BallotStyles[0], template.BallotStyles[0]] };

        Assert.Throws<InvalidManifestException>(manifest.Validate);
    }

    [Fact]
    public void EncryptionRecord_WithInvalidManifest_Throws()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var zeroBased = manifest with { Contests = [manifest.Contests[0] with { Index = 0 }] };

        Assert.Throws<InvalidManifestException>(() => ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, zeroBased, manifestFile));
    }

    /// <summary>
    /// §3.4.4 p.42 specifies chaining modes 0x00000000 and 0x00000001 only; "other modes must be
    /// uniquely identified by a 4-byte identifier and specified in the election manifest", and this
    /// manifest model specifies none. A JSON manifest carrying chainingMode 2 deserializes (the enum
    /// accepts any integer) but is refused, so neither an encryptor nor a verifier invents rules
    /// for it (S8 review round 1).
    /// </summary>
    [Theory]
    [InlineData(2)]
    [InlineData(-1)]
    public void Validate_UndefinedChainingMode_Throws(int mode)
    {
        var options = new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase };
        var json = System.Text.Json.JsonSerializer.Serialize(Minimal(), options);
        Assert.Contains("\"chainingMode\":0", json);
        var read = System.Text.Json.JsonSerializer.Deserialize<Manifest>(json.Replace("\"chainingMode\":0", $"\"chainingMode\":{mode}"), options)!;
        Assert.Equal((ChainingMode)mode, read.ChainingMode);

        var exception = Assert.Throws<InvalidManifestException>(read.Validate);
        Assert.Contains("chaining mode", exception.Message);

        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (_, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        Assert.Throws<InvalidManifestException>(() => ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, read, manifestFile));
    }

    [Theory]
    [InlineData(ChainingMode.None)]
    [InlineData(ChainingMode.Simple)]
    public void Validate_SpecifiedChainingModes_DoNotThrow(ChainingMode mode)
    {
        Assert.Null(Record.Exception(ElectionFixtureBuilder.CreateMinimalManifest(chainingMode: mode).Manifest.Validate));
    }

    /// <summary>
    /// The public <see cref="ChainingField"/> builders refuse an undefined mode too, rather than
    /// writing its identifier ahead of a simple-chaining hash (eq. 76) whose B_C,0 and close
    /// hard-code 0x00000001.
    /// </summary>
    [Fact]
    public void ChainingField_UndefinedChainingMode_Throws()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest();
        var record = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile).EncryptionRecord;
        var deviceHash = new VotingDeviceInformationHash(record.ExtendedBaseHash, "device-1");

        Assert.Throws<ArgumentOutOfRangeException>(() => new ChainingField((ChainingMode)2, deviceHash, record.ExtendedBaseHash, null));
        Assert.Throws<ArgumentOutOfRangeException>(() => ChainingField.ForPreEncryptedBallots((ChainingMode)2, deviceHash, record.ExtendedBaseHash, null));
    }

    /// <summary>
    /// A record's manifest validated on construction and then reordered in place is caught again
    /// by the ballot encryptors, which would otherwise bake the wrong indices into new ballots. The
    /// verifications deliberately do not re-validate per ballot (it costs O(manifest) per ballot);
    /// they rely on the validation done when the record was built.
    /// </summary>
    [Fact]
    public void Encryptors_ManifestReorderedAfterRecordCreation_Throw()
    {
        var guardianSet = ElectionFixtureBuilder.CreateGuardianSet();
        var (manifest, manifestFile) = ElectionFixtureBuilder.CreateMinimalManifest(hashTrimmingFunction: HashTrimmingFunction.TwoHex);
        var records = ElectionFixtureBuilder.CreateEncryptionRecord(guardianSet, manifest, manifestFile);
        var record = records.EncryptionRecord;
        var deviceHash = new VotingDeviceInformationHash(records.ExtendedBaseHash, "device-1");

        manifest.Contests[0].Choices.Reverse();

        Assert.Throws<InvalidManifestException>(() => new BallotEncryptor(record, "device-1", deviceHash));
        Assert.Throws<InvalidManifestException>(() => new BallotPreEncryptor(record, "device-1"));
    }

    // --- S5: per-contest supplemental fields (user decision Q1) ---------------------------------

    /// <summary>
    /// The minimal manifest's contest declaring <paramref name="fields"/> and offering
    /// <paramref name="writeInFieldCount"/> write-in fields: by default 1 when the write-in count is
    /// declared and none otherwise (a contest that offers write-ins must declare the count, Q13,
    /// Q19).
    /// </summary>
    private static Manifest WithFields(List<SupplementalField> fields, int? writeInFieldCount = null)
    {
        var template = Minimal();
        int offered = writeInFieldCount ?? (fields.Any(x => x.Kind == SupplementalFieldKind.WriteInCount) ? 1 : 0);
        return template with { Contests = [template.Contests[0] with { SupplementalFields = fields, WriteInFieldCount = offered }] };
    }

    private static SupplementalField Field(string id, int index, SupplementalFieldKind kind) =>
        new() { Id = id, Name = id, Index = index, Kind = kind };

    [Fact]
    public void Validate_EveryKindDeclaredAfterTheOptions_DoesNotThrow()
    {
        var manifest = WithFields(ElectionFixtureBuilder.SupplementalFields(2, ElectionFixtureBuilder.AllSupplementalFields));

        Assert.Null(Record.Exception(manifest.Validate));
    }

    [Theory]
    [InlineData(2)] // collides with option 2
    [InlineData(4)] // skips index 3
    [InlineData(1)]
    public void Validate_SupplementalFieldIndexNotContinuingAfterTheOptions_Throws(int index)
    {
        var manifest = WithFields([Field("overvotes", index, SupplementalFieldKind.OvervoteIndicator)]);

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains("continues after the selectable options", exception.Message);
    }

    [Fact]
    public void Validate_TwoFieldsOfOneKind_Throws()
    {
        var manifest = WithFields([Field("null-a", 3, SupplementalFieldKind.NullVoteIndicator), Field("null-b", 4, SupplementalFieldKind.NullVoteIndicator)]);

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains("more than one", exception.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(6)]
    [InlineData(-1)]
    public void Validate_UndefinedKind_Throws(int kind)
    {
        var manifest = WithFields([Field("field", 3, (SupplementalFieldKind)kind)]);

        Assert.Throws<InvalidManifestException>(manifest.Validate);
    }

    [Fact]
    public void Validate_FieldLabelThatIsAlsoAnOptionLabel_Throws()
    {
        var manifest = WithFields([Field("choice-1", 3, SupplementalFieldKind.NullVoteIndicator)]);

        Assert.Throws<InvalidManifestException>(manifest.Validate);
    }

    [Fact]
    public void Validate_TwoFieldsWithOneLabel_Throws()
    {
        var manifest = WithFields([Field("same", 3, SupplementalFieldKind.NullVoteIndicator), Field("same", 4, SupplementalFieldKind.UndervoteIndicator)]);

        Assert.Throws<InvalidManifestException>(manifest.Validate);
    }

    [Theory]
    // S5b (user decision Q14): there is no counts-toward-limit setting. A field is declared
    // ("tracked") or not, and any one kind may be declared on its own; Verification 7 includes every
    // declared field in its relations. The UndervoteDifferenceCount row declares u without the
    // overvote indicator, which user decision Q18 keeps valid (with no tracked overvote field,
    // there is no published overvote, and u = L on the neutralized contest).
    [InlineData(SupplementalFieldKind.OvervoteIndicator)]
    [InlineData(SupplementalFieldKind.NullVoteIndicator)]
    [InlineData(SupplementalFieldKind.UndervoteIndicator)]
    [InlineData(SupplementalFieldKind.UndervoteDifferenceCount)]
    [InlineData(SupplementalFieldKind.WriteInCount)]
    public void Validate_AnyKindDeclaredOnItsOwn_DoesNotThrow(SupplementalFieldKind kind)
    {
        var manifest = WithFields([Field("field", 3, kind)]);

        Assert.Null(Record.Exception(manifest.Validate));
    }

    [Fact]
    public void Validate_ALeftoverCountsTowardSelectionLimitKey_IsNotAField()
    {
        // The S5 flag is gone (Q14). System.Text.Json ignores the key, so a manifest written before
        // S5b still reads, with the same fields; its H_B changes only if its bytes are rewritten.
        var options = new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase };
        var json = System.Text.Json.JsonSerializer.Serialize(WithFields([Field("overvotes", 3, SupplementalFieldKind.OvervoteIndicator)]), options)
            .Replace("\"kind\":\"OvervoteIndicator\"", "\"kind\":\"OvervoteIndicator\",\"countsTowardSelectionLimit\":true");
        Assert.Contains("countsTowardSelectionLimit", json);

        var read = System.Text.Json.JsonSerializer.Deserialize<Manifest>(json, options)!;

        Assert.Equal(SupplementalFieldKind.OvervoteIndicator, Assert.Single(read.Contests[0].SupplementalFields).Kind);
        Assert.Null(Record.Exception(read.Validate));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void Validate_WriteInFieldsOfferedWithoutAWriteInCount_Throws(int writeInFieldCount)
    {
        // User decision Q13: write-ins always count toward the selection limit, and only the
        // write-in count's encryption can carry them into the selection-limit proof. User decision
        // Q19 ("Reject manifest"): write-in fields offered without a write-in count are invalid.
        var manifest = WithFields(ElectionFixtureBuilder.SupplementalFields(2, ElectionFixtureBuilder.DefaultSupplementalFields), writeInFieldCount);

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains("declares no write-in count field", exception.Message);
    }

    [Theory]
    // §3.1.3 p.17: R is "a positive integer".
    [InlineData(1, 0, "option selection limit")]
    [InlineData(1, -1, "option selection limit")]
    // L = 0 admits no selection, and L < 0 no selection-limit proof (S5 review round 2 decision).
    [InlineData(0, 1, "contest selection limit")]
    [InlineData(-1, 1, "contest selection limit")]
    public void Validate_SelectionLimitBelowOne_Throws(int selectionLimit, int optionSelectionLimit, string limit)
    {
        var template = Minimal();
        var manifest = template with { Contests = [template.Contests[0] with { SelectionLimit = selectionLimit, OptionSelectionLimit = optionSelectionLimit }] };

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains(limit, exception.Message);
    }

    [Fact]
    public void Validate_SelectionLimitsOfOne_DoNotThrow()
    {
        var template = Minimal();
        var manifest = template with { Contests = [template.Contests[0] with { SelectionLimit = 1, OptionSelectionLimit = 1 }] };

        Assert.Null(Record.Exception(manifest.Validate));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WriteInCountWithoutWriteInFields_Throws(int writeInFieldCount)
    {
        var manifest = WithFields([Field("write-ins", 3, SupplementalFieldKind.WriteInCount)], writeInFieldCount);

        Assert.Throws<InvalidManifestException>(manifest.Validate);
    }

    [Theory]
    // A null field list is refused as invalid, not a NullReferenceException.
    [InlineData("null field list", "no supplemental field list")]
    // A negative write-in field count is refused even when no write-in count field is declared.
    [InlineData("negative write-in fields, no write-in count field", "cannot be negative")]
    public void Validate_MalformedSupplementalFieldDeclaration_Throws(string declaration, string reason)
    {
        var template = Minimal();
        var contest = declaration switch
        {
            "null field list" => template.Contests[0] with { SupplementalFields = null! },
            "negative write-in fields, no write-in count field" => template.Contests[0] with
            {
                SupplementalFields = [Field("overvotes", 3, SupplementalFieldKind.OvervoteIndicator)],
                WriteInFieldCount = -1,
            },
            _ => throw new ArgumentOutOfRangeException(nameof(declaration)),
        };
        var manifest = template with { Contests = [contest] };

        var exception = Assert.Throws<InvalidManifestException>(manifest.Validate);

        Assert.Contains(reason, exception.Message);
    }

    [Fact]
    public void Validate_JsonManifestWithNullSupplementalFields_ThrowsInvalidManifest()
    {
        var options = new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase };
        var template = Minimal();
        var json = System.Text.Json.JsonSerializer.Serialize(template with { Contests = [template.Contests[0] with { SupplementalFields = null! }] }, options);
        Assert.Contains("\"supplementalFields\":null", json);

        var read = System.Text.Json.JsonSerializer.Deserialize<Manifest>(json, options)!;

        Assert.Null(read.Contests[0].SupplementalFields);
        var exception = Assert.Throws<InvalidManifestException>(read.Validate);
        Assert.Contains("no supplemental field list", exception.Message);
    }

    [Fact]
    public void Manifest_JsonRoundTrip_KeepsTheSupplementalFieldsWithKindsByName()
    {
        var manifest = WithFields(ElectionFixtureBuilder.SupplementalFields(2, ElectionFixtureBuilder.AllSupplementalFields), writeInFieldCount: 3);
        var options = new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase };

        var json = System.Text.Json.JsonSerializer.Serialize(manifest, options);
        var read = System.Text.Json.JsonSerializer.Deserialize<Manifest>(json, options)!;

        Assert.Contains("\"kind\":\"UndervoteDifferenceCount\"", json);
        Assert.Equal(3, read.Contests[0].WriteInFieldCount);
        Assert.Equal(manifest.Contests[0].SupplementalFields, read.Contests[0].SupplementalFields);
        read.Validate();
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "electionguard-cs.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Could not find the repository root above " + AppContext.BaseDirectory);
    }
}
