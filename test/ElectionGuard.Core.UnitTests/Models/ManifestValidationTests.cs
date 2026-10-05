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

    private static Manifest WithFields(List<SupplementalField> fields, int writeInFieldCount = 1)
    {
        var template = Minimal();
        return template with { Contests = [template.Contests[0] with { SupplementalFields = fields, WriteInFieldCount = writeInFieldCount }] };
    }

    private static SupplementalField Field(string id, int index, SupplementalFieldKind kind, bool counts = false) =>
        new() { Id = id, Name = id, Index = index, Kind = kind, CountsTowardSelectionLimit = counts };

    [Fact]
    public void Validate_EveryKindDeclaredAfterTheOptions_DoesNotThrow()
    {
        var manifest = WithFields(ElectionFixtureBuilder.SupplementalFields(2, ElectionFixtureBuilder.AllSupplementalFields, writeInsCountTowardLimit: true));

        Assert.Null(Record.Exception(manifest.Validate));
    }

    [Theory]
    [InlineData(2)] // collides with option 2
    [InlineData(4)] // skips index 3
    [InlineData(1)]
    public void Validate_SupplementalFieldIndexNotContinuingAfterTheOptions_Throws(int index)
    {
        var manifest = WithFields([Field("overvotes", index, SupplementalFieldKind.OvervoteIndicator, counts: true)]);

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
    // The overvote indicator must count toward the limit (§3.3.9 p.39); the write-in count may.
    [InlineData(SupplementalFieldKind.OvervoteIndicator, false, "must count toward the selection limit")]
    [InlineData(SupplementalFieldKind.OvervoteIndicator, true, null)]
    [InlineData(SupplementalFieldKind.WriteInCount, true, null)]
    [InlineData(SupplementalFieldKind.WriteInCount, false, null)]
    // The null-vote indicator must not, because p.39's optional L-times-null relation is not
    // implemented (Q2); the two undervote kinds must not, because on an overvote they are nonzero
    // while the overvote term takes the whole limit. Each refusal gives its own reason.
    [InlineData(SupplementalFieldKind.NullVoteIndicator, true, "not implemented")]
    [InlineData(SupplementalFieldKind.UndervoteIndicator, true, "on an overvoted contest it is nonzero")]
    [InlineData(SupplementalFieldKind.UndervoteDifferenceCount, true, "on an overvoted contest it is nonzero")]
    [InlineData(SupplementalFieldKind.UndervoteDifferenceCount, false, null)]
    public void Validate_CountsTowardSelectionLimit_OnlyWhereEveryHonestBallotHasAProof(SupplementalFieldKind kind, bool counts, string? reason)
    {
        var manifest = WithFields([Field("field", 3, kind, counts)]);

        var exception = Record.Exception(manifest.Validate);

        if (reason is null)
        {
            Assert.Null(exception);
        }
        else
        {
            var invalid = Assert.IsType<InvalidManifestException>(exception);
            Assert.Contains(reason, invalid.Message);
        }
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
                SupplementalFields = [Field("overvotes", 3, SupplementalFieldKind.OvervoteIndicator, counts: true)],
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
        var manifest = WithFields(ElectionFixtureBuilder.SupplementalFields(2, ElectionFixtureBuilder.AllSupplementalFields, writeInsCountTowardLimit: true), writeInFieldCount: 3);
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
