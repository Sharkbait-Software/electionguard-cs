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
