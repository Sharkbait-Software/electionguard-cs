using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;

namespace ElectionGuard.Perf.UnitTests;

public class BallotGeneratorTests
{
    [Fact]
    public void Constructor_ThrowsForAManifestWithADuplicatedChoiceIdInAContest()
    {
        var manifest = new Manifest
        {
            ElectionId = "duplicate-choice-id-election",
            Contests = new List<Contest>
            {
                new Contest
                {
                    Id = "contest-1",
                    Name = "Test Contest",
                    SelectionLimit = 1,
                    OptionSelectionLimit = 1,
                    Index = 1,
                    Choices = new List<Choice>
                    {
                        new Choice { Id = "choice-1", Name = "Choice 1", Index = 1 },
                        new Choice { Id = "choice-1", Name = "Choice 1 (duplicate id)", Index = 2 },
                    },
                },
            },
            BallotStyles = new List<BallotStyle>
            {
                new BallotStyle { Id = "ballot-style-1", Name = "Style 1", ContestIds = new List<string> { "contest-1" } },
            },
        };

        Assert.Throws<ArgumentException>(() => new BallotGenerator(manifest, seed: 1));
    }

    [Fact]
    public void Constructor_ReportsEveryDuplicatedChoiceIdInAContest()
    {
        var manifest = new Manifest
        {
            ElectionId = "multiple-duplicate-choice-ids-election",
            Contests = new List<Contest>
            {
                new Contest
                {
                    Id = "contest-1",
                    Name = "Test Contest",
                    SelectionLimit = 1,
                    OptionSelectionLimit = 1,
                    Index = 1,
                    Choices = new List<Choice>
                    {
                        new Choice { Id = "choice-1", Name = "Choice 1", Index = 1 },
                        new Choice { Id = "choice-1", Name = "Choice 1 (duplicate)", Index = 2 },
                        new Choice { Id = "choice-2", Name = "Choice 2", Index = 3 },
                        new Choice { Id = "choice-2", Name = "Choice 2 (duplicate)", Index = 4 },
                    },
                },
            },
            BallotStyles = new List<BallotStyle>
            {
                new BallotStyle { Id = "ballot-style-1", Name = "Style 1", ContestIds = new List<string> { "contest-1" } },
            },
        };

        var exception = Assert.Throws<ArgumentException>(() => new BallotGenerator(manifest, seed: 1));

        Assert.Contains("choice-1", exception.Message);
        Assert.Contains("choice-2", exception.Message);
    }

    [Fact]
    public void Constructor_ThrowsForAManifestWithNullContests()
    {
        var manifest = new Manifest
        {
            ElectionId = "null-contests-election",
            Contests = null!,
            BallotStyles = new List<BallotStyle>(),
        };

        var exception = Assert.Throws<ArgumentException>(() => new BallotGenerator(manifest, seed: 1));

        Assert.Equal("manifest", exception.ParamName);
        Assert.Contains("Contests", exception.Message);
    }

    [Fact]
    public void Constructor_ThrowsForAContestWithNullChoices()
    {
        var manifest = new Manifest
        {
            ElectionId = "null-choices-election",
            Contests = new List<Contest>
            {
                new Contest
                {
                    Id = "contest-1",
                    Name = "Test Contest",
                    SelectionLimit = 1,
                    OptionSelectionLimit = 1,
                    Index = 1,
                    Choices = null!,
                },
            },
            BallotStyles = new List<BallotStyle>
            {
                new BallotStyle { Id = "ballot-style-1", Name = "Style 1", ContestIds = new List<string> { "contest-1" } },
            },
        };

        var exception = Assert.Throws<ArgumentException>(() => new BallotGenerator(manifest, seed: 1));

        Assert.Equal("manifest", exception.ParamName);
        Assert.Contains("contest-1", exception.Message);
        Assert.Contains("Choices", exception.Message);
    }

    [Fact]
    public void Generate_IsDeterministicForSameSeedAndIndex()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        var first = new BallotGenerator(manifest, seed: 1234).Generate(42);
        var second = new BallotGenerator(manifest, seed: 1234).Generate(42);

        Assert.Equal(Describe(first), Describe(second));
    }

    [Fact]
    public void Generate_DiffersAcrossIndexes()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var generator = new BallotGenerator(manifest, seed: 1234);

        var descriptions = Enumerable.Range(0, 50).Select(i => Describe(generator.Generate(i))).ToList();

        Assert.True(descriptions.Distinct().Count() > 1,
            "50 generated ballots were all identical; the index is not feeding the RNG.");
    }

    [Fact]
    public void Generate_IsIndependentOfCallOrder()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var generator = new BallotGenerator(manifest, seed: 99);

        var forward = Enumerable.Range(0, 20).Select(i => Describe(generator.Generate(i))).ToList();
        var backward = Enumerable.Range(0, 20).Reverse().Select(i => Describe(generator.Generate(i))).Reverse().ToList();

        Assert.Equal(forward, backward);
    }

    [Fact]
    public void Generate_UsesAKnownBallotStyle()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var generator = new BallotGenerator(manifest, seed: 7);

        for (int i = 0; i < 25; i++)
        {
            var ballot = generator.Generate(i);
            Assert.Contains(manifest.BallotStyles, style => style.Id == ballot.BallotStyleId);
        }
    }

    [Fact]
    public void Generate_ProducesEveryContestAndChoiceForTheStyle()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var generator = new BallotGenerator(manifest, seed: 7);

        for (int i = 0; i < 25; i++)
        {
            var ballot = generator.Generate(i);
            var style = manifest.BallotStyles.Single(x => x.Id == ballot.BallotStyleId);

            Assert.Equal(
                style.ContestIds.OrderBy(x => x),
                ballot.Contests.Select(c => c.Id).OrderBy(x => x));

            foreach (var ballotContest in ballot.Contests)
            {
                var manifestContest = manifest.Contests.Single(c => c.Id == ballotContest.Id);
                Assert.Equal(
                    manifestContest.Choices.Select(c => c.Id).OrderBy(x => x),
                    ballotContest.Choices.Select(c => c.Id).OrderBy(x => x));
            }
        }
    }

    [Fact]
    public void Generate_NeverExceedsTheOptionSelectionLimit()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(selectionLimit: 2, optionSelectionLimit: 1);
        var generator = new BallotGenerator(manifest, seed: 55);

        for (int i = 0; i < 200; i++)
        {
            foreach (var contest in generator.Generate(i).Contests)
            {
                var manifestContest = manifest.Contests.Single(c => c.Id == contest.Id);
                Assert.All(contest.Choices, choice =>
                {
                    Assert.InRange(choice.SelectionValue, 0, manifestContest.OptionSelectionLimit);
                });
            }
        }
    }

    [Fact]
    public void Generate_WithOptionLimitAboveOne_UsesValuesUpToR_AndSometimesOvervotesAnOption()
    {
        // S5 (G10): with R > 1 the corpus exercises values in 2..R, and an option above R, which is
        // an overvote of its own; otherwise the egperf gate never sees the R > 1 overvote rule.
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest(selectionLimit: 3, optionSelectionLimit: 3);
        var generator = new BallotGenerator(manifest, seed: 55);

        var values = Enumerable.Range(0, 2000)
            .SelectMany(i => generator.Generate(i).Contests.SelectMany(c => c.Choices).Select(x => x.SelectionValue))
            .ToList();

        Assert.Contains(values, value => value is 2 or 3);
        Assert.Contains(values, value => value == 4);
        Assert.DoesNotContain(values, value => value > 4 || value < 0);
    }

    [Fact]
    public void Generate_UsesWriteInsOnlyInContestsThatOfferThem_WithinTheWriteInFieldCount()
    {
        var (without, _) = ElectionFixtureBuilder.CreateMinimalManifest();
        var (with, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, writeInFieldCount: 3);

        var noWriteIns = Enumerable.Range(0, 500).Select(i => new BallotGenerator(without, seed: 9).Generate(i).Contests[0].NumWriteinsSelected);
        var writeIns = Enumerable.Range(0, 500).Select(i => new BallotGenerator(with, seed: 9).Generate(i).Contests[0].NumWriteinsSelected).ToList();

        Assert.All(noWriteIns, n => Assert.Equal(0, n));
        Assert.Contains(writeIns, n => n > 0);
        Assert.All(writeIns, n => Assert.InRange(n, 0, 3));
    }

    /// <summary>
    /// S6: a contest that declares contest data (b_Λ) gets write-in text exactly on the ballots that
    /// use a write-in field, encoded to 32·b_Λ bytes (the encryptor fills the others with an empty
    /// field). The text comes from the ballot index, not the random stream, so it moves nothing else:
    /// the same seed gives the same selections with or without contest data declared.
    /// </summary>
    [Fact]
    public void Generate_WritesWriteInTextIntoTheContestDataOfBallotsThatUseAWriteIn()
    {
        var (with, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true);
        var (withoutData, _) = ElectionFixtureBuilder.CreateMinimalManifest(includeWriteIns: true, contestDataBlocks: 0);
        Assert.Equal(ElectionFixtureBuilder.DefaultContestDataBlocks, with.Contests[0].ContestDataBlocks);

        var contests = Enumerable.Range(0, 500).Select(i => new BallotGenerator(with, seed: 9).Generate(i).Contests[0]).ToList();
        var plain = Enumerable.Range(0, 500).Select(i => new BallotGenerator(withoutData, seed: 9).Generate(i).Contests[0]).ToList();

        Assert.Contains(contests, c => c.ContestData is not null);
        Assert.All(contests, c => Assert.Equal(c.NumWriteinsSelected > 0, c.ContestData is not null));
        Assert.All(contests.Where(c => c.ContestData is not null), c =>
        {
            Assert.Equal(32 * ElectionFixtureBuilder.DefaultContestDataBlocks, c.ContestData!.Length);
            Assert.StartsWith("Write-in ", ContestDataEncoding.Decode(c.ContestData));
        });
        Assert.All(plain, c => Assert.Null(c.ContestData));
        Assert.Equal(
            plain.Select(c => (c.NumWriteinsSelected, string.Join(",", c.Choices.Select(x => x.SelectionValue)))),
            contests.Select(c => (c.NumWriteinsSelected, string.Join(",", c.Choices.Select(x => x.SelectionValue)))));
    }

    [Fact]
    public void Generate_AssignsTheIndexAsTheBallotId()
    {
        var (manifest, _) = ElectionFixtureBuilder.CreateMinimalManifest();

        Assert.Equal("17", new BallotGenerator(manifest, seed: 1).Generate(17).Id);
    }

    private static string Describe(Ballot ballot) =>
        string.Join("|", new[] { ballot.Id, ballot.BallotStyleId }
            .Concat(ballot.Contests
                .OrderBy(c => c.Id)
                .Select(c => $"{c.Id}:{c.NumWriteinsSelected}:" +
                             string.Join(",", c.Choices.OrderBy(x => x.Id).Select(x => $"{x.Id}={x.SelectionValue}")))));
}
