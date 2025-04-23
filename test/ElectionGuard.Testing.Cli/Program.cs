using Bogus;
using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.Models;
using System.Collections.Generic;
using System.Text.Json;

string outputDirectory = @"c:\temp\eg\data\1";
var jsonSerializerOptions = new JsonSerializerOptions
{
    WriteIndented = true,
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
};

var manifest = GenerateManifest(1, 1, 1, outputDirectory);
GenerateTestBallots(manifest, 3, outputDirectory);

Manifest GenerateManifest(int numContests, int averageContestsPerBallot, int numBallotStyles, string outputDirectory)
{
    Faker faker = new Faker();

    List<Contest> contests = new();

    for (int i = 0; i < numContests; i++)
    {
        int selectionLimit = faker.Random.WeightedRandom(new[] { 1, 2, 3 }, new[] { 0.8f, 0.1f, 0.1f });
        int numChoices = faker.Random.WeightedRandom(new[] { selectionLimit * 2, selectionLimit * 2 + 1, selectionLimit * 2 * 2 }, new[] { 0.6f, 0.3f, 0.1f });
        List<Choice> choices = new();
        for (int j = 0; j < numChoices; j++)
        {
            var choice = new Choice
            {
                Id = $"{i}-{j}",
                Name = $"{faker.Person.FirstName} {faker.Person.LastName}",
                Index = j,
            };
            choices.Add(choice);
        }

        var contest = new Contest
        {
            Id = i.ToString(),
            Name = faker.Name.JobTitle(),
            SelectionLimit = selectionLimit,
            OptionSelectionLimit = 1,
            Index = i,
            Choices = choices,
        };

        contests.Add(contest);
    }

    List<BallotStyle> ballotStyles = new();
    for (int i = 0; i < numBallotStyles; i++)
    {
        var randomContestIds = contests.OrderBy(x => Guid.NewGuid())
            .Take(averageContestsPerBallot)
            .Select(x => x.Id)
            .ToList();

        var ballotStyle = new BallotStyle
        {
            Id = i.ToString(),
            Name = faker.Address.City(),
            ContestIds = randomContestIds,
        };
        ballotStyles.Add(ballotStyle);
    }

    var manifest = new Manifest
    {
        ElectionId = Guid.NewGuid().ToString(),
        Contests = contests,
        BallotStyles = ballotStyles,
        OptionalContestDataMaxLength = 0,
        IncludeOvervotes = true,
        IncludeNullvotes = true,
        IncludeUndervotes = true,
        IncludeWriteins = true,
        ChainingMode = ChainingMode.None,
    };

    var serializedManifest = JsonSerializer.Serialize(manifest, jsonSerializerOptions);
    File.WriteAllBytes(Path.Combine(outputDirectory, "manifest.json"), System.Text.Encoding.UTF8.GetBytes(serializedManifest));

    return manifest;
}

void GenerateTestBallots(Manifest manifest, int numBallots, string outputDirectory)
{
    Faker faker = new Faker();
    string ballotDirectory = Path.Combine(outputDirectory, "ballots");
    Directory.CreateDirectory(ballotDirectory);

    var tally = new Tally
    {
        Contests = manifest.Contests.Select(x => new ContestTally
        {
            ContestId = x.Id,
            NumOvervotes = 0,
            NumNullVotes = 0,
            NumUnderVotes = 0,
            NumWriteIns = 0,
            Choices = x.Choices.Select(c => new ChoiceTally
            {
                ChoiceId = c.Id,
                NumVotes = 0,
            }).ToList(),
        }).ToList(),
    };


    for(int i = 0; i < numBallots; i++)
    {
        var randomBallotStyle = manifest.BallotStyles[faker.Random.Int(0, manifest.BallotStyles.Count - 1)];

        List<BallotContest> contests = new();
        foreach(var contestId in randomBallotStyle.ContestIds)
        {
            var contest = manifest.Contests.Single(x => x.Id == contestId);
            var tallyContest = tally.Contests.Single(x => x.ContestId == contestId);

            bool isOvervote = false;
            int numUndervotes = 0;
            bool isNullvote = false;
            int numWriteIns = 0;

            // 5% chance of writein
            // 4% chance of undervote
            // 1% chance of overvote
            var rv = faker.Random.Number(0, 99);
            if(rv < 1)
            {
                isOvervote = true;
                tallyContest.NumOvervotes++;
            }
            else if (rv < 5)
            {
                numUndervotes = faker.Random.Number(1, contest.SelectionLimit);
                tallyContest.NumUnderVotes += numUndervotes;
                if (numUndervotes == contest.SelectionLimit)
                {
                    isNullvote = true;
                    tallyContest.NumNullVotes++;
                }
            }
            else if(rv < 10)
            {
                numWriteIns = faker.Random.Number(contest.SelectionLimit, contest.SelectionLimit);
                tallyContest.NumWriteIns += numWriteIns;
            }

            int numSelectionsLeft = contest.SelectionLimit - numUndervotes - numWriteIns;

            var choices = contest.Choices.Select(x => x.Id);
            float left = 1.0f;
            List<float> weights = new();
            foreach(var choice in choices)
            {
                var weight = left * 0.6f;
                left = left - weight;
                weights.Add(weight);
            }

            if(left > 0)
            {
                weights[0] += left;
            }
            else if(left < 0)
            {
                weights[0] -= left;
            }

            HashSet<string> selections = new();

            for (int j = 0; j < numSelectionsLeft; j++)
            {
                var selectedChoice = faker.Random.WeightedRandom(choices.ToArray(), weights.ToArray());
                selections.Add(selectedChoice);

                var tallyChoice = tallyContest.Choices.Single(x => x.ChoiceId == selectedChoice);
                tallyChoice.NumVotes++;
            }

            var ballotContest = new BallotContest
            {
                Id = contest.Id,
                NumWriteinsSelected = numWriteIns,
                ContestData = null,
                Choices = contest.Choices
                    .Select(x => new BallotChoice
                    {
                        Id = x.Id,
                        SelectionValue = 
                            isOvervote ? 1 : 
                            isNullvote ? 0 : 
                            selections.Contains(x.Id) ? 1 : 
                            0,
                    })
                    .ToList(),
            };

            contests.Add(ballotContest);
        }

        var ballot = new Ballot
        {
            Id = i.ToString(),
            BallotStyleId = randomBallotStyle.Id,
            Contests = contests,
        };

        var serializedBallot = JsonSerializer.Serialize(ballot, jsonSerializerOptions);
        File.WriteAllBytes(Path.Combine(ballotDirectory, $"{i}.json"), System.Text.Encoding.UTF8.GetBytes(serializedBallot));
    }

    var serializedTally = JsonSerializer.Serialize(tally, jsonSerializerOptions);
    File.WriteAllBytes(Path.Combine(outputDirectory, $"expected-tally.json"), System.Text.Encoding.UTF8.GetBytes(serializedTally));
}

public class Tally
{
    public required List<ContestTally> Contests { get; set; } = new();
}

public class ContestTally
{
    public required string ContestId { get; set; }
    public required int NumOvervotes { get; set; }
    public required int NumNullVotes { get; set; }
    public required int NumUnderVotes { get; set; }
    public required int NumWriteIns { get; set; }
    public required List<ChoiceTally> Choices { get; set; } = new();
}

public class ChoiceTally
{
    public required string ChoiceId { get; set; }
    public required int NumVotes { get; set; }
}