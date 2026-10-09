using Bogus;
using ElectionGuard.Core.Models;
using ElectionGuard.Testing.Common;
using System.Text.Json;

// This tool's unique value is Bogus-based random MANIFEST generation of arbitrary shape -- nothing
// else in the repo does that. Ballot generation, overvote/nullvote/undervote/write-in accounting
// and the expected-tally.json schema all come from ElectionGuard.Testing.Common, the same library
// perf/ElectionGuard.Perf.Cli's `corpus` command uses, so both tools emit one canonical fixture
// shape regardless of which one produced it.

var jsonSerializerOptions = new JsonSerializerOptions
{
    WriteIndented = true,
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
};

var options = ParseArgs(args);
if (options is null)
{
    PrintUsage();
    return 1;
}

Bogus.Randomizer.Seed = new Random(options.Seed);

Directory.CreateDirectory(options.OutputDirectory);

var manifest = GenerateManifest(options);

// The manifest file in Core's format (ManifestSerializer), which an encryption record parses its
// manifest from and whose bytes H_B hashes.
File.WriteAllBytes(
    Path.Combine(options.OutputDirectory, "manifest.json"),
    ElectionGuard.Core.Serialization.ManifestSerializer.Serialize(manifest));

GenerateBallotsAndTally(manifest, options);

return 0;

Manifest GenerateManifest(Options options)
{
    var faker = new Faker();

    var contests = new List<Contest>();
    for (int i = 0; i < options.NumContests; i++)
    {
        int selectionLimit = faker.Random.WeightedRandom(new[] { 1, 2, 3 }, new[] { 0.8f, 0.1f, 0.1f });
        int numChoices = faker.Random.WeightedRandom(
            new[] { selectionLimit * 2, selectionLimit * 2 + 1, selectionLimit * 2 * 2 },
            new[] { 0.6f, 0.3f, 0.1f });

        // Choice ids are "{contestIndex}-{choiceIndex}", unique within a contest because j runs
        // 0..numChoices-1 without repetition -- BallotGenerator throws if a manifest carries a
        // duplicated choice id within one contest, so this scheme must (and does) stay unique.
        // Indices, unlike ids, are the 1-based list positions §3.1.3 requires: j + 1 and i + 1.
        var choices = new List<Choice>();
        for (int j = 0; j < numChoices; j++)
        {
            choices.Add(new Choice
            {
                Id = $"{i}-{j}",
                Name = $"{faker.Person.FirstName} {faker.Person.LastName}",
                Index = j + 1,
            });
        }

        contests.Add(new Contest
        {
            Id = i.ToString(),
            Name = faker.Name.JobTitle(),
            SelectionLimit = selectionLimit,
            OptionSelectionLimit = 1,
            Index = i + 1,
            Choices = choices,
            // Every supplemental field kind of §3.3.9, indexed after the options; one write-in
            // field, whose use counts toward the selection limit.
            SupplementalFields = ElectionFixtureBuilder.SupplementalFields(numChoices, ElectionFixtureBuilder.AllSupplementalFields),
            WriteInFieldCount = 1,
            // b_Λ (§3.3.10): room for the write-in's text, which every ballot then carries encrypted.
            ContestDataBlocks = ElectionFixtureBuilder.DefaultContestDataBlocks,
        });
    }

    var ballotStyles = new List<BallotStyle>();
    for (int i = 0; i < options.NumBallotStyles; i++)
    {
        // Shuffled with the seeded faker, not Guid.NewGuid(), so the same --seed always produces
        // the same ballot styles. The ballot style's contest list is unordered (§3.1.3); the
        // encryptor puts contests into manifest order itself.
        var randomContestIds = faker.Random.Shuffle(contests)
            .Take(options.ContestsPerBallotStyle)
            .Select(x => x.Id)
            .ToList();

        ballotStyles.Add(new BallotStyle
        {
            Id = i.ToString(),
            Name = faker.Address.City(),
            ContestIds = randomContestIds,
        });
    }

    return new Manifest
    {
        // From the seeded faker too: the manifest bytes feed H_B, so the same --seed should give the same election.
        ElectionId = faker.Random.Guid().ToString(),
        Contests = contests,
        BallotStyles = ballotStyles,
        ChainingMode = ChainingMode.None,
    };
}

void GenerateBallotsAndTally(Manifest manifest, Options options)
{
    var ballotDirectory = Path.Combine(options.OutputDirectory, "ballots");
    Directory.CreateDirectory(ballotDirectory);

    var generator = new BallotGenerator(manifest, options.Seed);
    var accumulator = new ExpectedTallyAccumulator(manifest);

    for (int i = 0; i < options.NumBallots; i++)
    {
        // Accumulate BEFORE encryption/serialization: BallotGenerator's output is never encrypted
        // here, but the accumulator contract (see ExpectedTallyAccumulator) is to record a ballot's
        // contribution from its original, unmodified selection values.
        var ballot = generator.Generate(i);
        accumulator.Add(ballot);

        File.WriteAllBytes(
            Path.Combine(ballotDirectory, $"{i}.json"),
            JsonSerializer.SerializeToUtf8Bytes(ballot, jsonSerializerOptions));
    }

    var document = ExpectedTallyDocument.From(accumulator.Build());
    File.WriteAllBytes(
        Path.Combine(options.OutputDirectory, "expected-tally.json"),
        JsonSerializer.SerializeToUtf8Bytes(document, jsonSerializerOptions));

    Console.WriteLine($"Wrote {options.NumBallots:N0} ballots to {options.OutputDirectory}");
}

Options? ParseArgs(string[] args)
{
    string? output = null;
    int? ballots = null;
    int? seed = null;
    int? numContests = null;
    int? contestsPerBallotStyle = null;
    int? numBallotStyles = null;

    for (int i = 0; i < args.Length; i++)
    {
        if (i + 1 >= args.Length)
        {
            return null;
        }

        var flag = args[i];
        var value = args[++i];

        switch (flag)
        {
            case "--output":
                output = value;
                break;
            case "--ballots":
                if (!TryPositiveInt(value, out var b)) return null;
                ballots = b;
                break;
            case "--seed":
                if (!int.TryParse(value, out var s)) return null;
                seed = s;
                break;
            case "--contests":
                if (!TryPositiveInt(value, out var c)) return null;
                numContests = c;
                break;
            case "--contests-per-ballot":
                if (!TryPositiveInt(value, out var cpb)) return null;
                contestsPerBallotStyle = cpb;
                break;
            case "--ballot-styles":
                if (!TryPositiveInt(value, out var bs)) return null;
                numBallotStyles = bs;
                break;
            default:
                return null;
        }
    }

    if (output is null || ballots is null || seed is null
        || numContests is null || contestsPerBallotStyle is null || numBallotStyles is null)
    {
        return null;
    }

    return new Options(
        output,
        ballots.Value,
        seed.Value,
        numContests.Value,
        contestsPerBallotStyle.Value,
        numBallotStyles.Value);
}

static bool TryPositiveInt(string s, out int value) => int.TryParse(s, out value) && value > 0;

void PrintUsage()
{
    Console.Error.WriteLine("""
        Generates a random manifest (via Bogus) plus plaintext ballots and the matching
        expected-tally.json, in the same schema ElectionGuard.Perf.Cli's `corpus` command writes.

        Usage:
          ElectionGuard.Testing.Cli --output <dir> --ballots <n> --seed <n> --contests <n> --contests-per-ballot <n> --ballot-styles <n>

        Arguments (all required):
          --output               Directory to write manifest.json, ballots/, and expected-tally.json into.
          --ballots               Number of plaintext ballots to generate.
          --seed                  Seed for deterministic ballot generation (also seeds the manifest's random shape).
          --contests              Number of contests in the generated manifest.
          --contests-per-ballot   Number of contests each ballot style includes.
          --ballot-styles         Number of ballot styles in the generated manifest.
        """);
}

sealed record Options(
    string OutputDirectory,
    int NumBallots,
    int Seed,
    int NumContests,
    int ContestsPerBallotStyle,
    int NumBallotStyles);
