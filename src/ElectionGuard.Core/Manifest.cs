namespace ElectionGuard.Core;

public record Manifest
{
    public required string Label { get; init; }
    public required List<Contest> Contests { get; init; }
    public required List<BallotStyle> BallotStyles { get; init; }
}

public record Contest
{
    public required string Label { get; init; }
    public required int SelectionLimit { get; init; }
    public required List<Option> Options { get; init; }
}

public record Option
{
    public required string Label { get; init; }
}

public record BallotStyle
{
    public required string Label { get; init; }
    public required List<int> ContestIndexes { get; init; }
}
