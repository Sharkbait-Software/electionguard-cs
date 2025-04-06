namespace ElectionGuard.Core.Models;

public record Manifest
{
    public required string ElectionId { get; init; }
    public required List<Contest> Contests { get; init; }
    public required List<BallotStyle> BallotStyles { get; init; }
    public required int OptionalContestDataMaxLength { get; init; }
}

public record Contest
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required int SelectionLimit { get; init; }
    public required int OptionSelectionLimit { get; init; }
    public required int Index { get; init; }
    public required List<Choice> Choices { get; init; }
}

public record Choice
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required int Index { get; init; }
}

public record BallotStyle
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required List<string> ContestIds { get; init; }
}
