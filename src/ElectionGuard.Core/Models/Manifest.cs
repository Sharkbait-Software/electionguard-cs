using ElectionGuard.Core.PreEncryption;
using System.Text.Json.Serialization;

namespace ElectionGuard.Core.Models;

public record Manifest
{
    public required string ElectionId { get; init; }
    public required List<Contest> Contests { get; init; }
    public required List<BallotStyle> BallotStyles { get; init; }
    public required int OptionalContestDataMaxLength { get; init; }
    public bool IncludeOvervotes { get; init; }
    public bool IncludeNullvotes { get; init; }
    public bool IncludeUndervotes { get; init; }
    public bool IncludeWriteins { get; init; }
    public ChainingMode ChainingMode { get; init; }

    /// <summary>
    /// §4.1.5: the hash-trimming function that turns selection hashes into short codes on
    /// pre-encrypted ballots. Null when the election does not use pre-encrypted ballots; omitted
    /// from JSON then, so manifests that do not use it serialize exactly as before.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public HashTrimmingFunction? HashTrimmingFunction { get; init; }
}

public enum ChainingMode
{
    None = 0,
    Simple = 1,
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
