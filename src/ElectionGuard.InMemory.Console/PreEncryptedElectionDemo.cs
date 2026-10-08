using ElectionGuard.Core.BallotEncryption;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using ElectionGuard.Core.PreEncryption;
using ElectionGuard.Core.Serialization;
using ElectionGuard.Core.Serialization.Converters;
using ElectionGuard.Core.Tally;
using ElectionGuard.Core.Verify.Ballot;
using ElectionGuard.Core.Verify.KeyGeneration;
using ElectionGuard.Core.Verify.PreEncryption;
using ElectionGuard.Core.Verify.Tally;
using System.Text.Json;

/// <summary>
/// Pre-encrypted ballots (§4) end to end, in an election of their own: an election that uses them
/// names a hash-trimming function and declares no supplemental fields or contest data
/// (Manifest.Validate, S9), so it cannot share the main demo's manifest. A device pre-encrypts four
/// ballots on a simple chain (§4.1.4), the guardians decrypt each ballot nonce for the recording tool
/// (§4.3.1), three are recorded as cast and one as uncast (§4.3), and two regular ballots are
/// encrypted on another device. The cast pre-encrypted ballots are tallied together with the regular
/// ones (§4: "Ordinary and pre-encrypted ballots can be tallied together") and every verification
/// that applies runs: 1-7 and 9-11 on the mixed set, 8 on the regular ballots, 15-17 on the cast
/// records, 16-19 on the uncast one, and 16's device walk over the pre-encrypting device. The
/// decrypted counts are checked against the selections.
/// </summary>
internal static class PreEncryptedElectionDemo
{
    public static void Run(string outputDirectory)
    {
        var manifest = new Manifest
        {
            ElectionId = "pre-encrypted-demo",
            Contests =
            [
                new Contest
                {
                    Id = "mayor",
                    Name = "Mayor",
                    SelectionLimit = 1,
                    OptionSelectionLimit = 1,
                    Index = 1,
                    Choices = new[] { "Ada", "Grace", "Alan" }.Select((name, i) => new Choice { Id = $"mayor-{name.ToLowerInvariant()}", Name = name, Index = i + 1 }).ToList(),
                },
                new Contest
                {
                    Id = "council",
                    Name = "Council (vote for two)",
                    SelectionLimit = 2,
                    OptionSelectionLimit = 1,
                    Index = 2,
                    Choices = new[] { "Barbara", "Claude", "Donald", "Edsger" }.Select((name, i) => new Choice { Id = $"council-{name.ToLowerInvariant()}", Name = name, Index = i + 1 }).ToList(),
                },
            ],
            BallotStyles = [new BallotStyle { Id = "style-1", Name = "Style 1", ContestIds = ["mayor", "council"] }],
            ChainingMode = ChainingMode.Simple,
            HashTrimmingFunction = HashTrimmingFunction.LetterDigit,
        };
        var manifestFile = new ManifestFile { Bytes = JsonSerializer.SerializeToUtf8Bytes(manifest) };
        var (record, tallyGuardians) = KeyCeremony(manifest, manifestFile);

        // Voter selections by ballot: mayor option numbers, council option numbers.
        (string Id, int[] Mayor, int[] Council)[] regularVotes = [("regular-1", [1], [1, 2]), ("regular-2", [2], [3])];
        (string Id, int[] Mayor, int[] Council)[] preEncryptedVotes = [("pre-1", [1], [2, 4]), ("pre-2", [3], [1]), ("pre-3", [], []), ("pre-4", [2], [3, 4])];
        const string UncastId = "pre-3";

        // Regular ballots on their own device (§3.3).
        const string regularDevice = "Regular device";
        var regularChain = new DeviceChain(record, regularDevice);
        var regularEncryptor = new BallotEncryptor(record, regularDevice, regularChain.DeviceInformationHash);
        var regularBallots = regularVotes.Select(vote =>
        {
            var ballot = regularEncryptor.EncryptNext(Selections(manifest, vote.Id, vote.Mayor, vote.Council), regularChain);
            ballot.RecordStatus(BallotStatus.Cast);
            return ballot;
        }).ToList();
        var regularDeviceRecord = regularChain.Close();

        // The encrypting tool prints four ballots on one device's chain (§4.2, §4.1.4).
        const string printer = "Ballot printer 1";
        var printerChain = DeviceChain.ForPreEncryptedBallots(record, printer);
        var preEncryptor = new BallotPreEncryptor(record, printer);
        var printed = preEncryptedVotes.Select(vote => preEncryptor.PreEncryptNext(vote.Id, "style-1", printerChain)).ToList();
        var printerRecord = printerChain.Close();

        // Before voting the printer commits to the list of ballots it issued (user decision Q31; a
        // library format, not the spec's). Every guardian holds the same list, which it confirms by
        // the commitment, and its own view of the record's cast ballots, which grows as ballots are
        // published. In-process, one copy of each stands in for every guardian's.
        var issued = IssuedPreEncryptedBallots.FromPrintedBallots(record.ExtendedBaseHash, printed);
        var publishedCast = PublishedCastBallots.FromRecord(record.ExtendedBaseHash, regularBallots);

        // The recording tool's wrapper has the guardians decrypt each ballot nonce (§4.3.1), then
        // records the ballot as cast with the voter's selections, or as uncast (§4.3). A guardian
        // decrypts an issued ballot's nonce once, and never one that matches a cast ballot.
        var admin = new TallyAdmin();
        var tool = new BallotRecordingTool(record);
        var castBallots = new List<EncryptedBallot>();
        var uncastBallots = new List<PreEncryptedUncastBallot>();
        foreach (var (ballot, vote) in printed.Zip(preEncryptedVotes))
        {
            var ballotNonce = admin.DecryptPreEncryptedBallotNonce(tallyGuardians, ballot, record, publishedCast, issued);
            if (vote.Id == UncastId)
            {
                uncastBallots.Add(tool.RecordUncast(ballot, ballotNonce));
            }
            else
            {
                var cast = tool.RecordCast(ballot, ballotNonce, Selections(manifest, vote.Id, vote.Mayor, vote.Council));
                castBallots.Add(cast);
                publishedCast.Add(cast);
            }
        }

        // A second request for a recorded ballot's nonce, or one for a regular cast ballot's values
        // dressed as a pre-encrypted ballot, would reveal its votes; the guardians refuse both.
        var regularDressedAsPreEncrypted = printed[0] with
        {
            Id = regularBallots[0].Id,
            SelectionEncryptionIdentifier = regularBallots[0].SelectionEncryptionIdentifier,
            SelectionEncryptionIdentifierHash = regularBallots[0].SelectionEncryptionIdentifierHash,
            EncryptedBallotNonce = regularBallots[0].EncryptedBallotNonce,
        };
        foreach (var request in new[] { printed[0], regularDressedAsPreEncrypted })
        {
            try
            {
                admin.DecryptPreEncryptedBallotNonce(tallyGuardians, request, record, publishedCast, issued);
                throw new InvalidOperationException($"Pre-encrypted demo: the guardians decrypted ballot {request.Id}'s nonce a second time.");
            }
            catch (BallotNonceDecryptionRefusedException)
            {
            }
        }

        Console.WriteLine($"Issued list of {issued.Count} pre-encrypted ballots, commitment {Convert.ToHexString(issued.Commitment)[..16]}...; the guardians refused a repeated request and a regular ballot dressed as pre-encrypted.");

        // Verifications 1-4.
        new ParameterVerification().Verify(record);
        new GuardianPublicKeyVerification().Verify(record.Guardians);
        new ElectionPublicKeyVerification().Verify(record.Guardians, record.ElectionPublicKeys);
        new ExtendedBaseHashVerification().Verify(record.ExtendedBaseHash, record.ElectionBaseHash, record.ElectionPublicKeys);

        // Verification 5 over every ballot, pre-encrypted ones included (p.64).
        var identifiers = new SelectionEncryptionIdentifierVerification();
        identifiers.Verify(regularBallots.Concat(castBallots).Select(x => x.SelectionEncryptionIdentifier)
            .Concat(uncastBallots.Select(x => x.Ballot.SelectionEncryptionIdentifier)).ToList());
        foreach (var ballot in regularBallots.Concat(castBallots))
        {
            identifiers.Verify(ballot.SelectionEncryptionIdentifier, ballot.SelectionEncryptionIdentifierHash, record.ExtendedBaseHash);
        }

        foreach (var uncast in uncastBallots)
        {
            identifiers.Verify(uncast.Ballot.SelectionEncryptionIdentifier, uncast.Ballot.SelectionEncryptionIdentifierHash, record.ExtendedBaseHash);
        }

        // Verifications 6 and 7 on every cast ballot, the combined vectors of pre-encrypted ones included.
        foreach (var ballot in regularBallots.Concat(castBallots))
        {
            new SelectionEncryptionsWellFormedVerification().Verify(ballot, record);
            new AdherenceToVoteLimitsVerification().Verify(ballot, record);
        }

        // Verification 8 on the regular ballots only (p.64).
        foreach (var ballot in regularBallots)
        {
            new ConfirmationCodeVerification().Verify(ballot, record);
        }

        new ConfirmationCodeVerification().VerifyDevices([regularDeviceRecord], regularBallots, record);

        // Verifications 15-17 on the cast records, 16-19 on the uncast ones, and 16's walk over the
        // printer's chain, which lists cast and uncast ballots alike.
        var printerHash = printerChain.DeviceInformationHash;
        var confirmationCodes = new PreEncryptedConfirmationCodeVerification();
        var previousCodes = printerRecord.ConfirmationCodes.Select(x => (ConfirmationCode?)x).Prepend(null).ToList();
        ConfirmationCode? PreviousCode(ConfirmationCode code) => previousCodes[printerRecord.ConfirmationCodes.IndexOf(code)];
        foreach (var cast in castBallots)
        {
            new SelectionVectorAccumulationVerification().Verify(cast, record);
            confirmationCodes.Verify(cast, printerHash, record, PreviousCode(cast.ConfirmationCode));
            new ShortCodeVerification().Verify(cast, record);
        }

        foreach (var uncast in uncastBallots)
        {
            confirmationCodes.Verify(uncast.Ballot, printerHash, record, PreviousCode(uncast.Ballot.ConfirmationCode));
            new ShortCodeVerification().Verify(uncast.Ballot, record);
            new UncastBallotEncryptionVerification().Verify(uncast, record);
            new UncastBallotContentVerification().Verify(manifest, uncast);
        }

        confirmationCodes.VerifyDevices([printerRecord], castBallots, uncastBallots, record);

        // One tally over regular and cast pre-encrypted ballots; Verifications 9-11.
        var submitted = regularBallots.Concat(castBallots).ToList();
        var encryptedTally = new EncryptedTally(manifest);
        encryptedTally.AddBallots(submitted);
        new BallotAggregationVerification().Verify(submitted, manifest, encryptedTally);
        var decryptedTally = admin.Decrypt(tallyGuardians, encryptedTally, record);
        new TallyDecryptionVerification().Verify(record, encryptedTally, decryptedTally);
        var contestIds = submitted.SelectMany(x => x.Contests.Select(c => c.Id))
            .Concat(uncastBallots.SelectMany(x => x.Ballot.Contests.Select(c => c.ContestId)))
            .ToHashSet(StringComparer.Ordinal);
        new TallyContentsVerification().Verify(manifest, decryptedTally, contestIds);

        // The counts must be the selections of the regular and the cast pre-encrypted ballots.
        var counted = regularVotes.Concat(preEncryptedVotes.Where(x => x.Id != UncastId)).ToList();
        foreach (var contest in manifest.Contests)
        {
            for (int j = 1; j <= contest.Choices.Count; j++)
            {
                int expected = counted.Count(vote => (contest.Id == "mayor" ? vote.Mayor : vote.Council).Contains(j));
                int actual = decryptedTally.Contests[contest.Id].Choices[contest.Choices[j - 1].Id].VoteCount;
                if (actual != expected)
                {
                    throw new InvalidOperationException($"Pre-encrypted demo: {contest.Choices[j - 1].Id} decrypted to {actual}, expected {expected}.");
                }
            }
        }

        foreach (var cast in castBallots)
        {
            var codes = string.Join("; ", cast.PreEncryptedContests!.Select(c => $"{c.ContestId}: {string.Join(" ", c.SelectedVectors.Select(v => v.ShortCode))}"));
            Console.WriteLine($"Pre-encrypted ballot {cast.Id} cast, short codes {codes}.");
        }

        foreach (var uncast in uncastBallots)
        {
            Console.WriteLine($"Pre-encrypted ballot {uncast.Ballot.Id} uncast; its {uncast.Contests.Sum(c => c.Selections.Sum(s => s.Nonces.Count))} encryption nonces are released.");
        }

        var tally = string.Join(", ", manifest.Contests.SelectMany(c => c.Choices.Select(o => $"{o.Id}: {decryptedTally.Contests[c.Id].Choices[o.Id].VoteCount}")));
        Console.WriteLine($"Pre-encrypted demo tally ({regularBallots.Count} regular + {castBallots.Count} pre-encrypted cast ballots): {tally}. Verifications 1-11 and 15-19 passed.");

        // The pre-encrypted part of the election record.
        string directory = Path.Combine(outputDirectory, "pre-encrypted");
        Directory.CreateDirectory(directory);
        var ballotSerializer = new JsonEncryptedBallotSerializer();
        foreach (var ballot in submitted)
        {
            using var stream = File.Create(Path.Combine(directory, $"{ballot.Id}.json"));
            ballotSerializer.Serialize(stream, ballot);
        }

        var preEncryptedSerializer = new JsonPreEncryptedBallotSerializer();
        foreach (var uncast in uncastBallots)
        {
            using var stream = File.Create(Path.Combine(directory, $"{uncast.Ballot.Id}-uncast.json"));
            preEncryptedSerializer.Serialize(stream, uncast);
        }

        using (var stream = File.Create(Path.Combine(directory, "device-chains.json")))
        {
            new JsonDeviceChainRecordSerializer().Serialize(stream, [regularDeviceRecord, printerRecord]);
        }

        var tallyJsonOptions = new JsonSerializerOptions { Converters = { new IntegerModPJsonConverter(), new IntegerModQJsonConverter() } };
        File.WriteAllBytes(Path.Combine(directory, "tally.json"), JsonSerializer.SerializeToUtf8Bytes(decryptedTally, tallyJsonOptions));
    }

    private static Ballot Selections(Manifest manifest, string id, int[] mayor, int[] council) => new()
    {
        Id = id,
        BallotStyleId = "style-1",
        Contests = manifest.Contests.Select(contest => new BallotContest
        {
            Id = contest.Id,
            Choices = contest.Choices.Select(option => new BallotChoice
            {
                Id = option.Id,
                SelectionValue = (contest.Id == "mayor" ? mayor : council).Contains(option.Index) ? 1 : 0,
            }).ToList(),
        }).ToList(),
    };

    /// <summary>The key ceremony of Program.cs (§3.2) for this election's manifest, and the guardians' decryption handles.</summary>
    private static (EncryptionRecord Record, List<TallyGuardian> Guardians) KeyCeremony(Manifest manifest, ManifestFile manifestFile)
    {
        var electionBaseHash = new ElectionBaseHash(EGParameters.ParameterBaseHash, manifestFile);
        var guardians = Enumerable.Range(1, EGParameters.GuardianParameters.N).Select(i => new Guardian(new GuardianIndex(i))).ToList();
        var views = guardians.Select(x => x.GenerateKeys().ToPublicView()).ToList();
        var shares = guardians.SelectMany(g => g.EncryptShares(views.Where(x => x.Index != g.Index).ToList())).ToList();
        var secretShares = guardians.ToDictionary(g => g.Index, g => g.DecryptShares(shares.Where(x => x.DestinationIndex == g.Index).ToList()));
        var keys = new ElectionPublicKeys(views.Select(x => x.VoteEncryptionCommitments[0]), views.Select(x => x.OtherBallotDataEncryptionCommitments[0]));

        var guardianRecord = new GuardianRecord
        {
            CryptographicParameters = EGParameters.CryptographicParameters,
            GuardianParameters = EGParameters.GuardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = views,
            ElectionPublicKeys = keys,
        };
        foreach (var guardian in guardians)
        {
            guardian.Verify(guardianRecord, manifestFile);
        }

        var record = new EncryptionRecord
        {
            CryptographicParameters = EGParameters.CryptographicParameters,
            GuardianParameters = EGParameters.GuardianParameters,
            ParameterBaseHash = EGParameters.ParameterBaseHash,
            ManifestFile = manifestFile,
            ElectionBaseHash = electionBaseHash,
            Guardians = views,
            ElectionPublicKeys = keys,
            ExtendedBaseHash = new ExtendedBaseHash(electionBaseHash, keys),
            Manifest = manifest,
        };

        return (record, guardians.Select(g => new TallyGuardian(g.Index, secretShares[g.Index])).ToList());
    }
}
