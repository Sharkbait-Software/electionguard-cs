using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System.Text;

namespace ElectionGuard.Core.BallotEncryption;

public class BallotEncryptor
{
    public BallotEncryptor(EncryptionRecord encryptionRecord, VotingDeviceInformationHash deviceHash)
    {
        _encryptionRecord = encryptionRecord;
        _deviceHash = deviceHash;
    }

    private readonly EncryptionRecord _encryptionRecord;
    private readonly VotingDeviceInformationHash _deviceHash;

    public EncryptedBallot Encrypt(Ballot ballot, ConfirmationCode? previousConfirmationCode)
    {
        Validate(ballot);

        var selectionEncryptionIdentifier = new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32));
        var selectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(_encryptionRecord.ExtendedBaseHash, selectionEncryptionIdentifier);

        var ballotNonce = new BallotNonce(ElectionGuardRandom.GetBytes(32));
        var encryptedBallotNonce = EncryptBallotNonce(ballotNonce, selectionEncryptionIdentifierHash);

        var encryptedContests = new List<EncryptedContest>();
        List<ContestHash> contestHashes = new List<ContestHash>();
        foreach(var contest in ballot.Contests)
        {
            var encryptedContest = EncryptContest(contest, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedContests.Add(encryptedContest);
            contestHashes.Add(encryptedContest.ContestHash);
        }

        var chainingField = new ChainingField(_encryptionRecord.Manifest.ChainingMode, _deviceHash, _encryptionRecord.ExtendedBaseHash, previousConfirmationCode);
        var confirmationCode = new ConfirmationCode(selectionEncryptionIdentifierHash, contestHashes, chainingField);

        return new EncryptedBallot
        {
            Id = ballot.Id,
            BallotStyleId = ballot.BallotStyleId,
            SelectionEncryptionIdentifierHash = selectionEncryptionIdentifierHash,
            Contests = encryptedContests,
            ConfirmationCode = confirmationCode,
            Weight = 1,
        };
    }

    private void Validate(Ballot ballot)
    {
        // All contests exist in the manifest
        foreach(var contest in ballot.Contests)
        {
            var manifestContest = _encryptionRecord.Manifest.Contests.SingleOrDefault(x => x.Id == contest.Id);
            if(manifestContest == null)
            {
                throw new Exception($"Contest with id {contest.Id} not found in manifest.");
            }

            // All choices exist in the manifest
            // All choices are specified for this contest
            var manifestChoices = manifestContest.Choices.Select(x => x.Id).ToList();
            var choices = contest.Choices.Select(x => x.Id).ToList();
            if(manifestChoices.Count != choices.Count
                || manifestChoices.Except(choices).Any()
                || choices.Except(manifestChoices).Any())
            {
                throw new Exception($"Contest with id {contest.Id} did not provide all choice selections from the manifest.");
            }

            // All options for each contest have a selectionValue within the expected limits.
            foreach(var choice in contest.Choices)
            {
                var manifestChoice = manifestContest.Choices.Single(x => x.Id == choice.Id);
                if(choice.SelectionValue < 0 || choice.SelectionValue > manifestContest.OptionSelectionLimit)
                {
                    throw new Exception($"Choice for id {choice.Id} exceeds option selection limit.");
                }
            }

            // Each contest has an allowed number of selections.
            var numberOfSelections = contest.Choices.Where(x => x.SelectionValue > 0).Count();
            if(numberOfSelections > manifestContest.SelectionLimit)
            {
                throw new Exception($"Contest with id {contest.Id} has selections that exceed the contest selection limit.");
            }
        }

        // All contests for the given ballot style are specified.
        var ballotStyle = _encryptionRecord.Manifest.BallotStyles.SingleOrDefault(x => x.Id == ballot.BallotStyleId);
        if(ballotStyle == null)
        {
            throw new Exception($"Could not find ballot style with id {ballot.BallotStyleId} in manifest.");
        }
        var contestIds = ballot.Contests.Select(x => x.Id).ToList();
        if(contestIds.Count != ballotStyle.ContestIds.Count
            || contestIds.Except(ballotStyle.ContestIds).Any()
            || ballotStyle.ContestIds.Except(contestIds).Any())
        {
            throw new Exception($"Ballot with id {ballot.BallotStyleId} did not specify all contestIds for the ballot style.");
        }
    }

    private EncryptedData EncryptBallotNonce(BallotNonce ballotNonce, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash)
    {
        // 3.3.4
        var keyPair = KeyPair.GenerateRandom();
        IntegerModQ epsilon = keyPair.SecretKey;
        IntegerModP alpha = keyPair.PublicKey;
        IntegerModP beta = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey, epsilon);
        var symmetricKey = EGHash.Hash(selectionEncryptionIdentifierHash,
            [0x22],
            alpha,
            beta);
        var k1 = ComputeBallotNonceEncryptionKey(symmetricKey);

        var c0 = alpha;
        var c1 = ballotNonce.ToByteArray().XOR(k1);

        var proof = KeyPair.GenerateRandom();
        var u = proof.SecretKey;
        var commitment = proof.PublicKey;
        var challenge = EGHash.HashModQ(selectionEncryptionIdentifierHash,
            [0x23],
            commitment,
            c0,
            c1);
        var response = u - challenge * epsilon;

        return new EncryptedData
        {
            C0 = c0,
            C1 = c1,
            Challenge = challenge,
            Response = response,
        };
    }

    private EncryptedContest EncryptContest(BallotContest contest, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        var encryptedSelections = new List<EncryptedSelection>();
        var manifestContest = _encryptionRecord.Manifest.Contests.Single(x => x.Id == contest.Id);
        var actualSelectionTotal = contest.Choices.Sum(x => x.SelectionValue);
        var actualCountOfSelections = contest.Choices.Where(x => x.SelectionValue > 0).Count();

        bool isOvervote = actualSelectionTotal > manifestContest.SelectionLimit;
        bool isNullVote = contest.Choices.All(x => x.SelectionValue == 0);
        int numUndervotes = Math.Min(0, manifestContest.SelectionLimit - actualCountOfSelections);
        int numWriteins = contest.NumWriteinsSelected;


        if (isOvervote)
        {
            // Overvote. Per spec, we encrypt values of 0.
            foreach(var choice in contest.Choices)
            {
                choice.SelectionValue = 0;
            }
        }
        
        foreach (var choice in contest.Choices)
        {
            var manifestChoice = manifestContest.Choices.Single(x => x.Id == choice.Id);
            var encryptedSelection = EncryptSelection(manifestContest, manifestChoice, choice.SelectionValue, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedSelections.Add(encryptedSelection);
        }

        var encryptedAggregate = AggregateChoiceValues(encryptedSelections.Select(x => x.ToEncryptedValue()).ToList());
        var proofs = GenerateProofs(actualSelectionTotal, manifestContest.SelectionLimit, encryptedAggregate, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, manifestContest.Index);

        var overVoteCount = EncryptOptionalField(isOvervote ? 1 : 0, 1, manifestContest.Index, selectionEncryptionIdentifierHash, ballotNonce);
        var nullVoteCount = EncryptOptionalField(isNullVote ? 1 : 0, 1, manifestContest.Index, selectionEncryptionIdentifierHash, ballotNonce);
        var underVoteCount = EncryptOptionalField(numUndervotes, manifestContest.SelectionLimit, manifestContest.Index, selectionEncryptionIdentifierHash, ballotNonce);
        var writeInVoteCount = EncryptOptionalField(numWriteins, manifestContest.SelectionLimit, manifestContest.Index, selectionEncryptionIdentifierHash, ballotNonce);

        EncryptedData? encryptedContestData = null;
        if(contest.ContestData != null)
        {
            encryptedContestData = EncryptContestData(contest.ContestData, manifestContest.Index, selectionEncryptionIdentifierHash, ballotNonce);
        }

        var contestHash = new ContestHash(selectionEncryptionIdentifierHash, 
            manifestContest.Index, 
            encryptedSelections,
            overVoteCount,
            nullVoteCount,
            underVoteCount,
            writeInVoteCount,
            encryptedContestData);

        var encryptedContest = new EncryptedContest
        {
            Id = contest.Id,
            Choices = encryptedSelections,
            Proofs = proofs,
            OvervoteCount = overVoteCount,
            NullvoteCount = nullVoteCount,
            UndervoteCount = underVoteCount,
            WriteInVoteCount = writeInVoteCount,
            ContestData = encryptedContestData,
            ContestHash = contestHash,
        };

        return encryptedContest;
    }

    private EncryptedSelection EncryptSelection(Contest contest, Choice choice, int selectionValue, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        var encryptedValue = EncryptContestValue(selectionValue, selectionEncryptionIdentifierHash, ballotNonce, contest.Index, choice.Index);
        var proofs = GenerateProofs(selectionValue, contest.OptionSelectionLimit, encryptedValue, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, contest.Index, choice.Index);

        return new EncryptedSelection
        {
            ChoiceId = choice.Id,
            Alpha = encryptedValue.Alpha,
            Beta = encryptedValue.Beta,
            EncryptionNonce = encryptedValue.EncryptionNonce,
            Proofs = proofs,
        };
    }

    private EncryptedValueWithProofs EncryptOptionalField(int selectionValue, int maxValue, int contestIndex, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        var encryptedValue = EncryptContestValue(selectionValue, selectionEncryptionIdentifierHash, ballotNonce, contestIndex);
        var proofs = GenerateProofs(selectionValue, maxValue, encryptedValue, _encryptionRecord.ElectionPublicKeys, selectionEncryptionIdentifierHash, contestIndex);

        return new EncryptedValueWithProofs
        {
            Alpha = encryptedValue.Alpha,
            Beta = encryptedValue.Beta,
            EncryptionNonce = encryptedValue.EncryptionNonce,
            Proofs = proofs,
        };
    }

    private EncryptedValue EncryptContestValue(int valueToEncrypt, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce, int contestIndex, int? choiceIndex = null)
    {
        IntegerModQ encryptionNonce = new EncryptionNonce(selectionEncryptionIdentifierHash, ballotNonce, contestIndex, choiceIndex);
        var alpha = IntegerModP.PowModP(_encryptionRecord.CryptographicParameters.G, encryptionNonce);
        var beta = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, encryptionNonce + valueToEncrypt);
        return new EncryptedValue
        {
            Alpha = alpha,
            Beta = beta,
            EncryptionNonce = encryptionNonce,
        };
    }

    private EncryptedValue AggregateChoiceValues(List<EncryptedValue> encryptedSelections)
    {
        var alpha = encryptedSelections.Select(x => x.Alpha).Product();
        var beta = encryptedSelections.Select(x => x.Beta).Product();
        var aggregateEncryptionNonce = encryptedSelections.Select(x => x.EncryptionNonce!.Value).Sum();

        return new EncryptedValue
        {
            Alpha = alpha,
            Beta = beta,
            EncryptionNonce = aggregateEncryptionNonce,
        };
    }

    private ChallengeResponsePair[] GenerateProofs(
        int valueToEncrypt, 
        int selectionLimit,
        EncryptedValue encryptedValue,
        ElectionPublicKeys electionPublicKeys,
        SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, 
        int contestIndex, 
        int? choiceIndex = null)
    {
        List<(IntegerModQ u, IntegerModP a, IntegerModP b, IntegerModQ? cj)> commitments = new();

        for (int i = 0; i < selectionLimit; i++)
        {
            var keyPair = KeyPair.GenerateRandom();
            IntegerModQ u = keyPair.SecretKey;
            IntegerModP a = keyPair.PublicKey;

            IntegerModP b;
            IntegerModQ? cj = null;
            if (valueToEncrypt == i)
            {
                b = IntegerModP.PowModP(electionPublicKeys.VoteEncryptionKey, u);
            }
            else
            {
                cj = ElectionGuardRandom.GetIntegerModQ();
                var t = u + (valueToEncrypt - i) * cj.Value;
                b = IntegerModP.PowModP(electionPublicKeys.VoteEncryptionKey, t);
            }
            commitments.Add((u, a, b, cj));
        }

        List<byte[]> bytesToHash = [
            [0x24],
            contestIndex.ToByteArray()];

        if(choiceIndex != null)
        {
            bytesToHash.Add(choiceIndex.Value.ToByteArray());
        }

        bytesToHash.AddRange([
            encryptedValue.Alpha,
            encryptedValue.Beta]);

        foreach (var commitment in commitments)
        {
            bytesToHash.Add(commitment.a);
            bytesToHash.Add(commitment.b);
        }

        var c = EGHash.HashModQ(selectionEncryptionIdentifierHash, bytesToHash.ToArray());
        IntegerModQ cSum = new IntegerModQ();
        foreach (var commitment in commitments)
        {
            if (commitment.cj != null)
            {
                cSum += commitment.cj.Value;
            }
        }
        var cl = c - cSum;

        IEnumerable<(IntegerModQ challenge, IntegerModQ response)> challengeResponsePairs = commitments
            .Select(x => (x.cj ?? cl, x.u - (x.cj ?? cl) * encryptedValue.EncryptionNonce!.Value));

        return challengeResponsePairs.Select(x => new ChallengeResponsePair
        {
            Challenge = x.challenge,
            Response = x.response,
        }).ToArray();
    }

    private byte[] ComputeBallotNonceEncryptionKey(byte[] symmetricKey)
    {
        byte[] key = EGHash.Hash(symmetricKey,
            [0x01],
            Encoding.UTF8.GetBytes("ballot_nonce"),
            [0x00],
            Encoding.UTF8.GetBytes("ballot_nonce_encrypt"),
            [0x01, 0x00]);
        return key;
    }

    private EncryptedData EncryptContestData(string valueToEncrypt, int contestIndex, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        // 3.3.10
        var bytes = Encoding.UTF8.GetBytes(valueToEncrypt);
        var encryptionNonce = EGHash.HashModQ(selectionEncryptionIdentifierHash,
            [0x25],
            contestIndex.ToByteArray(),
            ballotNonce);

        var alpha = IntegerModP.PowModP(_encryptionRecord.CryptographicParameters.G, encryptionNonce);
        var beta = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.OtherBallotDataEncryptionKey, encryptionNonce);
        var secretKey = EGHash.Hash(selectionEncryptionIdentifierHash,
            [0x26],
            contestIndex.ToByteArray(),
            alpha,
            beta);

        List<byte[]> encryptedBlocks = new();

        for (int i = 0; i <= bytes.Length; i += 32)
        {
            int endOfSpan = i + 32;
            if(endOfSpan > bytes.Length)
            {
                endOfSpan = bytes.Length;
            }

            var di = bytes[i..endOfSpan];
            
            // Right pad any remaining bytes.
            if(di.Length < 32)
            {
                var ndi = new byte[32];
                di.CopyTo(ndi, 0);
                di = ndi;
            }

            var ki = EGHash.Hash(secretKey,
                i.ToByteArray(),
                Encoding.UTF8.GetBytes("data_enc_keys"),
                [0x00],
                Encoding.UTF8.GetBytes("contest_data"),
                contestIndex.ToByteArray(),
                (i * 256).ToByteArray());

            var encryptedBlock = di.XOR(ki);
            encryptedBlocks.Add(encryptedBlock);
        }

        var c0 = alpha;
        var c1 = ByteArrayExtensions.Concat(encryptedBlocks.ToArray());

        var proofKeyPair = KeyPair.GenerateRandom();
        var challenge = EGHash.HashModQ(selectionEncryptionIdentifierHash,
            [0x27],
            contestIndex.ToByteArray(),
            proofKeyPair.PublicKey,
            c0,
            c1);
        var response = proofKeyPair.SecretKey - challenge * encryptionNonce;

        return new EncryptedData
        {
            C0 = c0,
            C1 = c1,
            Challenge = challenge,
            Response = response,
        };
    }
}

public class EncryptedData
{
    public required byte[] C0 { get; init; }
    public required byte[] C1 { get; init; }
    public required IntegerModQ Challenge { get; init; }
    public required IntegerModQ Response { get; init; }
}