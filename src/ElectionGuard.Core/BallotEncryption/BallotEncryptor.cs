using ElectionGuard.Core.Crypto;
using ElectionGuard.Core.Extensions;
using ElectionGuard.Core.KeyGeneration;
using ElectionGuard.Core.Models;
using System;
using System.Text;

namespace ElectionGuard.Core.BallotEncryption;

public class BallotEncryptor
{
    public BallotEncryptor(EncryptionRecord encryptionRecord)
    {
        _encryptionRecord = encryptionRecord;
    }

    private readonly EncryptionRecord _encryptionRecord;

    public EncryptedBallot Encrypt(Ballot ballot)
    {
        // Validate the ballot
        Validate(ballot);

        var selectionEncryptionIdentifier = new SelectionEncryptionIdentifier(ElectionGuardRandom.GetBytes(32));
        var selectionEncryptionIdentifierHash = new SelectionEncryptionIdentifierHash(_encryptionRecord.ExtendedBaseHash, selectionEncryptionIdentifier);

        var ballotNonce = new BallotNonce(ElectionGuardRandom.GetBytes(32));
        var encryptedBallotNonce = EncryptBallotNonce(ballotNonce, selectionEncryptionIdentifierHash);

        var encryptedContests = new List<EncryptedContest>();
        foreach(var contest in ballot.Contests)
        {
            var encryptedContest = EncryptContest(contest, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedContests.Add(encryptedContest);
        }

        return new EncryptedBallot
        {
            Id = ballot.Id,
            BallotStyleId = ballot.BallotStyleId,
            SelectionEncryptionIdentifierHash = selectionEncryptionIdentifierHash,
            Contests = encryptedContests,
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

    private EncryptedBallotNonce EncryptBallotNonce(BallotNonce ballotNonce, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash)
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

        return new EncryptedBallotNonce
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

        foreach (var choice in contest.Choices)
        {
            var manifestChoice = manifestContest.Choices.Single(x => x.Id == choice.Id);
            var encryptedSelection = EncryptSelection(manifestContest, manifestChoice, choice.SelectionValue, selectionEncryptionIdentifierHash, ballotNonce);
            encryptedSelections.Add(encryptedSelection);
        }

        var alpha = encryptedSelections.Select(x => x.Alpha).Product();
        var beta = encryptedSelections.Select(x => x.Beta).Product();
        var actualSelectionTotal = contest.Choices.Sum(x => x.SelectionValue);
        var aggregateEncryptionNonce = encryptedSelections.Select(x => x.SelectionEncryptionNonce!.Value).Sum();
        
        List<(IntegerModQ u, IntegerModP a, IntegerModP b, IntegerModQ? cj)> commitments = new();

        for (int i = 0; i < manifestContest.SelectionLimit; i++)
        {
            var keyPair = KeyPair.GenerateRandom();
            IntegerModQ u = keyPair.SecretKey;
            IntegerModP a = keyPair.PublicKey;

            IntegerModP b;
            IntegerModQ? cj = null;
            if (actualSelectionTotal == i)
            {
                b = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, u);
            }
            else
            {
                cj = ElectionGuardRandom.GetIntegerModQ();
                var t = u + (actualSelectionTotal - i) * cj.Value;
                b = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, t);
            }
            commitments.Add((u, a, b, cj));
        }

        List<byte[]> bytesToHash = [
            [0x24],
            manifestContest.Index.ToByteArray(),
            alpha,
            beta];
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
            .Select(x => (x.cj ?? cl, x.u - (x.cj ?? cl) * aggregateEncryptionNonce));

        var encryptedContest = new EncryptedContest
        {
            Id = contest.Id,
            Choices = encryptedSelections,
            Proof = challengeResponsePairs.Select(x => new ChallengeResponsePair
            {
                Challenge = x.challenge,
                Response = x.response,
            }).ToArray(),
        };

        return encryptedContest;
    }

    private EncryptedSelection EncryptSelection(Contest contest, Choice choice, int selectionValue, SelectionEncryptionIdentifierHash selectionEncryptionIdentifierHash, BallotNonce ballotNonce)
    {
        IntegerModQ selectionEncryptionNonce = new SelectionNonce(selectionEncryptionIdentifierHash, ballotNonce, contest.Index, choice.Index);
        var alpha = IntegerModP.PowModP(_encryptionRecord.CryptographicParameters.G, selectionEncryptionNonce);
        var beta = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, selectionEncryptionNonce + selectionValue);

        List<(IntegerModQ u, IntegerModP a, IntegerModP b, IntegerModQ? cj)> commitments = new();

        for (int i = 0; i < contest.OptionSelectionLimit; i++)
        {
            var keyPair = KeyPair.GenerateRandom();
            IntegerModQ u = keyPair.SecretKey;
            IntegerModP a = keyPair.PublicKey;

            IntegerModP b;
            IntegerModQ? cj = null;
            if(selectionValue == i)
            {
                b = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, u);
            }
            else
            {
                cj = ElectionGuardRandom.GetIntegerModQ();
                var t = u + (selectionValue - i) * cj.Value;
                b = IntegerModP.PowModP(_encryptionRecord.ElectionPublicKeys.VoteEncryptionKey, t);
            }
            commitments.Add((u, a, b, cj));
        }

        List<byte[]> bytesToHash = [
            [0x24],
            contest.Index.ToByteArray(),
            choice.Index.ToByteArray(),
            alpha,
            beta];
        foreach(var commitment in commitments)
        {
            bytesToHash.Add(commitment.a);
            bytesToHash.Add(commitment.b);
        }

        var c = EGHash.HashModQ(selectionEncryptionIdentifierHash, bytesToHash.ToArray());
        IntegerModQ cSum = new IntegerModQ();
        foreach(var commitment in commitments)
        {
            if(commitment.cj != null)
            {
                cSum += commitment.cj.Value;
            }
        }
        var cl = c - cSum;

        IEnumerable<(IntegerModQ challenge, IntegerModQ response)> challengeResponsePairs = commitments
            .Select(x => (x.cj ?? cl, x.u - (x.cj ?? cl) * selectionEncryptionNonce));

        return new EncryptedSelection
        {
            ChoiceId = choice.Id,
            Alpha = alpha,
            Beta = beta,
            Proof = challengeResponsePairs.Select(x => new ChallengeResponsePair
            {
                Challenge = x.challenge,
                Response = x.response,
            }).ToArray(),
            SelectionEncryptionNonce = selectionEncryptionNonce,
        };
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
}

public class EncryptedBallotNonce
{
    public required byte[] C0 { get; init; }
    public required byte[] C1 { get; init; }
    public required IntegerModQ Challenge { get; init; }
    public required IntegerModQ Response { get; init; }
}