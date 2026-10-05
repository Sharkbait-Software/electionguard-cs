# ElectionGuard spec v2.1.0 compliance audit — 2026-10-04

Compared `src/ElectionGuard.Core` against [EG_Spec_2_1.pdf](https://github.com/microsoft/electionguard/releases/tag/v2.1). v2.1.0 is the latest published spec release (2024-08-15).

## Method

- 12 auditors each covered one spec area: hash domain separation, parameters/manifest, key generation, ballot encryption, ballot proofs, confirmation/chaining, tally/decryption, pre-encrypted ballot generation, pre-encrypted ballot verification, verification inventory, crypto engine/side channels, and serialization. A completeness critic then assigned 3 follow-up audits (tests-fixtures-masking, reconcile-conflicting-verdicts, cross-engine-byte-identity).
- Two independent skeptics tried to refute every candidate. One checked the spec: is the quote really there, and what do the page images show where symbols such as overbars matter? The other checked the code: does it really do this, and is that path ever run? **CONFIRMED** means neither skeptic refuted the item. **PLAUSIBLE** means they split.
- 145 candidates went in; 127 were kept and 18 refuted. After merging duplicates, **40 items** remain.
- I re-checked these by hand against the code and spec: G1, G2, G3, G5, G6, G7. All other items rest on the two-lens verification. G39 is PLAUSIBLE, and the spec has no constant-time requirement it could violate.

## Summary

| ID | Sev | Status | Bucket | Known | Title |
|---|---|---|---|---|---|
| G1 | critical | CONFIRMED | divergence |  | Parameter base hash H_P: version key is left-padded and p/q/g are encoded little-endian with sign bytes |
| G2 | critical | CONFIRMED | missing-component |  | Tally decryption has no Chaum-Pedersen proof (§3.6.5, 0x30/0x31), Verification 10 is missing, and DecryptedTally cannot carry T/c/v |
| G3 | high | CONFIRMED | divergence |  | The four supplemental counters (overvote/null/undervote/write-in) share one nonce, with no option index in the nonce or the proof challenge |
| G4 | high | CONFIRMED | divergence |  | Verifiers never check that a ballot lists each manifest option once and each contest once: duplicated contests or options pass V5-V9 and are tallied twice |
| G5 | high | CONFIRMED | divergence |  | Guardian index 0 is accepted, and EncryptShares sends shares to unvalidated indices: P_i(0) = s_i leaks every guardian's secret key |
| G6 | high | CONFIRMED | divergence |  | Election base hash H_B omits the 4-byte manifest length prefix |
| G7 | high | CONFIRMED | divergence |  | Voting device information hash H_DI (regular ballots) is missing its 0x2A domain separator |
| G8 | medium | CONFIRMED | divergence |  | Supplemental counters are always encrypted and hashed into the contest hash, ignoring the manifest's (election-wide, never-read) Include* flags, in a fixed order |
| G9 | medium | CONFIRMED | divergence |  | Contests and options are hashed in the caller's ballot list order, not manifest/index order, and Verification 8 accepts any order |
| G10 | medium | CONFIRMED | divergence |  | Overvote threshold is L*R instead of L: for R>1 a total in (L, L*R] is neither neutralized nor valid (invalid contest proof); a single option above R throws |
| G11 | medium | CONFIRMED | divergence |  | Contest-data KDF (eq 66) uses the byte offset as its counter and i*256 as its length field, and D_Λ is not fixed to 32*b_Λ (length leak, extra zero block) |
| G12 | medium | CONFIRMED | divergence |  | Contest/option Index is a free manifest field used directly in every hash, never checked to be unique, 1-based and positional; the shared fixtures and the corpus generator are 0-based |
| G13 | medium | CONFIRMED | divergence |  | Verification 5.A cannot detect duplicate identifiers: SelectionEncryptionIdentifier compares its byte[] by reference |
| G14 | medium | CONFIRMED | divergence |  | Verification 2 does not check for exactly k commitments and k+1 responses: an unproven extra commitment K_{i,k} is accepted, raising the decryption threshold |
| G15 | medium | CONFIRMED | divergence |  | DecryptShares/Guardian.Verify do not require exactly one share from each other guardian: duplicate or missing shares yield a wrong z_i with no error at key generation |
| G16 | medium | CONFIRMED | divergence |  | Tally discrete-log bound is BallotsCast, ignoring ballot weights (eq 80) and OptionSelectionLimit > 1, so valid elections fail to decrypt |
| G17 | medium | CONFIRMED | missing-component |  | Regular EncryptedBallot drops the encrypted ballot nonce C_ξB: it is computed and then discarded |
| G18 | medium | CONFIRMED | missing-component |  | Challenged-ballot handling is entirely missing: no §3.6.7 ballot-nonce decryption, no Verification 13 or 14, no model for challenged-ballot decryptions |
| G19 | medium | CONFIRMED | missing-component |  | Chain-closing hash never computed (eqs 77/78, 0x2B; 118/120, 0x44); 8.G and 16.H are unimplemented and the record has no per-device ordered list |
| G20 | medium | CONFIRMED | divergence | V9-2 | V9 iterates the claimed tally's contests and options instead of the manifest's |
| G21 | medium | CONFIRMED | missing-component | V9-3 | EncryptedBallot has no cast/challenged status; aggregation and V9 count every ballot they are given |
| G22 | low | CONFIRMED | divergence |  | Supplemental-field semantics and proofs: undervote count uses the number of nonzero options instead of L - sum, write-in bound is L and unvalidated, and V6/V7 never check these ciphertexts or proofs |
| G23 | low | CONFIRMED | divergence |  | Deserializers silently reduce out-of-range or over-long integers mod p/q, making the 0<=x<p and 0<=x<q halves of 2.A/2.B, 6.A-C and 7.A-C unenforceable; id_B length is never checked |
| G24 | low | CONFIRMED | divergence |  | Verification 16 does no structural checks (ballot-style contest set, m+L vectors per contest, m entries per vector) |
| G25 | low | CONFIRMED | divergence |  | V2/V3 (and EncryptShares) do not check that exactly n guardians with distinct indices 1..n are present |
| G26 | low | CONFIRMED | divergence |  | Verification 1.F is effectively never performed: the 5-arg overload compares byte[] by reference (always throws), nothing calls it, guardians never check H_B, and EncryptionRecord lacks manifest bytes and H_B |
| G27 | low | CONFIRMED | missing-component |  | Verification 11 (tally contents vs manifest, 11.A-11.D) is not implemented |
| G28 | low | CONFIRMED | divergence |  | Lagrange coefficient throws when a single guardian decrypts (/U/ = 1, allowed when k = 1) |
| G29 | low | CONFIRMED | missing-component | V9-1 | Overvote/Nullvote/Undervote/WriteIn counts are never aggregated, so neither the tally nor V9 covers them |
| G30 | low | CONFIRMED | divergence | V9-4 | Ballot weight <= 0 is silently treated as 1 in aggregation and V9 |
| G31 | low | CONFIRMED | missing-component |  | Pre-encrypted ballots can be generated but never recorded: no §4.3 recording tool or cast/uncast record type, and Verifications 15, 18 and 19 are missing |
| G32 | low | CONFIRMED | missing-component |  | Contest-data decryption (§3.6.6, proof eqs 99/101 with 0x32/0x33) and Verification 12 are not implemented |
| G33 | low | CONFIRMED | divergence |  | 6.B/6.C and 7.B/7.C reject a challenge or response of 0, but 0 is in Z_q |
| G34 | info | CONFIRMED | divergence |  | Guardian-record comparison hash H_G (eq 27) is keyed with H_P instead of H_B |
| G35 | info | CONFIRMED | divergence |  | Share decryption derives k_{i,l} with H_q (reduced mod q) where eq (16) specifies H; the encrypt side is correct |
| G36 | info | CONFIRMED | divergence | 7A | 7.A tests the contest aggregates (alpha-bar, beta-bar) instead of each alpha_i and beta_i |
| G37 | info | CONFIRMED | divergence | 8E | 8.D and 8.E chaining-field checks are tautological (both sides built from identical inputs); enforced only indirectly through 8.B |
| G38 | info | CONFIRMED | divergence | V9-5 | V9 throws a plain Exception with no 9.A/9.B SubSection |
| G39 | info | PLAUSIBLE | divergence |  | Operations on secrets are not constant-time (vote-dependent branch in GenerateProofs, secret-indexed table lookups, data-dependent final subtraction in scalar Montgomery) |
| G40 | info | CONFIRMED | interop-note |  | EncryptedBallot cannot carry other §3.7 record items: encryption timestamp and per-device ordering (status is G21) |

## Details

### G1 — Parameter base hash H_P: version key is left-padded and p/q/g are encoded little-endian with sign bytes

- **Severity / status:** critical / CONFIRMED (hand-verified); bucket `divergence`; category `hash-input-divergence`; known `none`
- **Spec:** §3.1.2 eq (4) p.16; §5.1 b(a,m) p.69; §5.5.1 B1 layout p.74 (len(B1)=1065); Verification 1.E
- **Code:** src/ElectionGuard.Core/Models/ParameterBaseHash.cs:10-16; src/ElectionGuard.Core/Models/Version.cs:42 (PadToLength, ByteArrayExtensions.cs:51); src/ElectionGuard.Core/Verify/KeyGeneration/ParameterVerification.cs:49-55

The spec defines H_P = H(ver; 0x00,p,q,g,n,k) with ver = "v2.1.0"||b(0,26) and fixed-width big-endian b(p,512)||b(q,32)||b(g,512), 1065 bytes in total. Version's implicit byte[] conversion left-pads, so the HMAC key comes out as 26 zero bytes followed by "v2.1.0". P/Q/G are System.Numerics.BigInteger, so .ToByteArray() emits little-endian two's complement: 513, 33 and 512 bytes, which makes B1 1067 bytes. Spec-correct H_P for n=3,k=2 is 51bca66c...b661; the code produces 8836a851...29ae. H_P feeds into every other hash, nonce, challenge and confirmation code, so nothing the library produces matches a conformant implementation. 1.E repeats the same construction, so it accepts C# records and would reject conformant ones.

**Fix sketch:** Right-pad ver in Version (do not change PadToLength; it is correct for integers). Encode P/Q/G as fixed-width big-endian, e.g. new IntegerModP(P).ToByteArray() or BigInteger.ToByteArray(isUnsigned:true,isBigEndian:true) left-padded to 512/32. Make 1.E call the ParameterBaseHash constructor. Add a known-answer test pinning H_P (51bca66c...) and len(B1)==1065. Update tests that pin the wrong value: CryptographicParameterTests.cs:43 expects the left-padded ver, and VerificationTests.cs:18 only compares H_P against itself.

**Verifier notes:** All verifiers confirmed. Two verifiers recomputed the H_P digests in Python and both match. The impact is interop and conformance, not confidentiality, but critical stands because every hash input downstream changes. The r2 test-pin items were downgraded to low/info and folded in here.

### G2 — Tally decryption has no Chaum-Pedersen proof (§3.6.5, 0x30/0x31), Verification 10 is missing, and DecryptedTally cannot carry T/c/v

- **Severity / status:** critical / CONFIRMED (hand-verified); bucket `missing-component`; category `missing-spec-component`; known `none`
- **Spec:** §3.6.5 eqs (87)-(93) pp.47-48; Verification 10 (10.A-10.C) p.49; §3.7 'proofs of correct decryption of each tally' p.56
- **Code:** src/ElectionGuard.Core/Tally/TallyGuardian.cs:32 (TallyGuardian.Decrypt computes only M_i) and :76 (TallyAdmin.Decrypt); src/ElectionGuard.Core/Tally/PartialTallyDecryption.cs:18; src/ElectionGuard.Core/Tally/DecryptedTally.cs:14

The spec requires guardians to produce a proof that M = A^s using commitments (a_i,b_i), the commitment hash d_i (0x30), a challenge c (0x31, with ind_c/ind_o), and responses v_i. T and (c,v) must be published and checked by Verification 10. The code computes only M_i = A^z_i, and DecryptedChoice holds only an int VoteCount. There is no 0x30/0x31 hash and no V10 class anywhere. Because the Lagrange w_i are public, one guardian can submit M_i' = M_i*K^(-delta/w_i) and shift any count by delta. The administrator can also publish arbitrary counts, and no verifier in any language can detect either.

**Fix sketch:** Implement the §3.6.5 commit/reveal protocol: each guardian sends d_i = H(H_E;0x30,ind_c,ind_o,i,A,B,a_i,b_i,M_i,U), every guardian checks the revealed d_j, then c = H_q(H_E;0x31,...), c_i = c*w_i, v_i = u_i - c_i*z_i. Add ind_c/ind_o and T (or M), c, v to the tally models, and add a TallyDecryptionVerification for 10.A-10.C. Note 3.7 (eqs 94-95) is optional in v2.1.

**Verifier notes:** Both tally-decryption verifiers rated this critical. The hash-domain variant was raised from medium to high. Critical is kept: an undetectable wrong tally is a soundness failure of the main output, which outranks interop issues. Ranked below G1 only because G1 touches every artifact. The eq 99/101 half of the hash-domain item moved to G32. The verification-inventory verifier noted that Note 3.7 per-guardian checks are optional and should not count toward this gap.

### G3 — The four supplemental counters (overvote/null/undervote/write-in) share one nonce, with no option index in the nonce or the proof challenge

- **Severity / status:** high / CONFIRMED (hand-verified); bucket `divergence`; category `side-channel-or-randomness`; known `none`
- **Spec:** §3.3.3 eq (33) p.29; §5.5.3 B1 len 41 p.75; §3.1.3 p.19 (supplemental fields 'treated like and listed with the option selection fields'); §3.3.9 p.38; eqs (41)/(50)
- **Code:** src/ElectionGuard.Core/BallotEncryption/BallotEncryptor.cs:179-182, 237 (EncryptOptionalField passes no choiceIndex), 308-315 (challenge omits ind_o); src/ElectionGuard.Core/Models/EncryptionNonce.cs:14-18

Eq (33) gives each field xi_{i,j} = H_q(H_I;0x21,i,j,xi_B), a 41-byte input. The spec treats supplemental fields as options, so each one gets its own j. The code calls EncryptionNonce with choiceIndex=null for all four counters, so they all get the same xi from a 37-byte input and share alpha = g^xi. From public data, beta_null/beta_over is one of K, 1 or K^-1, which reveals the null-vote and overvote flags. Further beta ratios give the exact undervote count (and therefore how many selections the voter made) and the write-in count, for every contest on every ballot. Nonces and challenges also differ byte-for-byte from any conformant encryptor.

**Fix sketch:** Give each supplemental field a manifest-declared, per-contest option index (e.g. after the last option) and encrypt it through the normal (i,j) path, using the same j in its range-proof challenge. Never call EncryptionNonce without j. This same change also resolves G8 and G22. Update BallotEncryptorTests.cs:56-60 (null choiceIndex challenge reconstruction) and EncryptionNonceTests.cs:20-30 (j-less form, 3-byte xi_B).

**Verifier notes:** 5 of 6 primary verdicts said high, and one (parameters-manifest spec lens) said critical. Kept at high, ranked first among the highs. It is not critical because it leaks per-contest metadata (null/over/undervote status, number of selections, write-in count), not which option was chosen. The verification-inventory item was raised from medium to high. Verifiers note that the §3.3.9 proofs for these fields are 'not described in detail', so the challenge-format claim is weaker than the nonce claim. The nonce reuse leaks regardless of how indices are assigned. The protobuf DTO's EncryptionNonce is not serialized (no ProtoMember), so the leak requires only alpha/beta.

### G4 — Verifiers never check that a ballot lists each manifest option once and each contest once: duplicated contests or options pass V5-V9 and are tallied twice

- **Severity / status:** high / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `none`
- **Spec:** §3.1.3 bijective contest/option indices p.17; §3.4 'unique contest index l, 1<=l<=m_B' p.41; Verification 6 preamble p.36; Verification 7 (7.1/7.2) p.37; Verification 9 p.45
- **Code:** src/ElectionGuard.Core/Verify/Ballot/SelectionEncryptionsWellFormedVerification.cs:37-81,165-173; src/ElectionGuard.Core/Verify/Ballot/AdherenceToVoteLimitsVerification.cs:21-23; src/ElectionGuard.Core/Verify/Ballot/ConfirmationCodeVerification.cs:14-16; src/ElectionGuard.Core/Tally/EncryptedTally.cs:44-63

The spec's model is one ciphertext per (contest index, option index) per ballot, and V6 and V9 range over the manifest's options. The structural checks in V6 and V7 only confirm that each listed ID appears once in the manifest. Nothing checks that IDs are unique on the ballot or that every manifest option is present. EncryptedTally.AddBallot, which V9 reuses for its recomputation, multiplies in every listed copy. A malicious encryptor can copy a valid contest verbatim (its challenges are bound only to H_I and the indices) to multiply that contest's votes. It can also duplicate an option in a contest with slack (e.g. L=2, R=1) to give one voter two votes for that option. V5-V9 all pass, and the decrypted tally includes the extra votes.

**Fix sketch:** Add a structural pre-check shared by V6, V7 and V8, and apply the same rule in EncryptedTally.AddBallot: contest IDs on a ballot must be unique, and each contest's ChoiceIds must equal the manifest's option set exactly, with no duplicates and none missing. Optionally also check contests against BallotStyleId. That is hardening, since the spec states ballot-style checks only for challenged and pre-encrypted ballots (14.B, 19.B).

**Verifier notes:** High is unanimous. Verifiers note that no lettered sub-check states this rule; it is implicit in the index-keyed model. Duplicating a choice is bounded by V7's limit proof, so the attack needs L > R. Duplicating a whole contest works at any L. The ballot-style part is hardening beyond the spec.

### G5 — Guardian index 0 is accepted, and EncryptShares sends shares to unvalidated indices: P_i(0) = s_i leaks every guardian's secret key

- **Severity / status:** high / CONFIRMED (hand-verified); bucket `divergence`; category `manifest-or-input-validation`; known `none`
- **Spec:** §3.2.1 'guardians G_1..G_n', a_{i,0}=s_i p.21; §3.2.2 share encryption 'each other guardian G_l (1<=l<=n, l!=i)' p.25; threat model 'malicious election administrator or network operator' p.24
- **Code:** src/ElectionGuard.Core/KeyGeneration/Guardian.cs:15 (index < 0 check, message 'between 0 and N'), :78-98 (EncryptShares evaluates at any view Index), :268-281 (ComputePolynomial); GuardianIndex.cs (no validation)

Shares are defined only at indices 1..n with l != i. The Guardian constructor accepts index 0. EncryptShares evaluates P_i at whatever index a GuardianPublicView carries, with no check of range, self, duplicates or count, and ComputePolynomial(0) returns a_{i,0} = s_i (and s-hat_i). Anyone who injects a view with Index 0, or k extra out-of-range indices, receives every guardian's secret keys and can decrypt all ballots alone. A deployment that numbers guardians from 0 hands guardian 0 the joint key, and Lagrange interpolation then gives guardian 0 w=1 and everyone else 0, so nothing ever reveals it. The canonical pipeline uses 1..N, so the risk is in the public API and in future orchestration code.

**Fix sketch:** Validate 1 <= index <= N in GuardianIndex or the Guardian constructor and fix the error message. In EncryptShares, require that peer indices are exactly {1..N} minus self, with no duplicates. Validate SourceIndex/DestinationIndex in DecryptShares too. Invert GuardianTests.cs:121 Constructor_IndexZero_DoesNotThrow.

**Verifier notes:** Both crypto-engine verifiers said high, and the key-gen spec lens said high. The key-gen code lens argued medium, because a κ-substitution attacker already gets k shares, so range checks are defence-in-depth. High was chosen because index 0 and out-of-range indices can be presented identically to all guardians and slip past eq-(27) detection, while a guardian accidentally numbered 0 leaks the key with no attacker at all. The constructor-only item (low) and the test pin (info/plausible) are folded in.

### G6 — Election base hash H_B omits the 4-byte manifest length prefix

- **Severity / status:** high / CONFIRMED (hand-verified); bucket `divergence`; category `hash-input-divergence`; known `none`
- **Spec:** §3.1.4 eq (5) p.19; §5.1.5 file inputs p.71; §5.5.1 B1 = 0x01||b(len(manifest),4)||manifest p.74
- **Code:** src/ElectionGuard.Core/Models/ElectionBaseHash.cs:9-12; src/ElectionGuard.Core/Verify/KeyGeneration/ParameterVerification.cs:77-79 (1.F, dead)

§5.1.5 says file inputs 'must start with a 4-byte encoding in big endian format of the file byte length', and names H_B as the example. The code hashes 0x01||manifest with no length, and every caller (Program.cs:81-87, ElectionFixtureBuilder, perf ScenarioRunner.cs:89) passes raw bytes. Even after G1 is fixed, H_B and therefore H_E, H_I, every nonce, challenge and confirmation code still differ from a conformant implementation for the same manifest.

**Fix sketch:** EGHash.Hash(H_P, [0x01], b(len,4) big-endian, manifest). Put the helper in one place shared by ElectionBaseHash and 1.F. Replace ElectionBaseHashTests.cs:47, which pins the unprefixed form, with a known-answer vector.

**Verifier notes:** High is unanimous. The 1.F copy of the omission is in dead code (see G26). The test pin was downgraded to low/info and folded in.

### G7 — Voting device information hash H_DI (regular ballots) is missing its 0x2A domain separator

- **Severity / status:** high / CONFIRMED (hand-verified); bucket `divergence`; category `hash-input-divergence`; known `none`
- **Spec:** §3.4.3 eq (72) p.42; §5.5.3 B1 = 0x2A||b(len,4)||S_device p.76; Verification 8.C p.44
- **Code:** src/ElectionGuard.Core/Models/VotingDeviceInformationHash.cs:14-19 (the pre-encrypted variant at :29-32 correctly prefixes 0x43); 8.C recompute at src/ElectionGuard.Core/Verify/Ballot/ConfirmationCodeVerification.cs:44

Eq (72) requires H_DI = H(H_E; 0x2A, S_device), with len(B1) = 5+len. The regular constructor hashes b(len,4)||S_device with no 0x2A. H_DI feeds B_C (0x00000000||H_DI) and H_0, so every regular ballot's confirmation code differs from a conformant encryptor's. 8.C uses the same constructor, so C# agrees with itself but would reject a conformant H_DI. §3.4.3 is new in v2.1.

**Fix sketch:** Prepend [0x2A] before the length prefix. Add a known-answer test for the B1 layout. Update VotingDeviceInformationHashTests.cs:55, which pins the separator-less form.

**Verifier notes:** The confirmation-chaining item was filed as critical. Both of its verifiers lowered it to high (interop break, not soundness), consistent with every other report.

### G8 — Supplemental counters are always encrypted and hashed into the contest hash, ignoring the manifest's (election-wide, never-read) Include* flags, in a fixed order

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `hash-input-divergence`; known `none`
- **Spec:** §3.4.1 eq (70) p.41 ('if the election manifest specifies any ... hashed in order specified by the election manifest'); §3.1.3 p.19 ('must be specified in the manifest per contest'; which fields count toward the limit must be specified); §3.3.9 p.38
- **Code:** src/ElectionGuard.Core/Models/ContestHash.cs:32 (length choices+4), :50-53; src/ElectionGuard.Core/BallotEncryption/BallotEncryptor.cs:179-182,190-197; src/ElectionGuard.Core/Models/Manifest.cs:12-15 (flags never read in src)

Eq (70) hashes only the options, plus whatever supplemental fields the manifest specifies, in manifest order. The code always encrypts, proves, publishes and hashes all four counters after the options, in the order over/null/under/write-in. The Include* flags are election-wide rather than per-contest, and nothing in src reads them. Whenever a flag is false, chi_l and H_C differ from a conformant encryptor. This happens today: ElectionFixtureBuilder defaults to IncludeWriteins=false. The manifest also cannot say which fields count toward the selection limit.

**Fix sketch:** Model supplemental fields per contest in the manifest, with option indices and a counts-toward-limit flag (the same change as G3). Encrypt, prove and hash only the declared fields, in manifest order. Have ContestHash take a single ordered list. Update ContestHashTests (lines 125-149, 152-181, 189-254, 261-314).

**Verifier notes:** The confirmation-chaining item was filed as high; both verifiers lowered it to medium (supplemental fields are optional; the manifest representation is implementation-specific, so the fixed order when all flags are true is weak). One parameters-manifest verifier argued low. One ballot-encryption verifier argued high, folding in the nonce issue, which is G3 here. Medium kept for the flag-off hash divergence.

### G9 — Contests and options are hashed in the caller's ballot list order, not manifest/index order, and Verification 8 accepts any order

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `hash-input-divergence`; known `none`
- **Spec:** §3.4.1 eq (70) p.41 ('hashed in order specified by the election manifest file'); §3.4.2 eq (71) p.42 ('contest hashes in the order of the contests as specified in the election manifest')
- **Code:** src/ElectionGuard.Core/BallotEncryption/BallotEncryptor.cs:67-72 (contests), :169-174 (choices), Validate :90-143 (set equality only); src/ElectionGuard.Core/Verify/Ballot/ConfirmationCodeVerification.cs:14-36

The spec requires chi_l and H_C inputs in manifest order. The encryptor iterates ballot.Contests and contest.Choices as given, and Validate checks only set equality. V8 recomputes in stored order, so it accepts any permutation. BallotPreEncryptor does sort by Index. The fixture generator shuffles ballot-style ContestIds (Testing.Cli Program.cs:78-82), so this is reachable. Out-of-order ballots produce chi_l/H_C that a conformant verifier will not reproduce. Ciphertexts and nonces are unaffected because they use the indices.

**Fix sketch:** In the encryptor and in V8, order contests by contest Index and options by option Index, as BallotPreEncryptor does, or reject non-canonical order.

**Verifier notes:** Mostly medium. One confirmation-chaining spec lens argued low, since the problem only appears for out-of-order input. Kept at medium because the fixture generator produces out-of-order input today.

### G10 — Overvote threshold is L*R instead of L: for R>1 a total in (L, L*R] is neither neutralized nor valid (invalid contest proof); a single option above R throws

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `arithmetic-bug`; known `none`
- **Spec:** §3.3.5 Overvotes p.31; §3.1.3 L = max total of selections, p.17-18; §3.3.9 overvote indicator 'strictly more than the contest selection limit' p.38; eq (62) p.37
- **Code:** src/ElectionGuard.Core/BallotEncryption/BallotEncryptor.cs:153 (isOvervote = total > L*R), :177 (GenerateProofs(total, L)), :116 (throws when value > R); test/ElectionGuard.Testing.Common/ExpectedTally.cs:97

The spec's rule is that the contest is overvoted when sum > L or when any option > R, and then all options are zeroed. The code uses sum > L*R. When R>1 and L < sum <= L*R, the contest is not neutralized, the overvote indicator encrypts 0, and GenerateProofs never hits a matching branch, so the contest proof silently fails 7.D. Example: L=1, R=2, one option set to 2. A single option above R throws instead of being neutralized. ExpectedTallyAccumulator copies the L*R rule and every corpus has R=1, so egperf's tally gate cannot catch this.

**Fix sketch:** Set isOvervote = sum > L || any(value > R), neutralize instead of throwing for value > R (still reject negatives), and prove the aggregate with value 0. Implement the spec rule independently in ExpectedTallyAccumulator, add R>1 fixtures and discriminating tests, and update CLAUDE.md.

**Verifier notes:** Medium agreed; it applies only to manifests with R>1. Verifiers note the per-option case is SHOULD ('treated analogously', p.18) and fails loud. The r2 fixture-masking item was lowered to low and folded in.

### G11 — Contest-data KDF (eq 66) uses the byte offset as its counter and i*256 as its length field, and D_Λ is not fixed to 32*b_Λ (length leak, extra zero block)

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `ciphertext-divergence`; known `none`
- **Spec:** §3.3.10 eqs (63), (66) p.40 (page image confirms labels data_enc_keys/contest_data, 1<=i<=b_Λ, constant b(b_Λ*256,4)); eq (104)/(12.4) p.51
- **Code:** src/ElectionGuard.Core/BallotEncryption/BallotEncryptor.cs:348-394 (loop :367 'i <= bytes.Length; i += 32', HMAC :385-391); Manifest.OptionalContestDataMaxLength (Manifest.cs:11) never read

The spec computes k_i = HMAC(h, b(i,4)||'data_enc_keys'||0x00||'contest_data'||b(ind_c,4)||b(b_Λ*256,4)) for block i = 1..b_Λ, over D_Λ of fixed length 32*b_Λ. The code uses the byte offset 0,32,... as the counter and i*256 as the length field, so even a one-block C1 differs. It pads only to the next 32 bytes and adds an all-zero block when the length is a multiple of 32. No manifest b_Λ is used. As a result C1, chi_l and H_C differ from a conformant encryptor, conformant guardians cannot decrypt the data, and the length of C1 reveals the length of the write-in text.

**Fix sketch:** First define b_Λ from the manifest; OptionalContestDataMaxLength has no defined unit. Then pad or require D_Λ of exactly 32*b_Λ bytes and reject longer input. Loop blk = 1..b_Λ with b(blk,4) and the constant b(b_Λ*256,4). Update BallotEncryptorTests.cs:260, which pins C1 = 32 bytes. Note that 13.7 prints 0<=l<b_Λ, which conflicts with eq (66); follow eq (66).

**Verifier notes:** Three verdicts said medium and one (ballot-encryption code lens) said high. Medium chosen because §3.3.10 is optional, though once the feature is used the output is fully non-interoperable. The spec puts unambiguous filling of the bytes on the calling device, but the library must enforce the fixed length.

### G12 — Contest/option Index is a free manifest field used directly in every hash, never checked to be unique, 1-based and positional; the shared fixtures and the corpus generator are 0-based

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `manifest-or-input-validation`; known `none`
- **Spec:** §3.1.3 Indices p.17 ('1-based ordinal in the range 1<=i<2^31', 'first contest ... has contest index 1', bijective mapping)
- **Code:** src/ElectionGuard.Core/Models/Manifest.cs:39,47; used at BallotEncryptor.cs:177-218, SelectionEncryptionsWellFormedVerification.cs:209-210, AdherenceToVoteLimitsVerification.cs:162, BallotPreEncryptor.cs:111,144-164; fixtures test/ElectionGuard.Testing.Common/ElectionFixtureBuilder.cs:140-144, test/ElectionGuard.Testing.Cli/Program.cs:60,70, test/data/single-contest/manifest.json:13-20

The spec defines an index as the 1-based list position. The code hashes whatever Index the manifest supplies and never validates it. A non-positional or 0-based index changes nonces, challenges and contest hashes relative to a conformant encryptor. Two options sharing an Index get the same xi, which leaks the difference of their plaintexts. The shared test manifest, the Testing.Cli generator and the perf smoke manifest all use 0-based indices, so most tests hash ind=0 and any check would break them. famous-names manifests are correct.

**Fix sketch:** Validate on manifest load that each Index equals its 1-based position, or derive it from position, and that labels are unique. Fix CreateMinimalManifest (Index 1, choices 1,2), Testing.Cli (i+1, j+1), single-contest/manifest.json and Perf BallotGeneratorTests. Derive expected indices from position in BallotEncryptorTests.cs:121 and BallotPreEncryptorTests.cs:91-98.

**Verifier notes:** The parameters-manifest item was filed as high; both verifiers lowered it to medium because the manifest is trusted, administrator-supplied input and conformant manifests produce correct output. The fixture items were rated low/info and folded in.

### G13 — Verification 5.A cannot detect duplicate identifiers: SelectionEncryptionIdentifier compares its byte[] by reference

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `none`
- **Spec:** Verification 5.A p.29 (repeated p.83)
- **Code:** src/ElectionGuard.Core/Verify/Ballot/SelectionEncryptionIdentifierVerification.cs:13-17; src/ElectionGuard.Core/Models/SelectionEncryptionIdentifier.cs:3-16 (struct, no Equals/GetHashCode)

5.A requires that no two submitted ballots share id_B. The struct wraps a byte[] with default ValueType equality, so the HashSet compares arrays by reference. Separately deserialized ballots with identical id_B, and therefore identical H_I, are never flagged. The only duplicate test adds the same instance twice. Program.cs:171-174 also passes a one-element list per ballot, and perf checks only within a chunk.

**Fix sketch:** Implement IEquatable with SequenceEqual and a content hash code. Add a test with two separately allocated, equal arrays. Have the caller pass the identifiers of all submitted ballots.

**Verifier notes:** Corrected line: :13-15, not :122. This is distinct from the already-fixed 5.B and GetHashCode items, which did not cover this type.

### G14 — Verification 2 does not check for exactly k commitments and k+1 responses: an unproven extra commitment K_{i,k} is accepted, raising the decryption threshold

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `none`
- **Spec:** Verification 2 (2.1)-(2.4), (2.A), (2.B), (2.C) p.24; eq (8)/(11) p.23
- **Code:** src/ElectionGuard.Core/Verify/KeyGeneration/GuardianPublicKeyVerification.cs:27-46 (h from the first K), :49-63 (2.A only j<K), :82,97 (2.C hashes all commitments)

The spec fixes K_{i,0..k-1} and v_{i,0..k}, and 2.C hashes exactly those. The code builds h from the first K entries but hashes every commitment in the list, and never checks counts. A guardian can publish k+1 commitments with a valid proof. K_{i,k} is then never proven or membership-checked, and the share checks in Guardian.Verify still pass, so exactly k guardians can no longer decrypt (DoS). A spec verifier would compute a different challenge. Short lists throw IndexOutOfRange instead of a 2.x failure.

**Fix sketch:** At the start of Verify(guardian), require both commitment lists to have Count == K and both Responses.Length == K+1, otherwise throw VerificationFailedException with a 2.x subsection.

**Verifier notes:** Medium agreed. Decryption still works with k+1 participating guardians; confidentiality is unaffected.

### G15 — DecryptShares/Guardian.Verify do not require exactly one share from each other guardian: duplicate or missing shares yield a wrong z_i with no error at key generation

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `manifest-or-input-validation`; known `none`
- **Spec:** §3.2.2 eq (24) p.26; share verification step 4 'for all 1<=i<=n' eq (28)/(29) p.27
- **Code:** src/ElectionGuard.Core/KeyGeneration/Guardian.cs:141-183 (DecryptShares sums whatever arrives), :241-265 (Verify loops over received shares only)

z_i is the sum of exactly n shares, one per guardian, and step 4 checks every source 1..n. The code sums whatever shares it receives and verifies only those. A replayed or doubled share passes eq (28) and is counted twice, and a missing share is never noticed. A malicious guardian, administrator or network can therefore break decryption, and the failure shows up later as an unattributable 'Tally did not decrypt successfully'. Using DestinationIndex instead of this.Index in the 0x11/KDF inputs is byte-identical for honest data, so it is hardening only.

**Fix sketch:** Require N-1 shares with distinct SourceIndex in [1,N] \ {Index} and DestinationIndex == Index. In Verify, loop over guardians 1..N rather than over received shares.

**Verifier notes:** Split verdict: the spec lens said low (DoS only), the code lens said medium. The code lens argument was preferred: a malicious guardian can duplicate its share to every peer, causing a failure no one can attribute, which is exactly what step 4 exists to catch at key generation. The DestinationIndex sub-claim is not an encryption divergence.

### G16 — Tally discrete-log bound is BallotsCast, ignoring ballot weights (eq 80) and OptionSelectionLimit > 1, so valid elections fail to decrypt

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `arithmetic-bug`; known `none`
- **Spec:** §3.5 eq (80) p.45 (weights are small positive integers); §3.6.2 p.46; R>1 cardinal voting §3.3.7
- **Code:** src/ElectionGuard.Core/Tally/TallyGuardian.cs:120 (TallyAdmin; new BoundedDiscreteLog(K, encryptedTally.BallotsCast, ...)); EncryptedTally.cs:51-56,65

Spec-valid weighted or R>1 tallies can exceed the ballot count. BallotsCast goes up by 1 per ballot and is used as the BSGS upper bound, so any option whose count exceeds the number of ballots throws 'Tally did not decrypt successfully'. Example: R=2 and one ballot giving 2. The encryptor can produce this directly; weights >1 arrive only on external ballots. It fails closed, with no wrong tally.

**Fix sketch:** Track the bound as sum of W_i * min(R, L) per contest, including in MergePartials, and pass it to BoundedDiscreteLog.

**Verifier notes:** Medium agreed; it is a liveness bug. CLAUDE.md documents it as a limitation, but it contradicts the spec's support for R>1 and weights.

### G17 — Regular EncryptedBallot drops the encrypted ballot nonce C_ξB: it is computed and then discarded

- **Severity / status:** medium / CONFIRMED; bucket `missing-component`; category `missing-spec-component`; known `none`
- **Spec:** §3.3.4 eqs (34)-(38) p.30 ('every ElectionGuard ballot contains an encryption of the ballot nonce'); §3.6.7 p.51-52; v2.1 changelog (challenged ballots are always decrypted via the ballot nonce)
- **Code:** src/ElectionGuard.Core/BallotEncryption/BallotEncryptor.cs:63 (encryptedBallotNonce unused), :77-87; src/ElectionGuard.Core/BallotEncryption/EncryptedBallot.cs:5-15 (no field; PreEncryptedBallot.cs:18 has one)

v2.1 makes ballot-nonce decryption the only way to open a challenged ballot. BallotEncryptor builds C_ξB correctly and then throws it away, and EncryptedBallot has no field for it. ξ_B is therefore unrecoverable for every ballot encrypted today, even after §3.6.7 is implemented. Ciphertexts and the confirmation code are unaffected, because C_ξB is not a hash input.

**Fix sketch:** Add EncryptedBallotNonce (EncryptedData) to EncryptedBallot, populate it at BallotEncryptor.cs:63, and add it to both the JSON shape and the protobuf DTO.

**Verifier notes:** Medium is the consensus; the tally-decryption code lens said high. This is not an encryption-bytes divergence. §3.7 does not list C_ξB explicitly; the requirement comes from §3.3.4 and §3.6.7. The decryption and verification half is G18.

### G18 — Challenged-ballot handling is entirely missing: no §3.6.7 ballot-nonce decryption, no Verification 13 or 14, no model for challenged-ballot decryptions

- **Severity / status:** medium / CONFIRMED; bucket `missing-component`; category `missing-spec-component`; known `none`
- **Spec:** §3.6.7 eqs (107)-(111) pp.51-53 ('Each and every challenged ballot must be verifiably decrypted'; 'An election verifier must confirm Verifications 13 and 14'); V13 p.54; V14 (14.A-14.F) p.55; §3.7 p.55-56
- **Code:** absent (no challenged/uncast type, no use of OtherBallotDataEncryptionKeyShare for decryption, no V13/V14 class under src/ElectionGuard.Core/Verify)

Guardians must check the 0x23 Schnorr proof on C_ξB, compute m_i = C_ξB,0^{ẑ_i} and combine them by Lagrange to recover ξ_B. Then ξ_{i,j} are published, and verifiers recompute α, β, the contest hashes and H_C (V13) and check labels and well-formedness (V14). None of this exists, so cast-or-challenge auditing cannot be done or verified. It depends on G17 and on V9-3 (G21).

**Fix sketch:** Add BallotNonceEncryption decryption with guardian partials and Lagrange combination. Add a ChallengedBallot record (ballot ref, σ, ξ_{i,j}, contest data D) and Verification13/14 classes.

**Verifier notes:** One tally-decryption spec verifier noted that 'impossible' overstates it, since the record format also allows proofs of decryption, but no route is implemented. Medium agreed.

### G19 — Chain-closing hash never computed (eqs 77/78, 0x2B; 118/120, 0x44); 8.G and 16.H are unimplemented and the record has no per-device ordered list

- **Severity / status:** medium / CONFIRMED; bucket `missing-component`; category `missing-spec-component`; known `none`
- **Spec:** §3.4.4 eqs (77)-(78) p.43; Verification 8.F/8.G p.44; §4.1.4 eqs (117)-(120) p.59; Verification 16.G/16.H p.65; §3.7 'Ordered lists of the ballots encrypted by each device' p.56
- **Code:** src/ElectionGuard.Core/Verify/Ballot/ConfirmationCodeVerification.cs:68-72 (empty VerifyDevice stub); src/ElectionGuard.Core/Verify/PreEncryption/PreEncryptedConfirmationCodeVerification.cs:8 ('16.G and 16.H ... not covered'); Program.cs:162 TODO

Under simple chaining, the spec closes each device's chain with B_C = 0x00000001||H(H_E;0x2B,H_l,B_C,0) and H = H(H_E;0x29,B_C), or 0x44/0x42 for pre-encrypted ballots, publishes it, and checks it in 8.G and 16.H. No code uses 0x2B or 0x44, nothing produces or stores a closing hash, and EncryptedBallot has no chaining field or sequence, so the verifier depends on the caller supplying previousConfirmationCode. Ballots truncated from the end of a device's chain cannot be detected. 8.F and 16.G are covered implicitly: H_0 is recomputed when previous == null and checked via 8.B/16.F.

**Fix sketch:** Add a per-device close API and record (ordered ballot ids, closing hash). Implement VerifyDevice for 8.G/16.H that walks each device's ordered list. Spec inconsistency to decide: the §5.5.5 table (p.77-78) lists eq 120's B1 as 0x44||0x4C4F434B||H_l||B_C,0 with len 69, which does not add up (73 bytes) and conflicts with body eq (120), which has no 'LOCK' constant. Pick one, document it, and check the analogous 0x2B row.

**Verifier notes:** The confirmation-chaining item was filed as high; both verifiers lowered it to medium (it applies only when ChainingMode.Simple is used, which is not the default, and changes no hash bytes). Verifiers corrected that 8.F/16.G are enforced implicitly. The caller-supplied previous-code part overlaps known 8E (G37).

### G20 — V9 iterates the claimed tally's contests and options instead of the manifest's

- **Severity / status:** medium / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `V9-2`
- **Spec:** Verification 9 p.45 ('for each option in each contest in the election manifest'), restated p.88
- **Code:** src/ElectionGuard.Core/Verify/Tally/BallotAggregationVerifier.cs:129-134

A claimed tally that omits options or contests, including an empty one, passes V9 because those entries are never compared. Extra entries throw KeyNotFoundException instead of a 9.x failure. Verification 11 (G27), which would catch this from the other side, is also missing.

**Fix sketch:** Iterate the manifest-derived _expected, require every key to be in the claimed tally, and report extra keys as failures.

**Verifier notes:** Tally-decryption verifiers said medium; verification-inventory verifiers said low because the honest pipeline builds the tally from the manifest. Medium chosen because V9 is the public verifier for untrusted records.

### G21 — EncryptedBallot has no cast/challenged status; aggregation and V9 count every ballot they are given

- **Severity / status:** medium / CONFIRMED; bucket `missing-component`; category `missing-spec-component`; known `V9-3`
- **Spec:** Verification 9 'all cast ballots' p.45; §3.7 'the status of the ballot (cast or challenged)' p.56; v2.1 changelog (status is required data)
- **Code:** src/ElectionGuard.Core/BallotEncryption/EncryptedBallot.cs:5-15

The record cannot say which ballots are cast. Nothing filters to cast ballots, so challenged ballots would be tallied and V9 would accept the result. V13/V14 (G18) also have no input to work on.

**Fix sketch:** Add a status field, carry it through both serializers, and filter to cast ballots in EncryptedTally and V9.

**Verifier notes:** Tally-decryption verifiers said medium; verification-inventory said low. Medium kept because it blocks G18.

### G22 — Supplemental-field semantics and proofs: undervote count uses the number of nonzero options instead of L - sum, write-in bound is L and unvalidated, and V6/V7 never check these ciphertexts or proofs

- **Severity / status:** low / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `none`
- **Spec:** §3.3.9 pp.38-39 (L - undervote difference count = sum of selections; write-in range 0..#write-in fields 'should'); §3.1.3 p.19 (fields treated as options, so covered by V6); Verification 6 p.36
- **Code:** src/ElectionGuard.Core/BallotEncryption/BallotEncryptor.cs:151,155 (count of nonzero selections), :156,182 (NumWriteinsSelected unvalidated, bound = SelectionLimit); SelectionEncryptionsWellFormedVerification.cs:55,96,141-147,165-172 (Choices only); test/ElectionGuard.Testing.Common/ExpectedTally.cs:99

With R>1, the encrypted undervote count does not satisfy the spec relation L - u = sum. For example, L=3, R=3 with selections (2,0,0) encrypts 2 where the spec requires 1. An out-of-range NumWriteinsSelected silently produces an invalid proof because no branch matches. Write-ins are not counted toward the contest limit. V6 iterates only contest.Choices, so the four counters' alpha/beta are never membership-checked and their proofs are never verified, even though they feed the confirmation code. A malicious device can put arbitrary values, including non-group elements, there. They are not tallied (V9-1), which limits the impact.

**Fix sketch:** Once fields are manifest-indexed options (G3/G8): compute u = L - sum after neutralization, decide and document the overvote case, validate the write-in count against a manifest count of write-in fields, and extend V6 to every emitted EncryptedValueWithProofs. Alternatively drop the fields until they are fully supported.

**Verifier notes:** Ballot-proofs spec lens said medium and code lens said low; the others said low. Low chosen because §3.3.9 is optional with SHOULD wording and its proofs are 'not described in detail', and nothing tallies the fields. The write-in item was PLAUSIBLE: its V6-failure impact was false, since nothing verifies these proofs. Overvote semantics for the undervote count are unspecified in the spec.

### G23 — Deserializers silently reduce out-of-range or over-long integers mod p/q, making the 0<=x<p and 0<=x<q halves of 2.A/2.B, 6.A-C and 7.A-C unenforceable; id_B length is never checked

- **Severity / status:** low / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `none`
- **Spec:** Verification 2.A/2.B p.24; 6.A/6.B/6.C p.36; 7.B/7.C p.37; eq (32) B1 = 0x20||b(id_B,32) p.75; §5.1.1/5.1.2 fixed-length encodings p.69-70
- **Code:** src/ElectionGuard.Core/Crypto/IntegerModP.cs:14-26, IntegerModQ.cs:14-26; Serialization/Converters/IntegerModQJsonConverter.cs:18-19,40-41,128-129; Serialization/IEncryptedBallotSerializer.cs:160,170-228; GuardianPublicKeyVerification.cs:70-74 (empty 2.B loop); SelectionEncryptionIdentifier.cs:5

The JSON and protobuf readers build IntegerModP/Q from bytes of any length, and the constructors reduce mod p/q, so a published alpha+p, c_j+q or v_j+q is accepted where a conformant verifier must reject it. The record becomes malleable and verifiers disagree, but votes and proofs are unaffected because the reduced values are congruent. 2.B is an empty loop. id_B of any length is hashed as given instead of b(id_B,32). The hard-coded l_p=512/l_q=32 matters only for non-standard parameters, which v2.1 does not allow. Guardian/encryption records have no deserializer today, so the 2.x part is latent.

**Fix sketch:** Add strict parse paths that require exactly 512/32 bytes and a value < p / < q, and report failures as the matching 2.x/6.x/7.x subsection, or carry the raw BigInteger into verification. Require a 32-byte id_B. Keep the reducing constructors for internal arithmetic only.

**Verifier notes:** Several items were filed as medium, and verifiers lowered them all to low: congruent values cannot change votes or proof outcomes. The key-gen 2.A/2.B part is info/latent because guardian records are never deserialized. Corrected claim: alpha+p fits in 512 bytes only when alpha < 2^4096-p (about 2^-256 of values); any-length Base64 input is the realistic path. The 'draft serialization spec' quotes are not normative for v2.1.

### G24 — Verification 16 does no structural checks (ballot-style contest set, m+L vectors per contest, m entries per vector)

- **Severity / status:** low / CONFIRMED; bucket `divergence`; category `manifest-or-input-validation`; known `none`
- **Spec:** Verification 16.A-16.C p.65 (Ψ of m entries; ψ_π(1..m+L); χ_1..χ_mB); eqs (114),(115) p.58
- **Code:** src/ElectionGuard.Core/Verify/PreEncryption/PreEncryptedConfirmationCodeVerification.cs:25-49; ShortCodeVerification.cs:19-29

16.A-16.C recompute hashes over whatever the ballot publishes. Missing or extra null vectors, short vectors, and missing or duplicated contests are therefore internally consistent and pass 16 and 17. The generator itself produces the correct shape.

**Fix sketch:** Before 16.A, require contests == the ballot style's contests, Selections.Count == m+L, Vector.Count == m, each option exactly once, and L null vectors.

**Verifier notes:** Spec lens said medium, code lens said low. Low chosen: pre-encrypted ballots are not tallied anywhere and the explicit manifest-structure checks are 19.A-D (G31).

### G25 — V2/V3 (and EncryptShares) do not check that exactly n guardians with distinct indices 1..n are present

- **Severity / status:** low / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `none`
- **Spec:** Verification 2 'For each guardian G_i, 1<=i<=n' p.24/81; Verification 3.A/3.B p.26/82
- **Code:** src/ElectionGuard.Core/Verify/KeyGeneration/ElectionPublicKeyVerification.cs:15,18,23; GuardianPublicKeyVerification.cs:13-19

K and K-hat are multiplied over whatever guardians are listed. A ceremony run consistently with fewer guardians, or with a duplicated guardian, passes V1-V3 while H_P claims n, which silently shrinks the threshold. Guardian.Verify's own-view comparison catches only inconsistent views. An empty list throws ArgumentOutOfRange.

**Fix sketch:** Require Count == N (after V1 confirms N) and indices == {1..N} in V2/V3, and the N-1 count in EncryptShares.

**Verifier notes:** Low agreed. Code lens corrected the impact: decryption still works for the reduced set; the problem is threshold or parameter mismatch.

### G26 — Verification 1.F is effectively never performed: the 5-arg overload compares byte[] by reference (always throws), nothing calls it, guardians never check H_B, and EncryptionRecord lacks manifest bytes and H_B

- **Severity / status:** low / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `none`
- **Spec:** Verification 1.F p.20 (restated p.80); §3.2.2 step 1 'Guardian G_l also verifies ... H_B by performing Verification 1' p.27; §3.7 record contents (manifest file, H_P, H_B) p.55
- **Code:** src/ElectionGuard.Core/Verify/KeyGeneration/ParameterVerification.cs:72-84 (line 81 'expectedElectionBaseHash != electionBaseHash'); Guardian.cs:229-230 (3-arg overload only); src/ElectionGuard.Core/Models/EncryptionRecord.cs

The only 1.F implementation compares two byte[] with !=, so it throws for every input. It has no callers, also omits the length prefix (G6), and the record carries no H_B or manifest file bytes to check. H_B is therefore never verified anywhere, including during the guardian ceremony. It fails closed and is latent until a verifier wires it in.

**Fix sketch:** Use SequenceEqual, or compare against new ElectionBaseHash(...). Add the canonical manifest bytes and H_B to the record (H_P is already in GuardianRecord). Call the full V1 from the verifier and, where the manifest exists, from guardian verification. Add positive and negative tests.

**Verifier notes:** Several items were filed as medium; most verifiers lowered them to low because the code is dead and fails closed. The record-contents item was PLAUSIBLE. One lens refuted it because EncryptionRecord is the encryptor input, not the §3.7 record, and §3.7 is SHOULD language with its structure deferred. Its H_P claim was wrong: H_P is in GuardianRecord.

### G27 — Verification 11 (tally contents vs manifest, 11.A-11.D) is not implemented

- **Severity / status:** low / CONFIRMED; bucket `missing-component`; category `missing-spec-component`; known `none`
- **Spec:** Verification 11 (11.A-11.D) p.49 (restated p.90)
- **Code:** absent (no verifier takes a DecryptedTally; src/ElectionGuard.Core/Tally/DecryptedTally.cs is a bare dictionary)

Nothing checks that a decrypted tally's contest and option keys exactly match the manifest, or that every contest appearing on a ballot appears in the tally. Honest generation complies by construction, but a published tally that omits or adds entries is not flagged. This is the complement of V9-2.

**Fix sketch:** Add TallyContentsVerification for 11.A-11.D over DecryptedTally, the Manifest and the set of ballot contests, alongside the V10 work (G2).

**Verifier notes:** The tally-decryption item was filed as medium; its code lens said low, and the inventory verifiers said low. Low chosen because nothing verifies a DecryptedTally at all until G2 lands.

### G28 — Lagrange coefficient throws when a single guardian decrypts (|U| = 1, allowed when k = 1)

- **Severity / status:** low / CONFIRMED; bucket `divergence`; category `arithmetic-bug`; known `none`
- **Spec:** §3.6.4 eq (85) p.47; 1<=k<=n p.20
- **Code:** src/ElectionGuard.Core/Tally/TallyGuardian.cs:202-210 (TallyAdmin.CalculateLagrangeCoefficient, lines 206-207); src/ElectionGuard.Core/Extensions/IEnumerableExtensions.cs:23-25 (seedless Aggregate)

The empty product over U\{i} should be 1. Product() uses a seedless Aggregate, which throws InvalidOperationException, so any k=1 election decrypted by one guardian crashes.

**Fix sketch:** Seed the product with 1 (IntegerModQ overload).

**Verifier notes:** Low agreed. Line 207 has the same issue as line 206.

### G29 — Overvote/Nullvote/Undervote/WriteIn counts are never aggregated, so neither the tally nor V9 covers them

- **Severity / status:** low / CONFIRMED; bucket `missing-component`; category `missing-spec-component`; known `V9-1`
- **Spec:** §3.5 eq (79) p.44; Verification 9 p.45; §3.1.3 p.19 (supplemental fields treated as options); §3.3.9 p.38
- **Code:** src/ElectionGuard.Core/Tally/EncryptedTally.cs:15-28 (ctor), :47 (AddBallot walks Choices only)

The four counters are encrypted, proved and published on every ballot, but EncryptedTally has no slot for them. They are never tallied, decrypted or checked by V9. TallyComparer intentionally skips them, so egperf cannot detect this.

**Fix sketch:** After G3/G8, aggregate each emitted supplemental field like an option, extend V9, and compare the counters in TallyComparer.

**Verifier notes:** Tally spec lens said medium; the code lens and inventory verifiers said low (supplemental fields are optional; option tallies are unaffected). Low chosen.

### G30 — Ballot weight <= 0 is silently treated as 1 in aggregation and V9

- **Severity / status:** low / CONFIRMED; bucket `divergence`; category `manifest-or-input-validation`; known `V9-4`
- **Spec:** §3.5 eq (80) p.45 ('Weights must be small positive integers')
- **Code:** src/ElectionGuard.Core/Tally/EncryptedTally.cs:51 ('if(encryptedBallot.Weight > 1)'); reused by BallotAggregationVerifier.cs:43,61

Weight 0 or a negative weight falls into the unweighted branch and is counted as 1. The verifier recomputes with the same code, so it agrees instead of rejecting. A protobuf ballot with no weight set deserializes to 0. The C# encryptor always writes 1.

**Fix sketch:** Reject Weight < 1 with a V9 failure, or a deserialization error.

**Verifier notes:** Low agreed.

### G31 — Pre-encrypted ballots can be generated but never recorded: no §4.3 recording tool or cast/uncast record type, and Verifications 15, 18 and 19 are missing

- **Severity / status:** low / CONFIRMED; bucket `missing-component`; category `missing-spec-component`; known `none`
- **Spec:** §4 intro p.57 ('requires two applications'; §4 optional); §4.3/§4.3.1 pp.61-62; §4.4 pp.62-63; V15.A p.64; V18 (18.1-18.4, 18.A) p.66; V19 (19.A-19.D) p.67
- **Code:** src/ElectionGuard.Core/PreEncryption/ (encrypting tool only); src/ElectionGuard.Core/Verify/PreEncryption/ (only V16/V17); PreEncryptedBallot.cs:51-67

Only the §4.1-4.2 encrypting tool and V16/V17 exist. Nothing combines the voter-selected vectors and summed nonces, generates their proofs, emits a cast record (sorted selection hashes, selected vectors and short codes, accumulated vector) or an uncast record (released ξ_B or ξ_{i,j,k}), or verifies V15, V18 or V19. Without V18 there is no cut-and-choose audit, so a mislabeled vector would pass 16 and 17. The gap is deliberate and documented in docs/superpowers/specs/2026-10-04-short-codes-design.md:21.

**Fix sketch:** Implement the §4.3 recording tool, reusing BallotEncryptor's proof code, cast and uncast record types with serializers, and Verification 15, 18 and 19 classes. This depends on G17/G18 for nonce decryption.

**Verifier notes:** Both V18 verifiers rated it medium and called the security argument correct in principle. The other constituents were lowered to low. Low chosen for the merged item because §4 is optional, the scope is deliberately deferred in the design doc, and pre-encryption is not reachable from the pipeline. Raise to medium before pre-encrypted ballots are used in a real election. Verifiers note that the 'ChoiceId reveals the vote' impact was speculative.

### G32 — Contest-data decryption (§3.6.6, proof eqs 99/101 with 0x32/0x33) and Verification 12 are not implemented

- **Severity / status:** low / CONFIRMED; bucket `missing-component`; category `missing-spec-component`; known `none`
- **Spec:** §3.6.6 'Decryption of Contest Data (Optional)' eqs (96)-(106) pp.49-51; Verification 12 (12.A-12.C) p.51
- **Code:** absent (contest data only encrypted: BallotEncryptor.cs:184-208,348; no 0x32/0x33 in src)

Contest data is encrypted to K-hat, but nothing decrypts it with guardian K-hat shares, proves the decryption, or verifies it. Write-in and overvote data are therefore unrecoverable through this library. The section is optional, and V12 applies only once decryptions are published.

**Fix sketch:** Implement this together with G2: guardians check the 0x27 proof, compute partials m_i = C0^{ẑ_i} with d_i keyed by H_I (0x32) and challenge 0x33, decrypt using the corrected KDF (G11), and add ContestDataDecryptionVerification for 12.A-12.C. The table row lists B0 = H_E for eq 99 while the body says H_I; use H_I.

**Verifier notes:** The constituents split. Spec lenses refuted the 'required' framing because §3.6.6 is titled optional. Code lenses kept it at medium or info. Merged as low, explicitly an optional component.

### G33 — 6.B/6.C and 7.B/7.C reject a challenge or response of 0, but 0 is in Z_q

- **Severity / status:** low / CONFIRMED; bucket `divergence`; category `verification-stricter-than-spec`; known `none`
- **Spec:** Verification 6.B/6.C p.36; 7.B/7.C p.37 (Z_q = {x : 0 <= x < q})
- **Code:** src/ElectionGuard.Core/Verify/Ballot/SelectionEncryptionsWellFormedVerification.cs:232-235; AdherenceToVoteLimitsVerification.cs:184-187 ('!(value <= 0 || value > EGParameters.Q)')

IsInZq rejects 0. A prover may choose a simulated c_j = 0 and still produce a valid proof, and this verifier alone would reject that ballot. Honest random values hit 0 with probability about 2^-256. The '> Q' arm is dead because values are already reduced (G23).

**Fix sketch:** Make the check 0 <= x < q on the unreduced value. Update SelectionEncryptionsWellFormedVerificationTests.cs:106-141, AdherenceToVoteLimitsVerificationTests.cs (~101-126) and the comment at RangeProofChallengeTests.cs:236-237.

**Verifier notes:** Low or info. Kept low because a deliberate c_j = 0 from another implementation is legitimate and would be rejected.

### G34 — Guardian-record comparison hash H_G (eq 27) is keyed with H_P instead of H_B

- **Severity / status:** info / CONFIRMED; bucket `divergence`; category `hash-input-divergence`; known `none`
- **Spec:** §3.2.2 eq (27) p.27 (page image shows H_B); §5.5.2 'B0 = HB' p.74
- **Code:** src/ElectionGuard.Core/KeyGeneration/Guardian.cs:210,221

The separator and input order match the spec; only the key differs. H_G is computed and compared locally by one guardian and never published or exchanged, and the spec offers it only as a way the comparison 'can be done'. Pass/fail is unchanged and no artifact differs. The real residual problem, guardians never checking H_B, is part of G26.

**Fix sketch:** Once H_B is available to guardians (G26), key both hashes with it.

**Verifier notes:** The key-gen item was confirmed at low. The other two were split, with code lenses saying info or refuted. Info chosen because H_G is optional and local-only, so the interop claim is unsupported.

### G35 — Share decryption derives k_{i,l} with H_q (reduced mod q) where eq (16) specifies H; the encrypt side is correct

- **Severity / status:** info / CONFIRMED; bucket `divergence`; category `hash-input-divergence`; known `none`
- **Spec:** §3.2.2 eq (16) p.25; share decryption p.26
- **Code:** src/ElectionGuard.Core/KeyGeneration/Guardian.cs:161-168 (HashModQ(...).ToByteArray()) vs :85 (EGHash.Hash)

The two derivations differ only when the digest is >= q = 2^256-189, which happens with probability about 2^-248.6. If it ever did, the share would decrypt to garbage and fail the share check. Nothing is published, so there is no interop effect in practice.

**Fix sketch:** Use EGHash.Hash at line 161.

**Verifier notes:** Info or low; info chosen.

### G36 — 7.A tests the contest aggregates (alpha-bar, beta-bar) instead of each alpha_i and beta_i

- **Severity / status:** info / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `7A`
- **Spec:** Verification 7.A p.37 (page image: subscript i, no overbar), restated p.85
- **Code:** src/ElectionGuard.Core/Verify/Ballot/AdherenceToVoteLimitsVerification.cs:21-26 (components), :90-93 (fused), :115 (in-order)

Run on its own, V7 would accept per-selection non-members whose product is a member. In a full verification, 6.A checks exactly the same alpha_i and beta_i, so nothing extra is accepted; only the subsection label differs.

**Fix sketch:** Decision pending with the user. Optionally add a test with two non-members that cancel out.

**Verifier notes:** Spec lenses said low; code lenses said info because V6.A compensates. Info chosen.

### G37 — 8.D and 8.E chaining-field checks are tautological (both sides built from identical inputs); enforced only indirectly through 8.B

- **Severity / status:** info / CONFIRMED; bucket `divergence`; category `verification-weaker-than-spec`; known `8E`
- **Spec:** Verification 8.D/8.E p.44 (restated p.86)
- **Code:** src/ElectionGuard.Core/Verify/Ballot/ConfirmationCodeVerification.cs:35 vs :52-53 (8.D) and :60-61 (8.E)

The verifier builds B_C itself and compares it with an identical rebuild, so neither throw can be reached. Because B_C feeds the 8.B recomputation, a wrong chaining field is still rejected, but labelled 8.B. Chain ordering depends on the caller passing the correct previousConfirmationCode.

**Fix sketch:** Remove the dead comparisons, or document that 8.D/8.E are enforced through 8.B. Compare against a stored B_C if the record ever carries one. Update ConfirmationCodeVerificationTests.cs:191 accordingly.

**Verifier notes:** All agree there is no enforcement gap. The 8.D variant was folded into 8E per the reconcile verdict.

### G38 — V9 throws a plain Exception with no 9.A/9.B SubSection

- **Severity / status:** info / CONFIRMED; bucket `divergence`; category `other`; known `V9-5`
- **Spec:** Verification 9.A/9.B p.45
- **Code:** src/ElectionGuard.Core/Verify/Tally/BallotAggregationVerifier.cs:137,141

Mismatches are still rejected. A caller catching VerificationFailedException misses V9 failures. This is a project convention, not a spec requirement.

**Fix sketch:** Throw VerificationFailedException("9.A"/"9.B") and update BallotAggregationVerifierTests.cs:84 and the Assert.Throws<Exception> sites.

**Verifier notes:** Info agreed. One lens refuted it as not a spec divergence.

### G39 — Operations on secrets are not constant-time (vote-dependent branch in GenerateProofs, secret-indexed table lookups, data-dependent final subtraction in scalar Montgomery)

- **Severity / status:** info / PLAUSIBLE; bucket `divergence`; category `side-channel-or-randomness`; known `none`
- **Spec:** No spec requirement (no constant-time language in v2.1); §3.3.4 p.30 is about storing nonces encrypted
- **Code:** src/ElectionGuard.Core/BallotEncryption/BallotEncryptor.cs:295-304; MontgomeryModP.cs:866; PowRadix.cs:338; MontgomeryContext.cs:613-637

A co-resident attacker timing an encryption device or guardian could in principle learn the selected value or bits of nonces and key shares. Total work per GenerateProofs call does not depend on the vote, and the AVX-512 path avoids the conditional subtraction. There is no encryption or interop impact. This is hardening only.

**Fix sketch:** Use branch-free selection in GenerateProofs, masked full-table scans for secret exponents, and a branch-free ConditionalSubtractModulus.

**Verifier notes:** Spec lens refuted it (the spec has no requirement); code lens kept it at info. Included only as a security hardening note.

### G40 — EncryptedBallot cannot carry other §3.7 record items: encryption timestamp and per-device ordering (status is G21)

- **Severity / status:** info / CONFIRMED; bucket `interop-note`; category `missing-spec-component`; known `none`
- **Spec:** §3.7 p.55-56 (date/time of encryption; ordered lists per device; record structure deferred to a separate document)
- **Code:** src/ElectionGuard.Core/BallotEncryption/EncryptedBallot.cs:5-15

No encryption timestamp and no record-level per-device ordered list exist. Neither is a hash input. The spec defers the record's structure, and the election-record layer (Administration) is not built yet.

**Fix sketch:** Address when designing the ElectionRecord type: add a timestamp, a status (G21) and per-device ordered lists (G19).

**Verifier notes:** Lowered from low to info by both verifiers. The status part duplicates V9-3.

## Refuted candidates

- Verification 1.B-1.D compare against mutable EGParameters rather than hard-coded constants: refuted. The spec says parameters 'may be hardcoded', footnote-25 checks do not apply to fixed v2.1 parameters, and every non-test caller uses the defaults.
- V6/V7 crash with InvalidOperationException on a contest or choice not in the manifest: refuted. It fails closed, and the spec prescribes no error type.
- Guardians do no preliminary verification before partial decryption (§3.6.1): refuted. Footnote 46 allows delegating to trusted parties, and Program.cs runs V4-V9 before decrypting.
- TallyAdmin.Decrypt does not enforce quorum or distinct indices: refuted. Bad inputs always fail closed with an exception and no wrong tally, and the spec has no such check.
- Undefined ChainingMode skips 16.E/16.F; undefined HashTrimmingFunction throws: refuted. §3.4.4 allows other manifest-defined modes, 16.E/F are conditional, and an unknown Ω still rejects.
- 17.A short-code comparison is case-sensitive: refuted. §4.1.5 leaves the short-code format to the manifest; uppercase is documented and spec-consistent.
- Verifier does not check short-code uniqueness within a contest: refuted. V17 lists only 17.A; uniqueness is the producer's duty (§4.2) and the encryptor enforces it.
- 8.D tautological because EncryptedBallot stores no chaining field (verification-inventory variant): refuted. B_C need not be published and 8.B enforces it; kept only under known 8E (G37).
- Subsection labels '6.B/C', '7.B/C', '6', '7' do not match spec letters: refuted. Reporting labels are left to the implementation, and all checks are performed.
- No serializer for record artifacts other than EncryptedBallot; Program.cs writes {} for keys: refuted. The spec defers record serialization, and this is a sample-app bug only.
- JSON encoding differs from the draft data-serialization spec (Base64, naming): refuted. v2.1 p.6 says it does not specify serialization, and the draft is not normative.
- Test pins: ConfirmationCodeTests build confirmation codes with no B_C: refuted. Every production caller passes a real ChainingField; test-only API looseness.
- Test pins: write-in counter tests use the contest selection limit as range bound: refuted. Test-only restatement of G22 under SHOULD language in an optional section.
- Fixture masks: all fixtures enable the supplemental flags election-wide: refuted. Test-coverage restatement of G8, not a spec divergence.
- Test pins: ExpectedTallyTests define Undervotes as L minus the count of nonzero options: refuted. Test fixture only; the production issue is in G22.
- Tests pass short id_B and ξ_B: refuted. Production always uses 32 bytes; the validation gap is in G23.
- No known-answer vectors in the hash test suite: refuted. The spec does not require test vectors; known-answer tests are recommended in the fix sketches of G1/G6/G7.
- Known (V9-5, V9-2): V9 tests pin plain Exception and KeyNotFoundException: refuted. Test maintenance note; the KeyNotFoundException at line 283 comes from AddBallot, not V9-2.
