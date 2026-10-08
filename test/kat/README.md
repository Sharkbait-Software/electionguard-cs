# ElectionGuard v2.1.0 hash-chain KAT oracle

`eg_kat.py` is an independent reference implementation of the ElectionGuard v2.1.0 hash chain,
used as a known-answer-test oracle for `ElectionGuard.Core`. It was written from the
specification text only (sections 3.1-3.4, 3.6.2-3.6.7, 4.1-4.4 and 5, and Verifications 6, 7, 10 and 12-18, including the section 5.5
domain-separation tables) and the user's recorded decisions on spec contradictions (Q4, Q5, Q6, Q7, Q10 and Q20 in
`docs/spec-compliance/2026-10-04-fix-progress.md`), without reading the C# source or its existing test expectations, so its outputs are not
shaped by any encoding bug in the C# code.

It is Python 3, standard library only (`hmac`, `hashlib`, `json`). It transcribes the standard
parameters p, q, g and the cofactor r from section 3.1.1 and checks them on load (q = 2^256 - 189,
p is 4096 bits, p - 1 = q * r, g = 2^r mod p, g^q mod p = 1).

## Regenerate

From the repository root:

```
python test/kat/eg_kat.py
```

This rewrites `test/kat/vectors.json` and prints H_P for n = 3, k = 2.

## Covered equations

| Family | Equation |
|---|---|
| `parameter_base_hash` | (4) H_P = H(ver; 0x00, p, q, g, n, k) |
| `election_base_hash` | (5) H_B = H(H_P; 0x01, manifest), manifest length-prefixed |
| `guardian_share_kdf_key` | (16) k_{i,l} = H(H_P; 0x11, i, l, kappa_l, alpha, beta) |
| `guardian_record_hash` | (27) H_G = H(H_B; 0x13, K, K-hat, all K_{i,j}, all K-hat_{i,j}, kappa_1..kappa_n), guardian-major, len(B1) = 1 + (2 + 2nk + n) * 512 |
| `extended_base_hash` | (30) H_E = H(H_B; 0x14, K, K-hat) |
| `selection_encryption_identifier_hash` | (32) H_I = H(H_E; 0x20, id_B) |
| `encryption_nonce` | (33) xi_{i,j} = H_q(H_I; 0x21, i, j, xi_B) |
| `contest_hash` | (70) chi_l, options only (no contest data) |
| `device_info_hash` | (72) H_DI = H(H_E; 0x2A, S_device), S_device length-prefixed UTF-8 |
| `confirmation_code` | (71) H_C with B_C from (73) no chaining and (75)/(76) simple chaining |
| `chain_init` | (74) H_0 = H(H_E; 0x29, B_C,0) |
| `chain_close_inner`, `chain_close` | (78), (77) |
| `preencrypted_device_info_hash` | (119) H_DI = H(H_E; 0x43, S_device) |
| `tally_decryption_commitment_hash` | (88) d_i = H(H_E; 0x30, ind_c, ind_o, i, A, B, a_i, b_i, M_i, U), len(B1) = 2577 + 4 * #U |
| `tally_decryption_challenge` | (90) c = H_q(H_E; 0x31, ind_c, ind_o, A, B, a, b, M), len(B1) = 2569 (Verification 10.B) |
| `contest_data_nonce` | (64) xi = H_q(H_I; 0x25, ind_c, xi_B), len(B1) = 37 |
| `contest_data_secret_key` | (65) h = H(H_I; 0x26, ind_c, alpha, beta), alpha = g^xi, beta = K-hat^xi, len(B1) = 1029 |
| `contest_data_kdf_key` | (66) k_i = HMAC(h, b(i, 4) \|\| "data_enc_keys" \|\| 0x00 \|\| "contest_data" \|\| b(ind_c, 4) \|\| b(b_Lambda * 256, 4)), 1 <= i <= b_Lambda |
| `contest_data_encryption_challenge` | (67)-(69) C0, C1 and C2 = (c, v), c = H_q(H_I; 0x27, ind_c, a, C0, C1), len(B1) = 1029 + 32 * b_Lambda |
| `contest_hash_with_contest_data` | (70) chi_l with C0, C1, C2, len(B1) = 69 + (2m + 1) * 512 + 32 * b_Lambda |
| `contest_data_decryption_commitment_hash` | (99) d_i = H(H_I; 0x32, ind_c, i, C0, C1, C2, a_i, b_i, m_i, U), len(B1) = 2125 + 32 * b_Lambda + 4 * #U |
| `contest_data_decryption_challenge` | (101) c = H_q(H_I; 0x33, ind_c, C0, C1, C2, a, b, beta), len(B1) = 2117 + 32 * b_Lambda (Verification 12.B) |
| `ballot_nonce_secret_key` | (35) h = H(H_I; 0x22, alpha_B, beta_B), (alpha_B, beta_B) = (g^xi-hat_B, K-hat^xi-hat_B) (34), len(B1) = 1025 |
| `ballot_nonce_kdf_key` | (36) k_1 = HMAC(h, 0x01 \|\| "ballot_nonce" \|\| 0x00 \|\| "ballot_nonce_encrypt" \|\| 0x0100), message 36 bytes |
| `ballot_nonce_encryption_challenge` | (37), (38) C0 = alpha_B, C1 = b(xi_B, 32) xor k_1, C2 = (c_B, v_B), c_B = H_q(H_I; 0x23, a_B, C0, C1), len(B1) = 1057 |
| `ballot_nonce_decryption_secret_key` | (107), (108) m_i = C0^z-hat_i, beta_B = prod m_i^w_i, then h = H(H_I; 0x22, C0, beta_B), k_1 and xi_B = C1 xor k_1, len(B1) = 1025 |
| `challenged_ballot_contest_data_secret_key` | Verification 13.4-13.6: h = H(H_I; 0x26, ind_c, g^xi, K-hat^xi) from the released contest data nonce xi, len(B1) = 1029 |
| `challenged_ballot_contest_data_kdf_key` | Verification 13.7: k_l by eq. (66), l 1-based (Q6) |
| `challenged_ballot_contest_hash` | Verification 13.1-13.3: chi from (alpha, beta) recomputed with the released xi_{i,j} (eq. 33), with or without contest data |
| `challenged_ballot_confirmation_code` | Verification 13.B: H_C = H(H_I; 0x29, chi_1, ..., chi_mB, B_C) |
| `preencrypted_confirmation_code` | (116) H_C = H(H_I; 0x42, chi_1, ..., chi_mB, B_C), B_C per 16.E (no chaining) and 16.F (j = 1, 2), len(B1) = 37 + 32 * m_B |
| `preencrypted_chain_init` | (117) H_0 = H(H_E; 0x42, B_C,0), B_C,0 = 0x00000001 \|\| H_DI with the 0x43 H_DI of (119), len(B1) = 37 |
| `preencrypted_chain_close_inner`, `preencrypted_chain_close` | (120) H(H_E; 0x44, H_l, B_C,0), body form (Q4), len(B1) = 69; (118) H-bar = H(H_E; 0x42, B-bar_C), len(B1) = 37 |
| `preencrypted_encryption_nonce` | (121) xi_{i,j,k} = H_q(H_I; 0x45, i, j, k, xi_B), len(B1) = 45; i = ind_c, null vector l is j = m + l |
| `preencrypted_selection_hash`, `preencrypted_null_selection_hash` | (113), (114) psi = H(H_I; 0x40, alpha_1, beta_1, ..., alpha_m, beta_m), len(B1) = 1 + 2m * 512 (Verification 16.A, 18.3) |
| `preencrypted_contest_hash` | (115) chi_l = H(H_I; 0x41, ind_c(Lambda_l), psi_pi(1), ..., psi_pi(m+L)), hashes sorted ascending, len(B1) = 5 + (m + L) * 32 (16.B, 18.4) |
| `preencrypted_confirmation_code` (2 more) | (116) over real eq. (115) contest hashes (16.C, 18.A) |
| `preencrypted_range_proof_challenge` | (59) with R = 1 (= (41)/(50)), 0x24, on the recording tool's combined vector, len(B1) = 3081 (Verification 6) |
| `preencrypted_selection_limit_challenge` | (62), 0x24, no ind_o, on the combined vector, len(B1) = 5 + (2L + 4) * 512 (Verification 7) |

## Vector format

Each vector in `vectors.json` records the `equation`, the key (`b0_name`, `b0_hex`), every input,
the exact message bytes hashed (`b1_hex`, `b1_len`), the length the spec's section 5.5 table prints
(`b1_len_spec_table`, `null` where the table prints none), and `expected_hex`. For H_q families
`expected_hex` is the reduced value as 32 bytes and `expected_hmac_hex` is the raw HMAC output.
Hex is uppercase big-endian. `main_chain` summarizes the n = 3, k = 2 chain the later vectors build on.

`guardian_record_hash` vectors also carry `b1_layout`, a list of `[offset, length, label]` for every field of
B1, so an ordering bug can be located. Every slot is a distinct group element, K = prod K_{i,0} and
K-hat = prod K-hat_{i,0} (eqs. 25, 26), and the n = 3, k = 2 case is built so that K = g^5 and K-hat = g^7,
the key pair `main_chain` uses for H_E. These vectors are appended after all earlier families, so existing
vector positions are unchanged.

`tally_decryption_commitment_hash` and `tally_decryption_challenge` vectors (sections 3.6.2-3.6.5) are complete,
valid tally decryption proofs on the `main_chain` election. The guardian polynomials are the ones the n = 3, k = 2
`guardian_record_hash` vector commits to (s = 5, so K = g^5), z_i = P(i) per eq. (83), and (A, B) is the product of
three genuine ballot encryptions (eq. 33 nonces) for the given (ind_c, ind_o), so t is known. Three cases cover
U = {1, 3} (t = 2), U = {1, 2, 3} (t = 3, one u_i = q - 2) and U = {2, 3} (t = 0). The set U is encoded as
b(#U, 4) followed by b(j, 4) for each j in ascending order; the spec does not state the order, so a consumer
that orders U differently will disagree. Each challenge vector carries the whole proof under `inputs.proof`
(c, v, t, T and per guardian w_i, z_i, u_i, M_i, a_i, b_i, d_i, c_i, v_i), and the script asserts Verification
10 (10.1-10.3 recompute exactly M, a, b; 10.A-10.C) and Note 3.7 (eqs. 94, 95) for each. Verification 10 uses no
hash other than eq. (90). These vectors carry `b1_layout` and are appended after all earlier families; the
top-level `tally_decryption` key (after `vectors`) summarizes the setup.

### Contest data (sections 3.3.10 and 3.6.6)

The contest data families sit on the `main_chain` ballot (its H_I, xi_B = A0A1..BF and K-hat = g^7) and are
appended after all earlier families. Five ciphertexts cover b_Lambda = 1 and 3: the empty string, an ASCII
string, a multi-block non-ASCII string, and strings that exactly fill 32 * b_Lambda bytes (28 UTF-8 bytes for
b_Lambda = 1, 92 for b_Lambda = 3). Each `contest_data_encryption_challenge` vector carries xi, alpha, beta,
h, every k_i, the fixed Schnorr nonce u and a = g^u in `inputs`, and C0, C1, c, v and `C2_hex` under
`ciphertext`. The script checks g^v * C0^c = a and that C1 decrypts back to D.

Encoding choices to know about:

- `D_hex` is the plaintext the spec operates on. The string-to-D step is the library helper fixed by user decision
  Q7, not spec: b(len_utf8, 4) || UTF-8 bytes, zero-padded to exactly 32 * b_Lambda bytes, rejected if it does
  not fit. The top-level `contest_data.string_helper_rejections` lists strings one byte over capacity.
- Label and Context are the raw UTF-8 bytes of `data_enc_keys` (13) and `contest_data` (12), with underscores as on
  the p.40 page image, with no length prefix. The KDF counter i is 1-based (Q6; Verification 13.7's 0 <= l < b_Lambda
  is treated as an erratum). The last field is the key length in bits, b_Lambda * 256.
- b(C2, 64) is b(c, 32) || b(v, 32). The spec writes C2 = (c, v) and b(C2, 64) without spelling out the split.
- In eq. (70) the table's 69 is 1 (0x28) + 4 (l) + 64 (C2), (2m + 1) * 512 is the m (alpha, beta) pairs plus C0,
  and 32 * b_Lambda is C1.
- Eq. (99) is keyed with H_I, per the body and user decision Q5. The section 5.5.4 table prints B0 = H_E, which is
  treated as an erratum; its B1 layout and length are used as printed. U is ascending (Q10).

The decryption vectors are complete, valid proofs. The guardians' ballot-data-key polynomials are the K-hat ones
the n = 3, k = 2 `guardian_record_hash` vector commits to (s-hat = 7). The script asserts that beta = prod m_i^w_i
equals K-hat^xi, that the decryption-side h = H(H_I; 0x26, ind_c, C0, beta) equals the encryption-side h of eq.
(65), that Verification 12.1-12.2 recompute exactly a and b, that 12.A-12.C hold, and that the per-guardian
relations hold. A `confirmation_code` vector over the three contest hashes with contest data is also appended.

### Ballot nonce and challenged ballots (sections 3.3.4 and 3.6.7, Verifications 13 and 14)

These families are appended after all earlier families; the top-level `challenged_ballots` key (after
`contest_data`) summarizes them. The ballot nonce is encrypted to K-hat = g^7 and decrypted by the n = 3, k = 2
guardians' K-hat shares (`contest_data.z_hat_i`). Four cases cover the `main_chain` ballot twice (xi-hat_B = 9001
with U = {1, 3}, and xi-hat_B = q - 1 with U = {1, 2, 3}), the ballot with id_B = q + 5 and xi_B = 2^256 - 1 (at
least q, so it must be encoded as a 256-bit value and never reduced), and a sparse ballot whose contests have
ind_c = 2 and 5. The spec draws xi-hat_B and u_B uniformly from Z_q and defines no derivation for them, so they are
fixed inputs. For each case the script checks g^v_B * C0^c_B = a_B and the p.52 guardian check, that
beta_B = prod m_i^w_i = K-hat^xi-hat_B, that the decryption-side h equals the encryption-side h, and that
C1 xor k_1 = b(xi_B, 32).

Encoding choices to know about:

- Eq. (36) is read literally from the p.30 page image: a one-byte counter 0x01 and a two-byte length 0x0100
  (256 bits), the shape of eqs. (17) and (18) and footnote 34. This is not the 4-byte form of eq. (66). Label and
  Context are the raw UTF-8 bytes of `ballot_nonce` (12) and `ballot_nonce_encrypt` (20), with underscores as on
  the page image and no length prefix. The Context carries no index. The message is always the same 36 bytes.
- `ciphertext.C2_hex` is b(c_B, 32) || b(v_B, 32) (Q20 order). C_xiB is not hashed into any contest hash or
  confirmation code, so for the ballot nonce this order matters only for serialization.
- The spec defines no proof of correct decryption for the ballot nonce: there is no commitment or challenge hash and
  no section 5.5.4 row. Section 3.6.7 says xi_B should not be published. Only the released nonces xi_{i,j} (eq. 33)
  and xi (eq. 64) are published, and Verification 13 checks them. The only proof involved is the guardians' check of
  the eq. (38) Schnorr proof before they decrypt, and no numbered verification covers that check.

The Verification 13 vectors start from the guardians' decrypted xi_B. They derive the released nonces, recompute
(13.1) and (13.2) (and assert they equal the ballot's recorded ciphertexts), recover sigma by eq. (109), recompute
(13.4) to (13.7) with the KDF counter 1-based (Q6; 13.7's 0 <= l < b_Lambda is an erratum), check (13.A) and
eq. (111), and emit chi (13.3) and H_C (13.B). For the `main_chain` ballot the script asserts that the results equal
the earlier `contest_hash_with_contest_data` and `confirmation_code` vectors. The sparse ballot uses simple chaining
(B_C = 0x00000001 || H_0). Its contest ind_c = 2 has no contest data, so its chi is eq. (70) without C0, C1 and C2
and has no printed table length. Its contest ind_c = 5 has contest data with b_Lambda = 2. In (13.3) the field after
0x28 is ind_c(Lambda_i), which is eq. (70)'s l and not the contest's position on the ballot; the sparse ballot makes
the two differ. Verification 14 compares labels and selection ranges and computes no hash, so it has no vectors.

### Pre-encrypted ballot chaining (section 4.1.4, Verification 16.E-16.H)

These families are appended after all earlier families; the top-level `preencrypted_chain` key (after
`challenged_ballots`) summarizes them. They run on the `main_chain` election and device string, with the
pre-encrypted device hash H_DI of eq. (119) (separator 0x43, already the `preencrypted_device_info_hash` family).
The chain is H_0 (117), H_1 on the `main_chain` ballot with two contests, H_2 on the id_B = q + 5 ballot with one
contest, then the close (120)/(118) with H_l = H_2. A no-chaining H_C (B_C = 0x00000000 || H_DI, 16.E) is included.
The contest hashes fed to eq. (116) are opaque labelled 32-byte stand-ins (bytes 0x50..0x6F, 0x70..0x8F, 0x90..0xAF):
eqs. (113)-(115) (selection and contest hashes) are not covered by this oracle.

Encoding choices to know about:

- Eq. (120) uses the body form B1 = 0x44 || H_l || B_C,0 (user decision Q4). The section 5.5.5 table prints
  B1 = 0x44 || 0x4C4F434B ('LOCK') || H_l || B_C,0, which is treated as an erratum. The same table row prints
  len(B1) = 69, which only the body form satisfies (the LOCK layout is 73 bytes). The vector carries the LOCK-layout
  B1 and hash under `lock_form_erratum` with `"expected": false`, so a consumer that followed the table can be
  diagnosed.
- The table row for (118), like the one for (77), prints no B0. H_E is used, per the equation.
- The regular-ballot chain families `chain_init`, `chain_close_inner` and `chain_close` (eqs. 74, 78, 77; separators
  0x29, 0x2B, 0x29; lengths 37, 69, 37) were rechecked against p.43, the section 5.5.3 table (p.76) and Verification
  8.F/8.G and are unchanged.

### Pre-encrypted ballots (sections 4.1-4.4, Verifications 15-18)

These families are appended after all earlier families; the top-level `preencrypted_ballots` key (after
`preencrypted_chain`) summarizes them, including every contest's selection hashes in generation order, pi, short
codes and, for the cast ballot, the recording tool's combined vector. Both ballots sit on the `main_chain` election
(K = g^5) with their own labelled id_B and xi_B:

- P1 (cast): contests (ind_c, m, L) = (1, 3, 1), (3, 4, 2), (4, 2, 2) at positions 1, 2, 3. The voter selects option 2,
  options 1 and 4, and option 2 alone. No chaining (B_C = 0x00000000 || the 0x43 H_DI of `main_chain`).
- P2 (uncast): contests (2, 2, 1), (5, 3, 2) at positions 1, 2, xi_B = q + 11 (at least q, never reduced). Simple
  chaining as ballot j = 1 on its own device (`kat pre-encrypted ballot printer 2`, whose eq. (119) H_DI and eq. (117)
  H_0 are appended to `preencrypted_device_info_hash` and `preencrypted_chain_init`). Every released nonce
  xi_{i,j,k} is an eq. (121) vector, and the script runs Verification 18 (18.1-18.4, 18.A) from them.

For each contest the encrypting tool builds m selection vectors (eq. 112: Enc(1; xi_{i,j,j}) at position j, Enc(0;
xi_{i,j,k}) elsewhere) and L null vectors, hashes each (113, 114), sorts the m + L hashes as big-endian integers
(lexicographic byte order) and hashes them with b(ind_c, 4) (115). Each `preencrypted_contest_hash` vector carries
`diagnostics` with the hash of the unsorted form and, where position and ind_c differ, of the position form
(16.B's literal l); these are `"expected": false`.

For the cast ballot the recording tool (section 4.3) multiplies the chosen vectors componentwise and adds their
nonces mod q, then proves each component with eq. (59), R = 1, and the contest total with eq. (62), R = L. The spec
gives these no new domain separator or table row ("as in standard ElectionGuard section 3.3.7"), so they are the
section 5.5.3 rows for (41)/(50)/(59) and (62), keyed with the pre-encrypted ballot's H_I. These are also the oracle's
first 0x24 vectors. The prover's random u_j and c_j (j != l) are fixed labelled inputs. The script asserts
Verification 15.A (the product), 6.1-6.3 and 6.A-6.D, and 7.1-7.5 and 7.A-7.D for each proof.

Short codes: Omega is defined by the manifest, not the spec. `short_codes` lists three spec examples per selection
hash (last byte as two hex characters, last byte as a three-digit number, and the 1-based sorted ordinal of section
4.2.2). The script asserts that the last-byte codes are unique within each contest.

Spec ambiguities, also listed under `preencrypted_ballots.spec_ambiguities`:

- 16.B writes `l` (the contest's sequence number) where eq. (115) and the table write ind_c(Lambda_l). ind_c is used
  (precedent: the S7 decision on 13.3).
- Verification 18.2-18.4 make each vector m_i long and hash only m_i selection hashes; eqs. (114), (115), the table
  and 16.B include the L null hashes. Eq. (115) is followed.
- Eq. (121) indexes the contest by its index i (section 4.2.1) while (18.1) indexes it by position. ind_c is used.
  Option indices are contiguous 1..m, so option index and position agree for j and k.
- Null vector l uses j = m + l in eq. (121) ("the sequence of indices should be extended accordingly").
- On an undervote the recording tool is taken to pad the combination with null vectors, so exactly L vectors are
  always combined. The spec does not say so explicitly (P1's ind_c = 4 contest).
- Section 4.4 publishes an uncast ballot's xi_B; section 4.3 and Verification 18 release the xi_{i,j,k}.
- The earlier `preencrypted_confirmation_code` vectors (section 4.1.4) use opaque contest-hash stand-ins and keep
  their values; their notes predate these families.
