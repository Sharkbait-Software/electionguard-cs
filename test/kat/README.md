# ElectionGuard v2.1.0 hash-chain KAT oracle

`eg_kat.py` is an independent reference implementation of the ElectionGuard v2.1.0 hash chain,
used as a known-answer-test oracle for `ElectionGuard.Core`. It was written from the
specification text only (sections 3.1-3.4, 3.6.2-3.6.6, 4.1.4 and 5, and Verifications 10, 12 and 13, including the section 5.5
domain-separation tables) and the user's recorded decisions on spec contradictions (Q5, Q6, Q7 and Q10 in
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
