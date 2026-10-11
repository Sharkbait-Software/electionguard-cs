#!/usr/bin/env python3
"""ElectionGuard v2.1.0 hash-chain known-answer-test (KAT) oracle.

Written from the ElectionGuard Design Specification v2.1.0 ONLY (sections 3.1-3.4, 3.6.2-3.6.7,
4.1-4.4 and 5, and Verifications 6, 7, 10 and 12-18), plus the user's recorded decisions Q4-Q7, Q10 and Q20 on spec
contradictions (docs/spec-compliance/2026-10-04-fix-progress.md), without reference to the C# implementation in this repository,
so that its outputs can be used as independent expected values. Standard library only.

Run from the repository root:

    python test/kat/eg_kat.py

It writes test/kat/vectors.json next to this script.
"""

import hashlib
import hmac
import json
import os
import sys

# ---------------------------------------------------------------------------------------------
# Standard baseline parameters, §3.1.1 (pp. 14-15), transcribed verbatim from the spec.
# ---------------------------------------------------------------------------------------------

_Q_HEX = """
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFF43
"""

_P_HEX = """
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
B17217F7 D1CF79AB C9E3B398 03F2F6AF 40F34326 7298B62D 8A0D175B 8BAAFA2B
E7B87620 6DEBAC98 559552FB 4AFA1B10 ED2EAE35 C1382144 27573B29 1169B825
3E96CA16 224AE8C5 1ACBDA11 317C387E B9EA9BC3 B136603B 256FA0EC 7657F74B
72CE87B1 9D6548CA F5DFA6BD 38303248 655FA187 2F20E3A2 DA2D97C5 0F3FD5C6
07F4CA11 FB5BFB90 610D30F8 8FE551A2 EE569D6D FC1EFA15 7D2E23DE 1400B396
17460775 DB8990E5 C943E732 B479CD33 CCCC4E65 9393514C 4C1A1E0B D1D6095D
25669B33 3564A337 6A9C7F8A 5E148E82 074DB601 5CFE7AA3 0C480A54 17350D2C
955D5179 B1E17B9D AE313CDB 6C606CB1 078F735D 1B2DB31B 5F50B518 5064C18B
4D162DB3 B365853D 7598A195 1AE273EE 5570B6C6 8F969834 96D4E6D3 30AF889B
44A02554 731CDC8E A17293D1 228A4EF9 8D6F5177 FBCF0755 268A5C1F 9538B982
61AFFD44 6B1CA3CF 5E9222B8 8C66D3C5 422183ED C9942109 0BBB16FA F3D949F2
36E02B20 CEE886B9 05C128D5 3D0BD2F9 62136319 6AF50302 0060E499 08391A0C
57339BA2 BEBA7D05 2AC5B61C C4E9207C EF2F0CE2 D7373958 D7622658 90445744
FB5F2DA4 B7510058 92D35689 0DEFE9CA D9B9D4B7 13E06162 A2D8FDD0 DF2FD608
FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
"""

_R_HEX = """
01 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000BC
B17217F7 D1CF79AB C9E3B398 03F2F6AF 40F34326 7298B62D 8A0D175B 8BAB857A
E8F42816 5418806C 62B0EA36 355A3A73 E0C74198 5BF6A0E3 130179BF 2F0B43E3
3AD86292 3861B8C9 F768C416 9519600B AD06093F 964B27E0 2D868312 31A9160D
E48F4DA5 3D8AB5E6 9E386B69 4BEC1AE7 22D47579 249D5424 767C5C33 B9151E07
C5C11D10 6AC446D3 30B47DB5 9D352E47 A53157DE 04461900 F6FE360D B897DF53
16D87C94 AE71DAD0 BE84B647 C4BCF818 C23A2D4E BB53C702 A5C8062D 19F5E9B5
033A94F7 FF732F54 12971286 9D97B8C9 6C412921 A9D86797 70F499A0 41C297CF
F79D4C91 49EB6CAF 67B9EA3D C563D965 F3AAD137 7FF22DE9 C3E62068 DD0ED615
1C37B4F7 4634C2BD 09DA912F D599F433 3A8D2CC0 05627DCA 37BAD43E 64A39631
19C0BFE3 4810A21E E7CFC421 D53398CB C7A95B3B F585E5A0 4B790E2F E1FE9BC2
64FDA810 9F6454A0 82F5EFB2 F37EA237 AA29DF32 0D6EA860 C41A9054 CCD24876
C6253F66 7BFB0139 B5531FF3 01899612 02FD2B0D 55A75272 C7FD7334 3F7899BC
A0B36A4C 470A64A0 09244C84 E77CEBC9 2417D5BB 13BF1816 7D8033EB 6C4DD787
9FD4A7F5 29FD4A7F 529FD4A7 F529FD4A 7F529FD4 A7F529FD 4A7F529F D4A7F52A
"""

_G_HEX = """
36036FED 214F3B50 DC566D3A 312FE413 1FEE1C2B CE6D02EA 39B477AC 05F7F885
F38CFE77 A7E45ACF 4029114C 4D7A9BFE 058BF2F9 95D2479D 3DDA618F FD910D3C
4236AB2C FDD783A5 016F7465 CF59BBF4 5D24A22F 130F2D04 FE93B2D5 8BB9C1D1
D27FC9A1 7D2AF49A 779F3FFB DCA22900 C14202EE 6C996160 34BE35CB CDD3E7BB
7996ADFE 534B63CC A41E21FF 5DC778EB B1B86C53 BFBE9998 7D7AEA07 56237FB4
0922139F 90A62F2A A8D9AD34 DFF799E3 3C857A64 68D001AC F3B681DB 87DC4242
755E2AC5 A5027DB8 1984F033 C4D17837 1F273DBB 4FCEA1E6 28C23E52 759BC776
5728035C EA26B44C 49A65666 889820A4 5C33DD37 EA4A1D00 CB62305C D541BE1E
8A92685A 07012B1A 20A746C3 591A2DB3 815000D2 AACCFE43 DC49E828 C1ED7387
466AFD8E 4BF19355 93B2A442 EEC271C5 0AD39F73 3797A1EA 11802A25 57916534
662A6B7E 9A9E449A 24C8CFF8 09E79A4D 806EB681 119330E6 C57985E3 9B200B48
93639FDF DEA49F76 AD1ACD99 7EBA1365 7541E79E C57437E5 04EDA9DD 01106151
6C643FB3 0D6D58AF CCD28B73 FEDA29EC 12B01A5E B86399A5 93A9D5F4 50DE39CB
92962C5E C6925348 DB54D128 FD99C14B 457F883E C20112A7 5A6A0581 D3D80A3B
4EF09EC8 6F9552FF DA1653F1 33AA2534 983A6F31 B0EE4697 935A6B1E A2F75B85
E7EBA151 BA486094 D68722B0 54633FEC 51CA3F29 B31E77E3 17B178B6 B9D8AE0F
"""


def _hex(s):
    return "".join(s.split())


Q = int(_hex(_Q_HEX), 16)
P = int(_hex(_P_HEX), 16)
R = int(_hex(_R_HEX), 16)
G = int(_hex(_G_HEX), 16)

LP = 512  # byte length of p (§5.1.1)
LQ = 32   # byte length of q (§5.1.2)


def _check_parameters():
    assert len(_hex(_Q_HEX)) == 64
    assert len(_hex(_P_HEX)) == 1024
    assert len(_hex(_G_HEX)) == 1024
    assert Q == 2**256 - 189, "q != 2^256 - 189"
    assert P.bit_length() == 4096, "p is not 4096 bits"
    # §3.1.1 properties 1 and 2: first and last 256 bits of p are ones.
    assert P >> (4096 - 256) == 2**256 - 1
    assert P & (2**256 - 1) == 2**256 - 1
    # §3.1.1 property 3 and the cofactor r = (p - 1) / q printed on p. 15.
    assert (P - 1) % Q == 0 and (P - 1) // Q == R, "p - 1 != q * r"
    # g = 2^r mod p (p. 15) and g has order q.
    assert G == pow(2, R, P), "g != 2^r mod p"
    assert 1 < G < P
    assert pow(G, Q, P) == 1, "g^q mod p != 1"
    # Cheap Fermat probable-prime checks on p, q and (p-1)/2q (§3.1.1 property 4).
    for base in (2, 3, 5):
        assert pow(base, P - 1, P) == 1
        assert pow(base, Q - 1, Q) == 1
        s = (P - 1) // (2 * Q)
        assert pow(base, s - 1, s) == 1


_check_parameters()

# ---------------------------------------------------------------------------------------------
# §5.1 encodings and §5.2-§5.4 hash functions.
# ---------------------------------------------------------------------------------------------


def b(x, length):
    """b(x, len): big-endian fixed-width encoding (eq. 123). Never truncates."""
    if not (0 <= x < 2 ** (8 * length)):
        raise ValueError(f"{x} does not fit in {length} bytes")
    return x.to_bytes(length, "big")


def b_small(x):
    """§5.1.3 small integer (index, n, k): 4 bytes, must be < 2^31."""
    if not (0 <= x < 2**31):
        raise ValueError(f"small integer {x} out of range")
    return b(x, 4)


def b_p(x):
    if not (0 <= x < P):
        raise ValueError("not in Z_p")
    return b(x, LP)


def b_q(x):
    if not (0 <= x < Q):
        raise ValueError("not in Z_q")
    return b(x, LQ)


def b_string(s):
    """§5.1.4 variable-length string: b(len, 4) || UTF-8 bytes (length is the UTF-8 byte length)."""
    enc = s.encode("utf-8")
    return b_small(len(enc)) + enc


def b_file(data):
    """§5.1.5 file: b(len(file), 4) || file bytes."""
    return b_small(len(data)) + data


def H(b0, b1):
    """§5.2 eq. (130): H(B0; B1) = HMAC-SHA-256(B0, B1), with |B0| = 32."""
    assert len(b0) == 32, "every B0 in ElectionGuard is exactly 32 bytes"
    return hmac.new(b0, b1, hashlib.sha256).digest()


def Hq(b0, b1):
    """§5.4 eq. (132): H_q = H mod q."""
    return int.from_bytes(H(b0, b1), "big") % Q


VER = bytes.fromhex("76322E312E30") + b(0, 26)  # "v2.1.0" || b(0, 26), §3.1.2
assert len(VER) == 32 and VER[:6] == "v2.1.0".encode("utf-8")

# ---------------------------------------------------------------------------------------------
# Hash-chain functions. Each returns (B1, output bytes).
# ---------------------------------------------------------------------------------------------


def parameter_base_hash(n, k):
    """Eq. (4): H_P = H(ver; 0x00, p, q, g, n, k)."""
    # p itself is not in Z_p, so it is encoded directly as b(p, l_p).
    b1 = b"\x00" + b(P, LP) + b(Q, LQ) + b_p(G) + b_small(n) + b_small(k)
    assert len(b1) == 1065
    return b1, H(VER, b1)


def election_base_hash(h_p, manifest):
    """Eq. (5): H_B = H(H_P; 0x01, manifest), manifest as a file input (§5.1.5)."""
    b1 = b"\x01" + b_file(manifest)
    assert len(b1) == 5 + len(manifest)
    return b1, H(h_p, b1)


def guardian_share_key(h_p, i, l, kappa_l, alpha, beta):
    """Eq. (16): k_{i,l} = H(H_P; 0x11, i, l, kappa_l, alpha_{i,l}, beta_{i,l})."""
    b1 = b"\x11" + b_small(i) + b_small(l) + b_p(kappa_l) + b_p(alpha) + b_p(beta)
    assert len(b1) == 1545
    return b1, H(h_p, b1)


def guardian_record_hash(h_b, K, K_hat, Ks, K_hats, kappas):
    """Eq. (27): H_G = H(H_B; 0x13, K, K-hat, K_1,0, ..., K_n,k-1, K-hat_1,0, ..., K-hat_n,k-1, kappa_1, ..., kappa_n).

    Ks[i-1][j] = K_{i,j} and K_hats[i-1][j] = K-hat_{i,j} for 1 <= i <= n, 0 <= j < k; kappas[i-1] = kappa_i.
    Order per the p.27 page image and the §5.5.2 table: guardian-major (i outer, j inner), all K before all
    K-hat, then the communication keys. Returns (B1, H_G, layout) with layout = [(offset, len, label), ...].
    """
    n, k = len(Ks), len(Ks[0])
    assert len(K_hats) == n and len(kappas) == n
    assert all(len(r) == k for r in Ks) and all(len(r) == k for r in K_hats)
    parts = [(b"\x13", "0x13"), (b_p(K), "K"), (b_p(K_hat), "K_hat")]
    for i in range(1, n + 1):
        for j in range(k):
            parts.append((b_p(Ks[i - 1][j]), f"K_{i},{j}"))
    for i in range(1, n + 1):
        for j in range(k):
            parts.append((b_p(K_hats[i - 1][j]), f"K_hat_{i},{j}"))
    for i in range(1, n + 1):
        parts.append((b_p(kappas[i - 1]), f"kappa_{i}"))
    b1, layout = b"", []
    for data, label in parts:
        layout.append([len(b1), len(data), label])
        b1 += data
    assert len(b1) == 1 + (2 + 2 * n * k + n) * 512  # §5.5.2 table
    return b1, H(h_b, b1), layout


def extended_base_hash(h_b, K, K_hat):
    """Eq. (30): H_E = H(H_B; 0x14, K, K-hat)."""
    b1 = b"\x14" + b_p(K) + b_p(K_hat)
    assert len(b1) == 1025
    return b1, H(h_b, b1)


def selection_encryption_identifier_hash(h_e, id_b):
    """Eq. (32): H_I = H(H_E; 0x20, id_B), id_B a 256-bit value encoded b(id_B, 32) (not reduced mod q)."""
    b1 = b"\x20" + b(id_b, 32)
    assert len(b1) == 33
    return b1, H(h_e, b1)


def encryption_nonce(h_i, i, j, xi_b):
    """Eq. (33): xi_{i,j} = H_q(H_I; 0x21, i, j, xi_B), xi_B a 256-bit value b(xi_B, 32)."""
    b1 = b"\x21" + b_small(i) + b_small(j) + b(xi_b, 32)
    assert len(b1) == 41
    return b1, H(h_i, b1)


def contest_hash(h_i, l, ciphertexts):
    """Eq. (70) with no contest data: chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_m, beta_m)."""
    b1 = b"\x28" + b_small(l)
    for alpha, beta in ciphertexts:
        b1 += b_p(alpha) + b_p(beta)
    # The §5.5 table only prints the with-contest-data length 69 + (2m+1)*512 + b*32; with C0, C1,
    # C2 omitted (body text under eq. 70) the length is 5 + 2m*512.
    assert len(b1) == 5 + 2 * len(ciphertexts) * 512
    return b1, H(h_i, b1)


def confirmation_code(h_i, contest_hashes, b_c, sep=0x29):
    """Eq. (71): H_C = H(H_I; 0x29, chi_1, ..., chi_mB, B_C). (Eq. (116) uses 0x42.)"""
    assert len(b_c) == 36 and all(len(c) == 32 for c in contest_hashes)
    b1 = bytes([sep]) + b"".join(contest_hashes) + b_c
    assert len(b1) == 37 + 32 * len(contest_hashes)
    return b1, H(h_i, b1)


def device_info_hash(h_e, s_device, sep=0x2A):
    """Eq. (72) (sep 0x2A) / eq. (119) (sep 0x43): H_DI = H(H_E; sep, S_device), S_device length-prefixed."""
    b1 = bytes([sep]) + b_string(s_device)
    assert len(b1) == 5 + len(s_device.encode("utf-8"))
    return b1, H(h_e, b1)


def b_c_no_chaining(h_di):
    """Eq. (73): B_C = 0x00000000 || H_DI."""
    return b"\x00\x00\x00\x00" + h_di


def b_c0_simple(h_di):
    """Eq. (75): B_{C,0} = 0x00000001 || H_DI."""
    return b"\x00\x00\x00\x01" + h_di


def b_c_simple(h_prev):
    """Eq. (76): B_{C,j} = 0x00000001 || H_{j-1}."""
    return b"\x00\x00\x00\x01" + h_prev


def chain_init(h_e, b_c0, sep=0x29):
    """Eq. (74) (sep 0x29) / eq. (117) (sep 0x42): H_0 = H(H_E; sep, B_{C,0})."""
    b1 = bytes([sep]) + b_c0
    assert len(b1) == 37
    return b1, H(h_e, b1)


def chain_close_bc(h_e, h_last, b_c0, sep=0x2B):
    """Eq. (78) (sep 0x2B) / eq. (120) (sep 0x44): B-bar_C = 0x00000001 || H(H_E; sep, H_l, B_{C,0}).
    Returns (inner B1, inner hash, B-bar_C). Eq. (120) uses the body form (user decision Q4): the
    §5.5.5 table's extra 0x4C4F434B ('LOCK') after 0x44 is an erratum; the table's own len(B1) = 69
    agrees with the body (1 + 32 + 36), not with its printed layout (1 + 4 + 32 + 36 = 73)."""
    assert len(h_last) == 32 and len(b_c0) == 36
    b1 = bytes([sep]) + h_last + b_c0
    assert len(b1) == 69
    inner = H(h_e, b1)
    return b1, inner, b"\x00\x00\x00\x01" + inner


def chain_close(h_e, b_c_bar, sep=0x29):
    """Eq. (77) (sep 0x29) / eq. (118) (sep 0x42): H-bar = H(H_E; sep, B-bar_C)."""
    assert len(b_c_bar) == 36
    b1 = bytes([sep]) + b_c_bar
    assert len(b1) == 37
    return b1, H(h_e, b1)


def _layout(parts):
    """Concatenate [(bytes, label), ...] into (B1, [[offset, length, label], ...])."""
    b1, layout = b"", []
    for data, label in parts:
        layout.append([len(b1), len(data), label])
        b1 += data
    return b1, layout


def b_index_set(U):
    """The set U of participating guardian indices as the §5.5.4 table encodes it:
    b(#U, 4) || b(j_1, 4) || ... || b(j_#U, 4). The spec does not state the order of j_1..j_#U;
    this oracle uses ascending order (U as a sorted list of distinct 1-based indices)."""
    U = list(U)
    assert U == sorted(set(U)) and all(j >= 1 for j in U), "U must be distinct, ascending, 1-based"
    parts = [(b_small(len(U)), "#U")] + [(b_small(j), f"j_{m}={j}") for m, j in enumerate(U, start=1)]
    return parts


def tally_decryption_commitment_hash(h_e, ind_c, ind_o, i, A, B, a_i, b_i, M_i, U):
    """Eq. (88): d_i = H(H_E; 0x30, ind_c(Lambda), ind_o(lambda), i, A, B, a_i, b_i, M_i, U), §3.6.5.

    §5.5.4 table (p.77): B0 = H_E, B1 = 0x30 || b(ind_c, 4) || b(ind_o, 4) || b(i, 4) || b(A, 512) || b(B, 512)
    || b(a_i, 512) || b(b_i, 512) || b(M_i, 512) || b(#U, 4) || b(j_1, 4) || ... || b(j_#U, 4),
    len(B1) = 2577 + 4 * #U. Returns (B1, d_i, layout)."""
    assert i in U, "the committing guardian must be in U"
    parts = [(b"\x30", "0x30"), (b_small(ind_c), "ind_c"), (b_small(ind_o), "ind_o"), (b_small(i), "i"),
             (b_p(A), "A"), (b_p(B), "B"), (b_p(a_i), "a_i"), (b_p(b_i), "b_i"), (b_p(M_i), "M_i")]
    parts += b_index_set(U)
    b1, layout = _layout(parts)
    assert len(b1) == 2577 + 4 * len(U)
    return b1, H(h_e, b1), layout


def tally_decryption_challenge(h_e, ind_c, ind_o, A, B, a, b_, M):
    """Eq. (90) / Verification 10.B: c = H_q(H_E; 0x31, ind_c(Lambda), ind_o(lambda), A, B, a, b, M), §3.6.5.

    §5.5.4 table (p.77): B0 = H_E, B1 = 0x31 || b(ind_c, 4) || b(ind_o, 4) || b(A, 512) || b(B, 512)
    || b(a, 512) || b(b, 512) || b(M, 512), len(B1) = 2569. Returns (B1, raw HMAC, layout); c = raw mod q."""
    parts = [(b"\x31", "0x31"), (b_small(ind_c), "ind_c"), (b_small(ind_o), "ind_o"),
             (b_p(A), "A"), (b_p(B), "B"), (b_p(a), "a"), (b_p(b_), "b"), (b_p(M), "M")]
    b1, layout = _layout(parts)
    assert len(b1) == 2569
    return b1, H(h_e, b1), layout


def lagrange_coefficient(i, U):
    """Eq. (85): w_i = prod_{l in U \\ {i}} l / (l - i) mod q."""
    w = 1
    for l in U:
        if l != i:
            w = w * l % Q * pow((l - i) % Q, -1, Q) % Q
    return w


# ---------------------------------------------------------------------------------------------
# §3.3.10 contest data (eqs. 63-70) and §3.6.6 its verifiable decryption (eqs. 96-106).
# ---------------------------------------------------------------------------------------------

# Eq. (66) Label and Context strings, §5.1.4 fixed-length form b(s, len(s)): raw UTF-8, no length prefix.
# The p.40 page image has underscores ("data_enc_keys", "contest_data"); the PDF text extraction shows spaces.
KDF_LABEL = "data_enc_keys".encode("utf-8")
KDF_CONTEXT_STR = "contest_data".encode("utf-8")
assert len(KDF_LABEL) == 13 and len(KDF_CONTEXT_STR) == 12


def b_c2(c, v):
    """b(C2, 64) for C2 = (c, v) (§5.5 tables, pp.76-77): b(c, 32) || b(v, 32). The spec writes C2 = (c, v)
    (eq. 69 text, p.41) and b(C2, 64) but does not spell out the split; this oracle takes c then v."""
    return b_q(c) + b_q(v)


def contest_data_nonce(h_i, ind_c, xi_b):
    """Eq. (64): xi = H_q(H_I; 0x25, ind_c(Lambda), xi_B), xi_B a 256-bit value b(xi_B, 32) (not reduced mod q).
    §5.5.3 table (p.76): B1 = 0x25 || b(ind_c, 4) || b(xi_B, 32), len(B1) = 37."""
    b1 = b"\x25" + b_small(ind_c) + b(xi_b, 32)
    assert len(b1) == 37
    return b1, H(h_i, b1)


def contest_data_secret_key(h_i, ind_c, alpha, beta):
    """Eq. (65): h = H(H_I; 0x26, ind_c(Lambda), alpha, beta); also (12.3) with (C0, beta) on decryption.
    §5.5.3 table (p.76): B1 = 0x26 || b(ind_c, 4) || b(alpha, 512) || b(beta, 512), len(B1) = 1029."""
    b1 = b"\x26" + b_small(ind_c) + b_p(alpha) + b_p(beta)
    assert len(b1) == 1029
    return b1, H(h_i, b1)


def contest_data_kdf_message(i, ind_c, b_lambda):
    """Eq. (66) HMAC message: b(i, 4) || Label || 0x00 || Context || b(b_Lambda * 256, 4),
    Label = b("data_enc_keys", 13), Context = b("contest_data", 12) || b(ind_c, 4); 1 <= i <= b_Lambda (Q6)."""
    assert 1 <= i <= b_lambda and 1 <= b_lambda < 2**24
    msg = b(i, 4) + KDF_LABEL + b"\x00" + KDF_CONTEXT_STR + b_small(ind_c) + b(b_lambda * 256, 4)
    assert len(msg) == 38
    return msg


def contest_data_kdf_keys(h, ind_c, b_lambda):
    """Eq. (66) / (104): k_i = HMAC(h, msg_i) for 1 <= i <= b_Lambda. Returns [(msg_i, k_i), ...]."""
    out = []
    for i in range(1, b_lambda + 1):
        msg = contest_data_kdf_message(i, ind_c, b_lambda)
        out.append((msg, H(h, msg)))
    return out


def xor_blocks(data, keys):
    """Eqs. (68) / (106): block-wise XOR of 32-byte blocks with k_1 .. k_b."""
    assert len(data) == 32 * len(keys)
    return b"".join(bytes(x ^ y for x, y in zip(data[32 * m:32 * m + 32], k)) for m, k in enumerate(keys))


def encode_contest_data_string(s, b_lambda):
    """NOT SPEC: the library helper fixed by user decision Q7. D_Lambda = b(len_utf8(s), 4) || UTF-8(s),
    zero-padded to exactly 32 * b_Lambda bytes; data that does not fit is rejected (ValueError)."""
    enc = s.encode("utf-8")
    d = b_small(len(enc)) + enc
    if len(d) > 32 * b_lambda:
        raise ValueError(f"contest data of {len(enc)} UTF-8 bytes does not fit in 32*{b_lambda} bytes")
    return d + b"\x00" * (32 * b_lambda - len(d))


def contest_data_challenge(h_i, ind_c, a, c0, c1):
    """Eq. (69): c = H_q(H_I; 0x27, ind_c(Lambda), a, C0, C1).
    §5.5.3 table (p.76): B1 = 0x27 || b(ind_c, 4) || b(a, 512) || b(C0, 512) || C1, len(B1) = 1029 + 32*b_Lambda."""
    assert len(c1) % 32 == 0
    parts = [(b"\x27", "0x27"), (b_small(ind_c), "ind_c"), (b_p(a), "a"), (b_p(c0), "C0"), (c1, "C1")]
    b1, layout = _layout(parts)
    assert len(b1) == 1029 + len(c1)
    return b1, H(h_i, b1), layout


def contest_hash_with_data(h_i, l, ciphertexts, c0, c1, c2):
    """Eq. (70) with contest data: chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_m, beta_m, C0, C1, C2).
    §5.5.3 table (p.76): B1 = 0x28 || b(l, 4) || b(alpha_1, 512) || ... || b(beta_m, 512) || b(C0, 512) || C1
    || b(C2, 64), len(B1) = 69 + (2m + 1)*512 + 32*b_Lambda."""
    parts = [(b"\x28", "0x28"), (b_small(l), "l")]
    for j, (alpha, beta) in enumerate(ciphertexts, start=1):
        parts += [(b_p(alpha), f"alpha_{j}"), (b_p(beta), f"beta_{j}")]
    parts += [(b_p(c0), "C0"), (c1, "C1"), (b_c2(*c2), "C2=(c,v)")]
    b1, layout = _layout(parts)
    m, b_lambda = len(ciphertexts), len(c1) // 32
    assert len(b1) == 69 + (2 * m + 1) * 512 + 32 * b_lambda
    return b1, H(h_i, b1), layout


def contest_data_decryption_commitment_hash(h_i, ind_c, i, c0, c1, c2, a_i, b_i, m_i, U):
    """Eq. (99): d_i = H(H_I; 0x32, ind_c(Lambda), i, C0, C1, C2, a_i, b_i, m_i, U), §3.6.6.
    B0 = H_I per the body and user decision Q5 (the §5.5.4 table's "B0 = H_E" is treated as an erratum).
    §5.5.4 table (p.77): B1 = 0x32 || b(ind_c, 4) || b(i, 4) || b(C0, 512) || C1 || b(C2, 64) || b(a_i, 512)
    || b(b_i, 512) || b(m_i, 512) || b(#U, 4) || b(j_1, 4) || ... || b(j_#U, 4), len(B1) = 2125 + 32*b_Lambda + 4*#U."""
    assert i in U
    parts = [(b"\x32", "0x32"), (b_small(ind_c), "ind_c"), (b_small(i), "i"), (b_p(c0), "C0"), (c1, "C1"),
             (b_c2(*c2), "C2=(c,v)"), (b_p(a_i), "a_i"), (b_p(b_i), "b_i"), (b_p(m_i), "m_i")]
    parts += b_index_set(U)
    b1, layout = _layout(parts)
    assert len(b1) == 2125 + len(c1) + 4 * len(U)
    return b1, H(h_i, b1), layout


def contest_data_decryption_challenge(h_i, ind_c, c0, c1, c2, a, b_, beta):
    """Eq. (101) / Verification 12.B: c = H_q(H_I; 0x33, ind_c(Lambda), C0, C1, C2, a, b, beta), §3.6.6.
    §5.5.4 table (p.77): B0 = H_I, B1 = 0x33 || b(ind_c, 4) || b(C0, 512) || C1 || b(C2, 64) || b(a, 512)
    || b(b, 512) || b(beta, 512), len(B1) = 2117 + 32*b_Lambda. No U."""
    parts = [(b"\x33", "0x33"), (b_small(ind_c), "ind_c"), (b_p(c0), "C0"), (c1, "C1"), (b_c2(*c2), "C2=(c,v)"),
             (b_p(a), "a"), (b_p(b_), "b"), (b_p(beta), "beta")]
    b1, layout = _layout(parts)
    assert len(b1) == 2117 + len(c1)
    return b1, H(h_i, b1), layout


# ---------------------------------------------------------------------------------------------
# §3.3.4 ballot nonce encryption (eqs. 34-38) and §3.6.7 its decryption (eqs. 107-111).
# ---------------------------------------------------------------------------------------------

# Eq. (36) Label and Context, §5.1.4 fixed-length form b(s, len(s)): raw UTF-8, no length prefix. The p.30 page
# image has underscores ("ballot_nonce", "ballot_nonce_encrypt"); the PDF text extraction shows spaces. Unlike eq.
# (66), the Context carries no index.
BN_KDF_LABEL = "ballot_nonce".encode("utf-8")
BN_KDF_CONTEXT = "ballot_nonce_encrypt".encode("utf-8")
assert len(BN_KDF_LABEL) == 12 and len(BN_KDF_CONTEXT) == 20


def ballot_nonce_secret_key(h_i, alpha_b, beta_b):
    """Eq. (35): h = H(H_I; 0x22, alpha_B, beta_B); on decryption (p.52) h = H(H_I; 0x22, C_xiB,0, beta_B).
    §5.5.3 table (p.75): B1 = 0x22 || b(alpha_B, 512) || b(beta_B, 512), len(B1) = 1025. No contest index."""
    b1 = b"\x22" + b_p(alpha_b) + b_p(beta_b)
    assert len(b1) == 1025
    return b1, H(h_i, b1)


def ballot_nonce_kdf_message():
    """Eq. (36) HMAC message: 0x01 || Label || 0x00 || Context || 0x0100, read literally from the p.30 image:
    a ONE-byte counter 0x01 and a TWO-byte output length 0x0100 = 256 bits, the same shape as eqs. (17)/(18)
    (0x01/0x02 ... 0x0200) and footnote 34 ("counter in the first byte", "final two bytes"). This differs from
    eq. (66), whose counter and length are 4 bytes each. Label = b("ballot_nonce", 12),
    Context = b("ballot_nonce_encrypt", 20). Length 1 + 12 + 1 + 20 + 2 = 36."""
    msg = b"\x01" + BN_KDF_LABEL + b"\x00" + BN_KDF_CONTEXT + b"\x01\x00"
    assert len(msg) == 36
    return msg


def ballot_nonce_kdf_key(h):
    """Eq. (36): k_1 = HMAC(h, msg). Returns (msg, k_1)."""
    msg = ballot_nonce_kdf_message()
    return msg, H(h, msg)


def ballot_nonce_challenge(h_i, a_b, c0, c1):
    """Eq. (38): c_B = H_q(H_I; 0x23, a_B, C_xiB,0, C_xiB,1).
    §5.5.3 table (p.75): B1 = 0x23 || b(a_B, 512) || b(C_xiB,0, 512) || C_xiB,1, len(B1) = 1057."""
    assert len(c1) == 32
    parts = [(b"\x23", "0x23"), (b_p(a_b), "a_B"), (b_p(c0), "C_xiB,0"), (c1, "C_xiB,1")]
    b1, layout = _layout(parts)
    assert len(b1) == 1057
    return b1, H(h_i, b1), layout


def xor32(x, y):
    assert len(x) == 32 and len(y) == 32
    return bytes(a ^ b_ for a, b_ in zip(x, y))


def small_dlog(base, target, bound=64):
    """Eq. (109) follow-up: the small sigma with base^sigma = target (brute force; sigma is a small selection)."""
    acc = 1
    for s in range(bound + 1):
        if acc == target:
            return s
        acc = acc * base % P
    raise ValueError("no small discrete log")


# ---------------------------------------------------------------------------------------------
# §3.3.7 / §3.3.8 range-proof and selection-limit challenges (eqs. 41, 50, 59, 62), used here for the
# recording tool's combined pre-encrypted selection vectors (§4.3). §5.5.3 table (p.75).
# ---------------------------------------------------------------------------------------------


def range_proof_challenge(h_i, ind_c, ind_o, alpha, beta, commits):
    """Eqs. (41)/(50) (R = 1) and (59): c = H_q(H_I; 0x24, ind_c(Lambda), ind_o(lambda), alpha, beta, a_0, b_0, ...,
    a_R, b_R). §5.5.3 table (p.75): len(B1) = 9 + (2R + 4)*512 (3081 for R = 1). Returns (B1, raw HMAC, layout)."""
    R = len(commits) - 1
    parts = [(b"\x24", "0x24"), (b_small(ind_c), "ind_c"), (b_small(ind_o), "ind_o"),
             (b_p(alpha), "alpha"), (b_p(beta), "beta")]
    for j, (a_j, b_j) in enumerate(commits):
        parts += [(b_p(a_j), f"a_{j}"), (b_p(b_j), f"b_{j}")]
    b1, layout = _layout(parts)
    assert len(b1) == 9 + (2 * R + 4) * 512
    return b1, H(h_i, b1), layout


def selection_limit_challenge(h_i, ind_c, alpha_bar, beta_bar, commits):
    """Eq. (62): c = H_q(H_I; 0x24, ind_c(Lambda), alpha-bar, beta-bar, a_0, b_0, ..., a_L, b_L). No ind_o.
    §5.5.3 table (p.75): len(B1) = 5 + (2L + 4)*512. Returns (B1, raw HMAC, layout)."""
    L = len(commits) - 1
    parts = [(b"\x24", "0x24"), (b_small(ind_c), "ind_c"), (b_p(alpha_bar), "alpha_bar"), (b_p(beta_bar), "beta_bar")]
    for j, (a_j, b_j) in enumerate(commits):
        parts += [(b_p(a_j), f"a_{j}"), (b_p(b_j), f"b_{j}")]
    b1, layout = _layout(parts)
    assert len(b1) == 5 + (2 * L + 4) * 512
    return b1, H(h_i, b1), layout


def make_range_proof(challenge, K_pub, alpha, beta, xi, ell, R, u, c_fake):
    """§3.3.7 general range proof (eqs. 57-61) that (alpha, beta) = (g^xi, K^(xi + ell)) encrypts ell in 0..R.
    u[j] (0 <= j <= R) and c_fake[j] (j != ell) are the prover's random values, fixed here. challenge(commits)
    returns (B1, raw, layout). The script then runs the verifier's recomputation (6.1-6.3 / 7.3-7.5) and 6.D/7.D.
    Returns dict with commits, c, c_j, v_j, B1, raw, layout."""
    assert 0 <= ell <= R
    assert pow(G, xi, P) == alpha and pow(K_pub, (xi + ell) % Q, P) == beta
    commits = []
    for j in range(R + 1):
        if j == ell:
            commits.append((pow(G, u[j], P), pow(K_pub, u[j], P)))                       # eq. (57)
        else:
            t_j = (u[j] + (ell - j) * c_fake[j]) % Q
            commits.append((pow(G, u[j], P), pow(K_pub, t_j, P)))                        # eq. (58)
    b1, raw, layout = challenge(commits)
    c = int.from_bytes(raw, "big") % Q
    cs = [c_fake[j] if j != ell else None for j in range(R + 1)]
    cs[ell] = (c - sum(cs[j] for j in range(R + 1) if j != ell)) % Q                    # eq. (60)
    vs = [(u[j] - cs[j] * xi) % Q for j in range(R + 1)]                                # eq. (61)
    # Verifier: a_j = g^v_j alpha^c_j, b_j = K^w_j beta^c_j, w_j = (v_j - j c_j) mod q; c recomputed; sum c_j = c.
    ver = [(pow(G, vs[j], P) * pow(alpha, cs[j], P) % P,
            pow(K_pub, (vs[j] - j * cs[j]) % Q, P) * pow(beta, cs[j], P) % P) for j in range(R + 1)]
    assert ver == commits, "6.1-6.2 / 7.3-7.4 must recompute the commitments"
    assert challenge(ver)[1] == raw, "6.3 / 7.5"
    assert sum(cs) % Q == c, "6.D / 7.D"
    assert all(0 <= x < Q for x in cs + vs), "6.B-6.C / 7.B-7.C"
    return {"commits": commits, "c": c, "cs": cs, "vs": vs, "b1": b1, "raw": raw, "layout": layout}


# ---------------------------------------------------------------------------------------------
# §4.1-4.2 pre-encrypted ballots: eqs. (112)-(115), (121); §5.5.5 table (p.78).
# ---------------------------------------------------------------------------------------------


def preencrypted_nonce(h_i, i, j, k, xi_b):
    """Eq. (121): xi_{i,j,k} = H_q(H_I; 0x45, i, j, k, xi_B), xi_B a 256-bit value b(xi_B, 32) (not reduced).
    §5.5.5 table (p.78): B1 = 0x45 || b(i, 4) || b(j, 4) || b(k, 4) || b(xi_B, 32), len(B1) = 45."""
    b1 = b"\x45" + b_small(i) + b_small(j) + b_small(k) + b(xi_b, 32)
    assert len(b1) == 45
    return b1, H(h_i, b1)


def preencrypted_selection_hash(h_i, cts):
    """Eqs. (113)/(114): psi = H(H_I; 0x40, alpha_1, beta_1, ..., alpha_m, beta_m).
    §5.5.5 table (p.78): len(B1) = 1 + 2m*512. Returns (B1, psi, layout)."""
    parts = [(b"\x40", "0x40")]
    for k, (a_k, b_k) in enumerate(cts, start=1):
        parts += [(b_p(a_k), f"alpha_{k}"), (b_p(b_k), f"beta_{k}")]
    b1, layout = _layout(parts)
    assert len(b1) == 1 + 2 * len(cts) * 512
    return b1, H(h_i, b1), layout


def sort_selection_hashes(psis):
    """§4.1.2: pi with psi_pi(1) < psi_pi(2) < ... as big-endian integers. For equal-length byte strings this is
    lexicographic byte order. Returns (sorted list, pi as 1-based positions in generation order)."""
    assert all(len(x) == 32 for x in psis)
    assert len(set(psis)) == len(psis), "selection hashes must be distinct for pi to be well defined"
    pi = sorted(range(1, len(psis) + 1), key=lambda r: int.from_bytes(psis[r - 1], "big"))
    srt = [psis[r - 1] for r in pi]
    assert srt == sorted(psis)
    assert all(int.from_bytes(srt[x], "big") < int.from_bytes(srt[x + 1], "big") for x in range(len(srt) - 1))
    return srt, pi


def preencrypted_contest_hash(h_i, ind_c, psis_in_order):
    """Eq. (115): chi_l = H(H_I; 0x41, ind_c(Lambda_l), psi_pi(1), ..., psi_pi(m+L)), selection hashes (including
    the L null hashes) in ascending big-endian order. §5.5.5 table (p.78): len(B1) = 5 + (m + L)*32.
    Returns (B1, chi, layout, pi)."""
    srt, pi = sort_selection_hashes(psis_in_order)
    parts = [(b"\x41", "0x41"), (b_small(ind_c), "ind_c")] + [(x, f"psi_pi({r})={pi[r - 1]}")
                                                            for r, x in enumerate(srt, start=1)]
    b1, layout = _layout(parts)
    assert len(b1) == 5 + len(psis_in_order) * 32
    return b1, H(h_i, b1), layout, pi


def short_code_hex(psi):
    """§4.1.5 example Omega (NOT the binding one; Omega is manifest-defined): last byte as two uppercase hex chars."""
    return f"{psi[-1]:02X}"


def short_code_dec3(psi):
    """§4.1.5 example Omega (NOT binding): last byte as a three-digit decimal number, 000-255."""
    return f"{psi[-1]:03d}"


def short_code_ordinal(psi, contest_psis):
    """§4.2.2 example Omega (NOT binding): 1-based position of psi in the contest's sorted selection hashes."""
    return str(sorted(contest_psis).index(psi) + 1)


# ---------------------------------------------------------------------------------------------
# Vector generation.
# ---------------------------------------------------------------------------------------------


def hx(x):
    return x.hex().upper()


def hp(x):
    return b_p(x).hex().upper()


def hq(x):
    return b(x, 32).hex().upper()


def vec(family, equation, name, b0_name, b0, b1, out, inputs, table_len, notes=None, hq_out=False):
    v = {
        "family": family,
        "equation": equation,
        "name": name,
        "b0_name": b0_name,
        "b0_hex": hx(b0),
        "inputs": inputs,
        "b1_len": len(b1),
        "b1_len_spec_table": table_len,
        "b1_hex": hx(b1),
        "expected_hex": hx(out),
    }
    if hq_out:
        v["expected_hmac_hex"] = hx(out)
        v["expected_hex"] = hq(int.from_bytes(out, "big") % Q)
        v["expected_reduced_mod_q"] = True
    if table_len is not None:
        assert len(b1) == table_len, (name, len(b1), table_len)
    if notes:
        v["notes"] = notes
    return v


def build():
    vectors = []

    # --- Eq. (4) parameter base hash -------------------------------------------------------
    hps = {}
    for n, k in ((3, 2), (5, 3), (1, 1)):
        b1, h_p = parameter_base_hash(n, k)
        hps[(n, k)] = h_p
        vectors.append(vec("parameter_base_hash", "(4) H_P = H(ver; 0x00, p, q, g, n, k)",
                           f"H_P n={n} k={k}", "ver", VER, b1, h_p,
                           {"ver_hex": hx(VER), "p": "standard", "q": "standard", "g": "standard",
                            "n": n, "k": k}, 1065))

    # --- Eq. (5) election base hash --------------------------------------------------------
    manifests = [
        ("kat manifest", b'{"election":"kat"}'),
        ("empty manifest", b""),
        ("utf8 manifest", '{"election":"Zürich – Wahl №1"}'.encode("utf-8")),
    ]
    hbs = {}
    for (n, k) in ((3, 2), (5, 3)):
        for mname, m in manifests:
            b1, h_b = election_base_hash(hps[(n, k)], m)
            hbs[(n, k, mname)] = h_b
            vectors.append(vec("election_base_hash", "(5) H_B = H(H_P; 0x01, manifest)",
                               f"H_B n={n} k={k} {mname}", "H_P", hps[(n, k)], b1, h_b,
                               {"H_P_hex": hx(hps[(n, k)]), "manifest_hex": hx(m),
                                "manifest_len": len(m)}, 5 + len(m)))

    # --- Eq. (16) guardian share KDF key ---------------------------------------------------
    for (n, k), i, l, zeta, xi in (((3, 2), 1, 2, 11, 101), ((3, 2), 3, 1, 13, 103),
                                    ((5, 3), 2, 5, 17, Q - 1)):
        h_p = hps[(n, k)]
        kappa = pow(G, zeta, P)
        alpha = pow(G, xi, P)
        beta = pow(kappa, xi, P)
        b1, key = guardian_share_key(h_p, i, l, kappa, alpha, beta)
        vectors.append(vec("guardian_share_kdf_key", "(16) k_{i,l} = H(H_P; 0x11, i, l, kappa_l, alpha_{i,l}, beta_{i,l})",
                           f"k_{{{i},{l}}} n={n} k={k}", "H_P", h_p, b1, key,
                           {"H_P_hex": hx(h_p), "i": i, "l": l,
                            "kappa_l_hex": hp(kappa), "alpha_hex": hp(alpha), "beta_hex": hp(beta),
                            "derivation": f"kappa_l = g^{zeta}, alpha = g^xi, beta = kappa_l^xi mod p, xi = {xi}"},
                           1545))

    # --- Eq. (30) extended base hash -------------------------------------------------------
    x, x_hat = 5, 7  # K = g^5, K-hat = g^7 for the main chain
    K, K_hat = pow(G, x, P), pow(G, x_hat, P)
    hes = {}
    for key in (("3", "2", "kat manifest"), ("5", "3", "kat manifest"), ("3", "2", "empty manifest")):
        n, k, mname = int(key[0]), int(key[1]), key[2]
        h_b = hbs[(n, k, mname)]
        b1, h_e = extended_base_hash(h_b, K, K_hat)
        hes[(n, k, mname)] = h_e
        vectors.append(vec("extended_base_hash", "(30) H_E = H(H_B; 0x14, K, K-hat)",
                           f"H_E n={n} k={k} {mname} K=g^5 Khat=g^7", "H_B", h_b, b1, h_e,
                           {"H_B_hex": hx(h_b), "K_hex": hp(K), "K_hat_hex": hp(K_hat),
                            "derivation": "K = g^5 mod p, K_hat = g^7 mod p"}, 1025))
    # A second key pair on the n=3,k=2 chain.
    K2, K2_hat = pow(G, 1234567, P), pow(G, 7654321, P)
    h_b = hbs[(3, 2, "kat manifest")]
    b1, h_e2 = extended_base_hash(h_b, K2, K2_hat)
    vectors.append(vec("extended_base_hash", "(30) H_E = H(H_B; 0x14, K, K-hat)",
                       "H_E n=3 k=2 kat manifest K=g^1234567 Khat=g^7654321", "H_B", h_b, b1, h_e2,
                       {"H_B_hex": hx(h_b), "K_hex": hp(K2), "K_hat_hex": hp(K2_hat),
                        "derivation": "K = g^1234567 mod p, K_hat = g^7654321 mod p"}, 1025))

    # Main chain: n=3, k=2, kat manifest, K=g^5, K-hat=g^7.
    H_E = hes[(3, 2, "kat manifest")]

    # --- Eq. (32) selection encryption identifier hash --------------------------------------
    id_bs = [
        ("id_B=1", 1),
        ("id_B=0x0102..20", int.from_bytes(bytes(range(1, 33)), "big")),
        ("id_B=q+5 (>= q, must not be reduced)", Q + 5),
        ("id_B=2^256-1", 2**256 - 1),
    ]
    his = {}
    for name, id_b in id_bs:
        b1, h_i = selection_encryption_identifier_hash(H_E, id_b)
        his[name] = h_i
        vectors.append(vec("selection_encryption_identifier_hash", "(32) H_I = H(H_E; 0x20, id_B)",
                           f"H_I {name}", "H_E", H_E, b1, h_i,
                           {"H_E_hex": hx(H_E), "id_B_hex": hq(id_b)}, 33))
    H_I = his["id_B=0x0102..20"]

    # --- Eq. (33) encryption nonces ---------------------------------------------------------
    xi_b_main = int.from_bytes(bytes(range(0xA0, 0xC0)), "big")
    nonce_cases = [
        (1, 1, xi_b_main), (1, 2, xi_b_main), (2, 1, xi_b_main), (2, 3, xi_b_main),
        (1, 1, Q + 7), (2147483647, 2147483647, 2**256 - 1),
    ]
    nonces = {}
    for i, j, xi_b in nonce_cases:
        b1, raw = encryption_nonce(H_I, i, j, xi_b)
        nonce = int.from_bytes(raw, "big") % Q
        if xi_b == xi_b_main:
            nonces[(i, j)] = nonce
        vectors.append(vec("encryption_nonce", "(33) xi_{i,j} = H_q(H_I; 0x21, i, j, xi_B)",
                           f"xi_{{{i},{j}}} xi_B={hq(xi_b)[:8]}..", "H_I", H_I, b1, raw,
                           {"H_I_hex": hx(H_I), "i": i, "j": j, "xi_B_hex": hq(xi_b)}, 41, hq_out=True))

    # --- Eq. (70) contest hash, options only ------------------------------------------------
    # Ciphertexts are genuine encryptions (eq. 31) under K with the nonces above:
    # contest 1: 2 options, votes (1, 0); contest 2: 3 options, votes (0, 0, 1).
    contests = {1: [1, 0], 2: [0, 0, 1]}
    nonces[(2, 2)] = int.from_bytes(encryption_nonce(H_I, 2, 2, xi_b_main)[1], "big") % Q
    chis = {}
    for l, votes in contests.items():
        cts = []
        for j, sigma in enumerate(votes, start=1):
            xi = nonces[(l, j)]
            cts.append((pow(G, xi, P), pow(K, sigma + xi, P)))
        b1, chi = contest_hash(H_I, l, cts)
        chis[l] = chi
        vectors.append(vec("contest_hash", "(70) chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_ml, beta_ml) [no contest data]",
                           f"chi_{l} {len(votes)} options", "H_I", H_I, b1, chi,
                           {"H_I_hex": hx(H_I), "l": l,
                            "ciphertexts": [{"alpha_hex": hp(a), "beta_hex": hp(bb)} for a, bb in cts],
                            "derivation": f"alpha_j = g^xi_{{l,j}}, beta_j = K^(sigma_j + xi_{{l,j}}) with K = g^5, "
                                          f"xi from eq. (33) vectors (xi_B = A0A1..BF), sigma = {votes}"},
                           None,
                           notes="Spec table prints len(B1) only for the with-contest-data form "
                                 "(69 + (2m+1)*512 + b*32); with C0, C1, C2 omitted, len(B1) = 5 + 2m*512."))
    # A single-option contest at a larger index, with arbitrary group elements.
    cts = [(pow(G, 3, P), pow(G, 9, P))]
    b1, chi7 = contest_hash(H_I, 7, cts)
    vectors.append(vec("contest_hash", "(70) chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_ml, beta_ml) [no contest data]",
                       "chi_7 1 option alpha=g^3 beta=g^9", "H_I", H_I, b1, chi7,
                       {"H_I_hex": hx(H_I), "l": 7,
                        "ciphertexts": [{"alpha_hex": hp(a), "beta_hex": hp(bb)} for a, bb in cts]},
                       None, notes="len(B1) = 5 + 2m*512 (no contest data)."))

    # --- Eq. (72) / (119) device information hashes -----------------------------------------
    devices = [
        "polling-place-42/device-7",
        "Wahllokal Zürich – Gerät №7 🗳",
        "",
    ]
    h_dis = {}
    for s in devices:
        enc = s.encode("utf-8")
        for sep, eqn, fam in ((0x2A, "(72) H_DI = H(H_E; 0x2A, S_device)", "device_info_hash"),
                              (0x43, "(119) H_DI = H(H_E; 0x43, S_device) [pre-encrypted ballots]",
                               "preencrypted_device_info_hash")):
            b1, h_di = device_info_hash(H_E, s, sep)
            h_dis[(s, sep)] = h_di
            vectors.append(vec(fam, eqn, f"H_DI 0x{sep:02X} {s!r}", "H_E", H_E, b1, h_di,
                               {"H_E_hex": hx(H_E), "S_device": s, "S_device_utf8_hex": hx(enc),
                                "S_device_utf8_len": len(enc), "S_device_char_len": len(s)},
                               5 + len(enc)))
    H_DI = h_dis[(devices[1], 0x2A)]
    H_DI_pre = h_dis[(devices[1], 0x43)]

    # --- Eq. (73)-(76) chaining fields, eq. (74) H_0, eq. (71) confirmation codes -------------
    chi_list = [chis[1], chis[2]]
    bc_none = b_c_no_chaining(H_DI)
    b1, hc_none = confirmation_code(H_I, chi_list, bc_none)
    vectors.append(vec("confirmation_code", "(71) H_C = H(H_I; 0x29, chi_1, ..., chi_mB, B_C), B_C per (73) no chaining",
                       "H_C no chaining (B_C = 0x00000000 || H_DI)", "H_I", H_I, b1, hc_none,
                       {"H_I_hex": hx(H_I), "contest_hashes_hex": [hx(c) for c in chi_list],
                        "H_DI_hex": hx(H_DI), "B_C_hex": hx(bc_none)}, 37 + 32 * len(chi_list)))

    bc0 = b_c0_simple(H_DI)
    b1, h0 = chain_init(H_E, bc0)
    vectors.append(vec("chain_init", "(74) H_0 = H(H_E; 0x29, B_C,0), B_C,0 = 0x00000001 || H_DI (75)",
                       "H_0 simple chaining", "H_E", H_E, b1, h0,
                       {"H_E_hex": hx(H_E), "H_DI_hex": hx(H_DI), "B_C0_hex": hx(bc0)}, 37))

    bc1 = b_c_simple(h0)
    b1, h1 = confirmation_code(H_I, chi_list, bc1)
    vectors.append(vec("confirmation_code", "(71) H_C with B_C,1 = 0x00000001 || H_0 (76), simple chaining j=1",
                       "H_1 simple chaining", "H_I", H_I, b1, h1,
                       {"H_I_hex": hx(H_I), "contest_hashes_hex": [hx(c) for c in chi_list],
                        "H_prev_hex": hx(h0), "B_C_hex": hx(bc1)}, 37 + 32 * len(chi_list)))

    # Ballot j=2 on the same device: a different ballot (different H_I) with one contest.
    H_I2 = his["id_B=q+5 (>= q, must not be reduced)"]
    b1c, chi_b2 = contest_hash(H_I2, 1, [(pow(G, 21, P), pow(G, 22, P))])
    bc2 = b_c_simple(h1)
    b1, h2 = confirmation_code(H_I2, [chi_b2], bc2)
    vectors.append(vec("confirmation_code", "(71) H_C with B_C,2 = 0x00000001 || H_1 (76), simple chaining j=2",
                       "H_2 simple chaining (one contest)", "H_I", H_I2, b1, h2,
                       {"H_I_hex": hx(H_I2), "contest_hashes_hex": [hx(chi_b2)],
                        "H_prev_hex": hx(h1), "B_C_hex": hx(bc2),
                        "contest_hash_derivation": "chi_1 = eq. (70) with l=1, alpha=g^21, beta=g^22 under this H_I"},
                       37 + 32))

    # Chain closing, eqs. (77)-(78), with H_l = H_2.
    b1_in, inner, bc_bar = chain_close_bc(H_E, h2, bc0)
    vectors.append(vec("chain_close_inner", "(78) inner H(H_E; 0x2B, H_l, B_C,0)",
                       "chain close inner hash, H_l = H_2", "H_E", H_E, b1_in, inner,
                       {"H_E_hex": hx(H_E), "H_l_hex": hx(h2), "B_C0_hex": hx(bc0),
                        "B_C_bar_hex": hx(bc_bar)}, 69))
    b1, h_bar = chain_close(H_E, bc_bar)
    vectors.append(vec("chain_close", "(77) H-bar = H(H_E; 0x29, B-bar_C), B-bar_C = 0x00000001 || H(H_E; 0x2B, H_l, B_C,0) (78)",
                       "chain close H-bar, H_l = H_2", "H_E", H_E, b1, h_bar,
                       {"H_E_hex": hx(H_E), "B_C_bar_hex": hx(bc_bar)}, 37,
                       notes="Table for (77) prints no B0; H_E per the equation."))

    # A no-chaining confirmation code with an empty device string.
    bc_empty = b_c_no_chaining(h_dis[("", 0x2A)])
    b1, hc_e = confirmation_code(H_I, [chis[1]], bc_empty)
    vectors.append(vec("confirmation_code", "(71) H_C, no chaining, S_device = \"\"",
                       "H_C no chaining one contest empty device", "H_I", H_I, b1, hc_e,
                       {"H_I_hex": hx(H_I), "contest_hashes_hex": [hx(chis[1])],
                        "H_DI_hex": hx(h_dis[("", 0x2A)]), "B_C_hex": hx(bc_empty)}, 37 + 32))

    # --- Eq. (27) guardian record comparison hash ---------------------------------------------
    # Appended after every earlier family so existing vectors keep their positions.
    # K_{i,j} = g^a_{i,j}, K-hat_{i,j} = g^ahat_{i,j}, kappa_i = g^zeta_i (eqs. 8, 9 and §3.2.2), with
    # a_{i,j} = 100i + 10j + 1, ahat_{i,j} = 100i + 10j + 5, zeta_i = 1000 + i, so every 512-byte slot is a
    # distinct group element and any reordering changes the digest. K_i = K_{i,0} (p.23), so the joint keys
    # are K = prod K_{i,0}, K-hat = prod K-hat_{i,0} (eqs. 25, 26). For n=3, k=2 the j=0 exponents are
    # overridden to (10, 20, -25) and (30, 40, -63) mod q, which sum to 5 and 7: K = g^5, K-hat = g^7 is the
    # key pair main_chain's H_E uses, so that H_G sits on the same election as the rest of the chain.
    hg_cases = [
        ((3, 2), "kat manifest", {1: 10, 2: 20, 3: Q - 25}, {1: 30, 2: 40, 3: Q - 63}),
        ((5, 3), "kat manifest", {}, {}),
        ((1, 1), "kat manifest", {}, {}),
    ]
    h_gs = {}
    guardian_coeffs = {}
    guardian_coeffs_hat = {}
    for (n, k), mname, a0, ahat0 in hg_cases:
        if (n, k, mname) in hbs:
            h_b = hbs[(n, k, mname)]
        else:  # H_B for (1, 1) is not an emitted vector; compute it here by eq. (5).
            h_b = election_base_hash(hps[(n, k)], dict(manifests)[mname])[1]
        a = [[a0.get(i, 100 * i + 1) if j == 0 else 100 * i + 10 * j + 1 for j in range(k)]
             for i in range(1, n + 1)]
        ahat = [[ahat0.get(i, 100 * i + 5) if j == 0 else 100 * i + 10 * j + 5 for j in range(k)]
                for i in range(1, n + 1)]
        zeta = [1000 + i for i in range(1, n + 1)]
        Ks = [[pow(G, e, P) for e in row] for row in a]
        K_hats = [[pow(G, e, P) for e in row] for row in ahat]
        kappas = [pow(G, z, P) for z in zeta]
        K_j = 1
        K_hat_j = 1
        for i in range(n):
            K_j = K_j * Ks[i][0] % P
            K_hat_j = K_hat_j * K_hats[i][0] % P
        assert K_j == pow(G, sum(r[0] for r in a) % Q, P)
        elems = [x for r in Ks for x in r] + [x for r in K_hats for x in r] + kappas
        if n > 1:  # with n = 1, K = K_{1,0} and K-hat = K-hat_{1,0} by eqs. (25), (26)
            elems = [K_j, K_hat_j] + elems
        assert len(set(elems)) == len(elems), "every slot must be a distinct group element"
        if (n, k) == (3, 2):
            assert (K_j, K_hat_j) == (K, K_hat), "n=3,k=2 H_G must use main_chain's K = g^5, K-hat = g^7"
        b1, h_g, layout = guardian_record_hash(h_b, K_j, K_hat_j, Ks, K_hats, kappas)
        h_gs[(n, k)] = h_g
        guardian_coeffs[(n, k)] = a
        guardian_coeffs_hat[(n, k)] = ahat
        v = vec("guardian_record_hash",
                "(27) H_G = H(H_B; 0x13, K, K-hat, K_1,0, ..., K_1,k-1, K_2,0, ..., K_n,k-1, "
                "K-hat_1,0, ..., K-hat_n,k-1, kappa_1, ..., kappa_n)",
                f"H_G n={n} k={k} {mname}", "H_B", h_b, b1, h_g,
                {"H_B_hex": hx(h_b), "n": n, "k": k, "manifest": mname,
                 "K_hex": hp(K_j), "K_hat_hex": hp(K_hat_j),
                 "K_i_j": [[{"i": i + 1, "j": j, "exponent_hex": hq(a[i][j]), "hex": hp(Ks[i][j])}
                            for j in range(k)] for i in range(n)],
                 "K_hat_i_j": [[{"i": i + 1, "j": j, "exponent_hex": hq(ahat[i][j]), "hex": hp(K_hats[i][j])}
                                for j in range(k)] for i in range(n)],
                 "kappa_i": [{"i": i + 1, "exponent_hex": hq(zeta[i]), "hex": hp(kappas[i])} for i in range(n)],
                 "derivation": "K_{i,j} = g^a_{i,j}, K_hat_{i,j} = g^ahat_{i,j}, kappa_i = g^zeta_i mod p; "
                               "a_{i,j} = 100i + 10j + 1, ahat_{i,j} = 100i + 10j + 5, zeta_i = 1000 + i"
                               + ("; j=0 overridden to a = (10, 20, q-25), ahat = (30, 40, q-63) so that "
                                  "K = g^5 and K_hat = g^7 (main_chain)" if (n, k) == (3, 2) else "")
                               + "; K = prod_i K_{i,0}, K_hat = prod_i K_hat_{i,0} mod p (eqs. 25, 26)"},
                1 + (2 + 2 * n * k + n) * 512,
                notes="B0 = H_B (p.27 image and §5.5.2 table). B1 is guardian-major: all K_{i,j} (i outer, "
                      "j inner), then all K_hat_{i,j} in the same order, then kappa_1..kappa_n. "
                      "len(B1) = 1 + (2 + 2nk + n) * 512 per the §5.5.2 table. b1_layout gives "
                      "[offset, length, label] for every field.")
        v["b1_layout"] = layout
        vectors.append(v)

    # --- Eqs. (88), (90) tally decryption proof hashes, §3.6.5 / Verification 10 --------------
    # Appended after every earlier family so existing vectors keep their positions.
    # Election: main_chain (n=3, k=2, H_E with K = g^5). The guardian polynomials are exactly the ones the
    # n=3,k=2 guardian_record_hash vector commits to: P_i(x) = a_{i,0} + a_{i,1} x, so s = sum a_{i,0} = 5 and
    # z_i = P(i) = sum_j P_j(i) mod q (eq. 83). Every proof below is a complete, valid proof: the script
    # checks Verification 10 (10.1-10.3, 10.A-10.C) and Note 3.7 (eqs. 94, 95) for each one.
    n_t, k_t = 3, 2
    a_t = guardian_coeffs[(n_t, k_t)]
    s_t = sum(row[0] for row in a_t) % Q
    assert s_t == 5 and pow(G, s_t, P) == K
    z = {i: sum(a_t[j - 1][m] * pow(i, m, Q) for j in range(1, n_t + 1) for m in range(k_t)) % Q
         for i in range(1, n_t + 1)}
    # Commitments to the coefficients, K_{j,m} = g^a_{j,m} (eq. 8); g^z_i = prod_j prod_m K_{j,m}^(i^m).
    K_jm = [[pow(G, e, P) for e in row] for row in a_t]

    # Three ballots encrypted under K = g^5 (eq. 31) with nonces from eq. (33) under each ballot's own H_I and
    # xi_B. Ballot 1 is main_chain's ballot (H_I, xi_B = A0A1..BF). Contest 1 has 2 options, contest 2 has 3.
    tally_ballots = [
        ("ballot 1 (main_chain)", int.from_bytes(bytes(range(1, 33)), "big"), xi_b_main,
         {1: [1, 0], 2: [0, 0, 1]}),
        ("ballot 2", int.from_bytes(bytes(range(0x41, 0x61)), "big"), int.from_bytes(bytes(range(0xC0, 0xE0)), "big"),
         {1: [1, 0], 2: [0, 0, 1]}),
        ("ballot 3", int.from_bytes(bytes(range(0x61, 0x81)), "big"), int.from_bytes(bytes(range(0xE0, 0x100)), "big"),
         {1: [0, 1], 2: [0, 0, 1]}),
    ]
    ballot_cts = []  # per ballot: {(l, j): (alpha, beta, sigma)}
    for bname, id_b, xi_b, votes in tally_ballots:
        h_i_b = selection_encryption_identifier_hash(H_E, id_b)[1]
        cts_b = {}
        for l, sel in votes.items():
            for j, sigma in enumerate(sel, start=1):
                xi = int.from_bytes(encryption_nonce(h_i_b, l, j, xi_b)[1], "big") % Q
                cts_b[(l, j)] = (pow(G, xi, P), pow(K, sigma + xi, P), sigma)
        ballot_cts.append(cts_b)
    # Ballot 1's ciphertexts are the ones the contest_hash vectors chi_1 / chi_2 hash.
    assert ballot_cts[0][(1, 1)][0] == pow(G, nonces[(1, 1)], P)

    # (ind_c, ind_o, U, u_i labels). u_i is the guardian's random commitment exponent (eq. 87), chosen here.
    tally_cases = [
        (1, 1, [1, 3], {1: 1001007, 3: 1003007}),
        (2, 3, [1, 2, 3], {1: 2001007, 2: Q - 2, 3: 2003007}),
        (2, 1, [2, 3], {2: 3002007, 3: 3003007}),
    ]
    tally_summary = []
    for ind_c, ind_o, U, u in tally_cases:
        A_agg, B_agg, t = 1, 1, 0
        for cts_b in ballot_cts:  # eq. (79) / Verification 9: unweighted aggregation
            alpha, beta, sigma = cts_b[(ind_c, ind_o)]
            A_agg, B_agg, t = A_agg * alpha % P, B_agg * beta % P, t + sigma
        w = {i: lagrange_coefficient(i, U) for i in U}
        assert sum(w[i] * z[i] for i in U) % Q == s_t, "Lagrange interpolation of z_i must give s"
        M_i = {i: pow(A_agg, z[i], P) for i in U}                       # eq. (84)
        a_i = {i: pow(G, u[i], P) for i in U}                           # eq. (87)
        b_i = {i: pow(A_agg, u[i], P) for i in U}
        M = 1
        for i in U:                                                     # eq. (86)
            M = M * pow(M_i[i], w[i], P) % P
        assert M == pow(A_agg, s_t, P)
        T = B_agg * pow(M, -1, P) % P                                   # eq. (82)
        assert T == pow(K, t, P)
        ballots_inputs = [{"ballot": tb[0], "alpha_hex": hp(cb[(ind_c, ind_o)][0]),
                           "beta_hex": hp(cb[(ind_c, ind_o)][1]), "sigma": cb[(ind_c, ind_o)][2]}
                          for tb, cb in zip(tally_ballots, ballot_cts)]
        u_label = ", ".join(f"u_{i}={'q-2' if u[i] == Q - 2 else u[i]}" for i in U)

        d = {}
        for i in U:
            b1, d_i, layout = tally_decryption_commitment_hash(H_E, ind_c, ind_o, i, A_agg, B_agg,
                                                                a_i[i], b_i[i], M_i[i], U)
            d[i] = d_i
            v = vec("tally_decryption_commitment_hash",
                    "(88) d_i = H(H_E; 0x30, ind_c(Lambda), ind_o(lambda), i, A, B, a_i, b_i, M_i, U)",
                    f"d_{i} ind_c={ind_c} ind_o={ind_o} U={U}", "H_E", H_E, b1, d_i,
                    {"H_E_hex": hx(H_E), "ind_c": ind_c, "ind_o": ind_o, "i": i, "U": U,
                     "A_hex": hp(A_agg), "B_hex": hp(B_agg), "a_i_hex": hp(a_i[i]), "b_i_hex": hp(b_i[i]),
                     "M_i_hex": hp(M_i[i]), "u_i_hex": hq(u[i]), "z_i_hex": hq(z[i]),
                     "U_encoding_hex": hx(b"".join(p for p, _ in b_index_set(U))),
                     "derivation": f"main_chain election (n=3, k=2, K=g^5, s=5); z_i = P(i) from the n=3,k=2 "
                                   f"guardian_record_hash polynomials; (A, B) = product of the three ballots' "
                                   f"(ind_c, ind_o) ciphertexts; M_i = A^z_i (84); a_i = g^u_i, b_i = A^u_i (87); "
                                   f"{u_label}"},
                    2577 + 4 * len(U),
                    notes="B0 = H_E (eq. 88 and §5.5.4 table, p.77). U is encoded b(#U, 4) || b(j_1, 4) || ... || "
                          "b(j_#U, 4); the spec does not state the order of the j's, this oracle uses ascending "
                          "order. len(B1) = 2577 + 4*#U per the table. b1_layout gives [offset, length, label].")
            v["b1_layout"] = layout
            vectors.append(v)

        a_acc, b_acc = 1, 1
        for i in U:                                                     # eq. (89)
            a_acc, b_acc = a_acc * a_i[i] % P, b_acc * b_i[i] % P
        b1, raw_c, layout = tally_decryption_challenge(H_E, ind_c, ind_o, A_agg, B_agg, a_acc, b_acc, M)
        c = int.from_bytes(raw_c, "big") % Q
        c_i = {i: c * w[i] % Q for i in U}                              # eq. (91)
        v_i = {i: (u[i] - c_i[i] * z[i]) % Q for i in U}                # eq. (92)
        v_resp = sum(v_i.values()) % Q                                  # eq. (93)
        # Verification 10 on the published (c, v, t): 10.1-10.3 recompute M, a, b; 10.A-10.C.
        M_ver = B_agg * pow(pow(K, t, P), -1, P) % P
        a_ver = pow(G, v_resp, P) * pow(K, c, P) % P
        b_ver = pow(A_agg, v_resp, P) * pow(M_ver, c, P) % P
        assert (M_ver, a_ver, b_ver) == (M, a_acc, b_acc), "Verification 10.1-10.3"
        assert 0 <= v_resp < Q, "Verification 10.A"
        assert tally_decryption_challenge(H_E, ind_c, ind_o, A_agg, B_agg, a_ver, b_ver, M_ver)[1] == raw_c
        assert pow(K, t, P) == T, "Verification 10.C"
        for i in U:  # Note 3.7, eqs. (94), (95)
            g_zi = 1
            for j in range(n_t):
                for m in range(k_t):
                    g_zi = g_zi * pow(K_jm[j][m], pow(i, m), P) % P
            assert g_zi == pow(G, z[i], P)
            assert pow(g_zi, c_i[i], P) * pow(G, v_i[i], P) % P == a_i[i], "Note 3.7 eq. (94)"
            assert pow(A_agg, v_i[i], P) * pow(M_i[i], c_i[i], P) % P == b_i[i], "Note 3.7 eq. (95)"
        v = vec("tally_decryption_challenge",
                "(90) c = H_q(H_E; 0x31, ind_c(Lambda), ind_o(lambda), A, B, a, b, M) [= Verification 10.B]",
                f"c ind_c={ind_c} ind_o={ind_o} U={U} t={t}", "H_E", H_E, b1, raw_c,
                {"H_E_hex": hx(H_E), "ind_c": ind_c, "ind_o": ind_o,
                 "A_hex": hp(A_agg), "B_hex": hp(B_agg), "a_hex": hp(a_acc), "b_hex": hp(b_acc), "M_hex": hp(M),
                 "ballots": ballots_inputs,
                 "proof": {
                     "U": U, "t": t, "T_hex": hp(T), "c_hex": hq(c), "v_hex": hq(v_resp),
                     "guardians": [{"i": i, "w_i_hex": hq(w[i]), "z_i_hex": hq(z[i]), "u_i_hex": hq(u[i]),
                                    "M_i_hex": hp(M_i[i]), "a_i_hex": hp(a_i[i]), "b_i_hex": hp(b_i[i]),
                                    "d_i_hex": hx(d[i]), "c_i_hex": hq(c_i[i]), "v_i_hex": hq(v_i[i])}
                                   for i in U]},
                 "derivation": "a = prod a_i, b = prod b_i (89); M = prod M_i^w_i (86) = A^5; w_i per (85); "
                               "T = B * M^-1 (82) = K^t; c_i = c*w_i (91); v_i = u_i - c_i*z_i (92); "
                               "v = sum v_i (93). The script asserts Verification 10.1-10.3 recompute exactly "
                               "M, a, b from (c, v, t), 10.A-10.C hold, and Note 3.7 (94)/(95) hold per guardian."},
                2569, hq_out=True,
                notes="B0 = H_E (eq. 90, Verification 10.B and §5.5.4 table, p.77); len(B1) = 2569. No public key "
                      "and no U in B1. Verification 10 uses no other hash. b1_layout gives [offset, length, label].")
        v["b1_layout"] = layout
        vectors.append(v)
        tally_summary.append({"ind_c": ind_c, "ind_o": ind_o, "U": U, "t": t, "c_hex": hq(c), "v_hex": hq(v_resp)})

    # --- §3.3.10 contest data, eqs. (64)-(69), and eq. (70) with contest data ------------------
    # Appended after every earlier family so existing vectors keep their positions.
    # Everything sits on main_chain's ballot: H_I (id_B = 0x0102..20), xi_B = A0A1..BF, K_hat = g^7.
    cd_derivation = "main_chain ballot: H_I = main_chain.H_I_hex, xi_B = main_chain.xi_B_hex, K_hat = g^7"
    # (a) eq. (64) contest data nonces.
    cd_nonce_cases = [(1, xi_b_main), (2, xi_b_main), (3, xi_b_main), (4, xi_b_main), (5, xi_b_main),
                      (1, Q + 7), (2147483647, 2**256 - 1)]
    cd_xi = {}
    for ind_c, xi_b in cd_nonce_cases:
        b1, raw = contest_data_nonce(H_I, ind_c, xi_b)
        if xi_b == xi_b_main:
            cd_xi[ind_c] = int.from_bytes(raw, "big") % Q
        vectors.append(vec("contest_data_nonce", "(64) xi = H_q(H_I; 0x25, ind_c(Lambda), xi_B)",
                           f"contest data xi ind_c={ind_c} xi_B={hq(xi_b)[:8]}..", "H_I", H_I, b1, raw,
                           {"H_I_hex": hx(H_I), "ind_c": ind_c, "xi_B_hex": hq(xi_b)}, 37, hq_out=True,
                           notes="§5.5.3 table (p.76): B1 = 0x25 || b(ind_c, 4) || b(xi_B, 32), len(B1) = 37. "
                                 "xi_B is encoded as a 256-bit value, never reduced mod q."))

    # Exactly-full non-ASCII string for b_Lambda = 3: 32*3 - 4 = 92 UTF-8 bytes.
    full3 = "write-in: Ægir Þórsson – №7 🗳 "
    full3 += "é" * ((92 - len(full3.encode("utf-8"))) // 2)
    full3 += "x" * (92 - len(full3.encode("utf-8")))
    assert len(full3.encode("utf-8")) == 92
    full1 = "Write-in: Grace Hopper (USN)"
    assert len(full1.encode("utf-8")) == 28
    # (label, ind_c, b_Lambda, contest data string, Schnorr nonce u of eq. 69).
    cd_cases = [
        ("empty string", 1, 1, "", 5001),
        ("ASCII", 2, 1, "Write-in: Ada Lovelace", 5002),
        ("non-ASCII multi-block", 3, 3, "Wahl Zürich – Gerät №7 🗳 / write-in: Ægir Þórsson", Q - 1),
        ("exactly full b=1 (28 UTF-8 bytes)", 4, 1, full1, 5004),
        ("exactly full b=3 non-ASCII (92 UTF-8 bytes)", 5, 3, full3, 5005),
    ]
    cd = {}  # ind_c -> dict of every value of the encryption
    for label, ind_c, b_lambda, s, u_s in cd_cases:
        D = encode_contest_data_string(s, b_lambda)
        xi = cd_xi[ind_c]
        alpha, beta = pow(G, xi, P), pow(K_hat, xi, P)
        b1_h, h = contest_data_secret_key(H_I, ind_c, alpha, beta)
        kdf = contest_data_kdf_keys(h, ind_c, b_lambda)
        keys = [k for _, k in kdf]
        C0, C1 = alpha, xor_blocks(D, keys)                              # eqs. (67), (68)
        a_s = pow(G, u_s, P)
        b1_c, raw_c, layout_c = contest_data_challenge(H_I, ind_c, a_s, C0, C1)
        c_s = int.from_bytes(raw_c, "big") % Q
        v_s = (u_s - c_s * xi) % Q
        # Schnorr check a guardian runs before decrypting (p.49-50) and the verifier's recomputation.
        assert pow(G, v_s, P) * pow(C0, c_s, P) % P == a_s
        assert contest_data_challenge(H_I, ind_c, pow(G, v_s, P) * pow(C0, c_s, P) % P, C0, C1)[1] == raw_c
        # Verification 13.4-13.A with the nonce: recompute (alpha, beta), h, k_l and confirm C1.
        assert xor_blocks(C1, keys) == D
        enc = s.encode("utf-8")
        assert int.from_bytes(D[:4], "big") == len(enc) and D[4:4 + len(enc)].decode("utf-8") == s
        cd[ind_c] = {"label": label, "b": b_lambda, "s": s, "D": D, "xi": xi, "alpha": alpha, "beta": beta,
                     "h": h, "b1_h": b1_h, "kdf": kdf, "C0": C0, "C1": C1, "u": u_s, "a": a_s, "c": c_s,
                     "v": v_s, "b1_c": b1_c, "raw_c": raw_c, "layout_c": layout_c}

    # (b) eq. (65) secret keys.
    for ind_c, e in cd.items():
        vectors.append(vec("contest_data_secret_key", "(65) h = H(H_I; 0x26, ind_c(Lambda), alpha, beta)",
                           f"contest data h ind_c={ind_c}", "H_I", H_I, e["b1_h"], e["h"],
                           {"H_I_hex": hx(H_I), "ind_c": ind_c, "xi_hex": hq(e["xi"]),
                            "alpha_hex": hp(e["alpha"]), "beta_hex": hp(e["beta"]),
                            "derivation": f"{cd_derivation}; xi = eq. (64) with this ind_c; alpha = g^xi, "
                                          f"beta = K_hat^xi mod p"},
                           1029, notes="§5.5.3 table (p.76): B1 = 0x26 || b(ind_c, 4) || b(alpha, 512) || "
                                       "b(beta, 512), len(B1) = 1029. Decryption (eq. 104 text, 12.3) hashes "
                                       "(C0, beta) with beta = prod m_i^w_i, the same value K_hat^xi."))

    # (c) eq. (66) KDF keys: b_Lambda = 1 and 3. The ind_c=2 secret key is also expanded with b_Lambda = 3 to
    # show that b(b_Lambda * 256, 4) changes every k_i, not just the number of keys.
    for ind_c, b_lambda in ((2, 1), (2, 3), (3, 3)):
        h = cd[ind_c]["h"]
        for i, (msg, k_i) in enumerate(contest_data_kdf_keys(h, ind_c, b_lambda), start=1):
            vectors.append(vec("contest_data_kdf_key",
                               "(66) k_i = HMAC(h, b(i, 4) || Label || 0x00 || Context || b(b_Lambda * 256, 4)), "
                               "Label = b(\"data_enc_keys\", 13), Context = b(\"contest_data\", 12) || b(ind_c, 4)",
                               f"k_{i} ind_c={ind_c} b_Lambda={b_lambda}", "h", h, msg, k_i,
                               {"h_hex": hx(h), "i": i, "ind_c": ind_c, "b_Lambda": b_lambda,
                                "Label_hex": hx(KDF_LABEL), "Context_hex": hx(KDF_CONTEXT_STR + b_small(ind_c)),
                                "key_bits_hex": hx(b(b_lambda * 256, 4)),
                                "derivation": f"h = eq. (65) vector for ind_c={ind_c}"},
                               None,
                               notes="Not in the §5.5 tables (an HMAC, not a domain-separated H call); the message "
                                     "is always 4 + 13 + 1 + 16 + 4 = 38 bytes. The key is h (32 bytes). The counter "
                                     "i is 1-based, 1 <= i <= b_Lambda (eqs. 66, 104, Verification 12.4; user "
                                     "decision Q6: Verification 13.7's 0 <= l < b_Lambda is an erratum). The final "
                                     "field is the key material length in BITS, b_Lambda * 256."))

    # (d) eqs. (67)-(69): full ciphertexts and the Schnorr proof C2 = (c, v) with a fixed nonce u.
    for ind_c, e in cd.items():
        v = vec("contest_data_encryption_challenge", "(69) c = H_q(H_I; 0x27, ind_c(Lambda), a, C0, C1), "
                "C0 = g^xi (67), C1 = D_1 xor k_1 || ... || D_b xor k_b (68), C2 = (c, v), v = (u - c*xi) mod q",
                f"contest data C ind_c={ind_c} b_Lambda={e['b']} {e['label']}", "H_I", H_I, e["b1_c"], e["raw_c"],
                {"H_I_hex": hx(H_I), "ind_c": ind_c, "b_Lambda": e["b"],
                 "contest_data_string": e["s"], "contest_data_string_utf8_hex": hx(e["s"].encode("utf-8")),
                 "contest_data_string_utf8_len": len(e["s"].encode("utf-8")),
                 "D_hex": hx(e["D"]),
                 "xi_hex": hq(e["xi"]), "alpha_hex": hp(e["alpha"]), "beta_hex": hp(e["beta"]), "h_hex": hx(e["h"]),
                 "k_hex": [hx(k) for _, k in e["kdf"]],
                 "u_hex": hq(e["u"]), "a_hex": hp(e["a"]),
                 "derivation": f"{cd_derivation}; xi = eq. (64) with this ind_c; h = eq. (65); k_i = eq. (66); "
                               f"D = the Q7 string helper (NOT SPEC): b(len_utf8, 4) || UTF-8 || 0x00 padding to "
                               f"32*b_Lambda bytes; a = g^u with u fixed (u = {'q-1' if e['u'] == Q - 1 else e['u']})"},
                1029 + 32 * e["b"], hq_out=True,
                notes="§5.5.3 table (p.76): B1 = 0x27 || b(ind_c, 4) || b(a, 512) || b(C0, 512) || C1, len(B1) = "
                      "1029 + 32*b_Lambda (1029 = 1 + 4 + 512 + 512). D_hex is the plaintext the spec operates on; "
                      "the string and its encoding are a library convention (user decision Q7), not spec. "
                      "ciphertext gives C0, C1 and C2 = (c, v); C2_hex is b(C2, 64) = b(c, 32) || b(v, 32). "
                      "The script checks g^v * C0^c = a and that C1 decrypts back to D.")
        v["ciphertext"] = {"C0_hex": hp(e["C0"]), "C1_hex": hx(e["C1"]), "c_hex": hq(e["c"]), "v_hex": hq(e["v"]),
                           "C2_hex": hx(b_c2(e["c"], e["v"]))}
        v["b1_layout"] = e["layout_c"]
        vectors.append(v)

    # (e) eq. (70) with contest data. Contests 1 and 2 are main_chain's option ciphertexts (the ones the
    # options-only contest_hash vectors chi_1, chi_2 hash), contest 3 is one option encrypting 1 with
    # xi_{3,1} from eq. (33). Each carries the contest data ciphertext with the same ind_c.
    nonces[(3, 1)] = int.from_bytes(encryption_nonce(H_I, 3, 1, xi_b_main)[1], "big") % Q
    cd_contests = {1: [1, 0], 2: [0, 0, 1], 3: [1]}
    chis_cd = {}
    for l, votes in cd_contests.items():
        e = cd[l]
        cts = [(pow(G, nonces[(l, j)], P), pow(K, sigma + nonces[(l, j)], P)) for j, sigma in enumerate(votes, start=1)]
        b1, chi, layout = contest_hash_with_data(H_I, l, cts, e["C0"], e["C1"], (e["c"], e["v"]))
        chis_cd[l] = chi
        m = len(cts)
        v = vec("contest_hash_with_contest_data",
                "(70) chi_l = H(H_I; 0x28, l, alpha_1, beta_1, ..., alpha_ml, beta_ml, C0, C1, C2)",
                f"chi_{l} {m} options + contest data b_Lambda={e['b']}", "H_I", H_I, b1, chi,
                {"H_I_hex": hx(H_I), "l": l,
                 "ciphertexts": [{"alpha_hex": hp(a_), "beta_hex": hp(bb)} for a_, bb in cts],
                 "C0_hex": hp(e["C0"]), "C1_hex": hx(e["C1"]), "C2_hex": hx(b_c2(e["c"], e["v"])),
                 "b_Lambda": e["b"],
                 "derivation": f"alpha_j = g^xi_{{l,j}}, beta_j = K^(sigma_j + xi_{{l,j}}), K = g^5, xi from eq. (33) "
                               f"(xi_B = A0A1..BF), sigma = {votes}; (C0, C1, C2) = the "
                               f"contest_data_encryption_challenge vector with ind_c = {l}"},
                69 + (2 * m + 1) * 512 + 32 * e["b"],
                notes="§5.5.3 table (p.76): B1 = 0x28 || b(l, 4) || b(alpha_1, 512) || ... || b(beta_m, 512) || "
                      "b(C0, 512) || C1 || b(C2, 64), len(B1) = 69 + (2m + 1)*512 + 32*b_Lambda. 69 = 1 (0x28) + 4 "
                      "(b(l, 4)) + 64 (b(C2, 64)); (2m + 1)*512 = m (alpha, beta) pairs plus C0; 32*b_Lambda = C1. "
                      "C2 = (c, v) is encoded b(c, 32) || b(v, 32). b1_layout gives [offset, length, label].")
        v["b1_layout"] = layout
        vectors.append(v)
    # The ballot's confirmation code over those three contest hashes, no chaining (eqs. 71, 73).
    chi_cd_list = [chis_cd[l] for l in sorted(chis_cd)]
    b1, hc_cd = confirmation_code(H_I, chi_cd_list, bc_none)
    vectors.append(vec("confirmation_code", "(71) H_C = H(H_I; 0x29, chi_1, ..., chi_mB, B_C), B_C per (73) no chaining",
                       "H_C no chaining, three contests with contest data", "H_I", H_I, b1, hc_cd,
                       {"H_I_hex": hx(H_I), "contest_hashes_hex": [hx(c_) for c_ in chi_cd_list],
                        "H_DI_hex": hx(H_DI), "B_C_hex": hx(bc_none),
                        "derivation": "contest hashes = the three contest_hash_with_contest_data vectors"},
                       37 + 32 * len(chi_cd_list)))

    # (f) §3.6.6 verifiable decryption of contest data, eqs. (96)-(106) / Verification 12. The guardian
    # ballot-data-key polynomials are the K_hat ones the n=3,k=2 guardian_record_hash vector commits to:
    # P_hat_i(x) = ahat_{i,0} + ahat_{i,1} x, s_hat = sum ahat_{i,0} = 7 (K_hat = g^7), z_hat_i = sum_j P_hat_j(i).
    ahat_t = guardian_coeffs_hat[(n_t, k_t)]
    s_hat = sum(row[0] for row in ahat_t) % Q
    assert s_hat == 7 and pow(G, s_hat, P) == K_hat
    z_hat = {i: sum(ahat_t[j - 1][m] * pow(i, m, Q) for j in range(1, n_t + 1) for m in range(k_t)) % Q
             for i in range(1, n_t + 1)}
    K_hat_jm = [[pow(G, e_, P) for e_ in row] for row in ahat_t]
    cd_dec_cases = [
        (2, [1, 3], {1: 6001007, 3: 6003007}),
        (3, [1, 2, 3], {1: 7001007, 2: Q - 2, 3: 7003007}),
        (5, [2, 3], {2: 8002007, 3: 8003007}),
    ]
    cd_dec_summary = []
    for ind_c, U, u in cd_dec_cases:
        e = cd[ind_c]
        C0, C1, C2 = e["C0"], e["C1"], (e["c"], e["v"])
        # Each guardian first checks the Schnorr proof C2 (p.49-50).
        assert contest_data_challenge(H_I, ind_c, pow(G, C2[1], P) * pow(C0, C2[0], P) % P, C0, C1)[1] == e["raw_c"]
        w = {i: lagrange_coefficient(i, U) for i in U}
        assert sum(w[i] * z_hat[i] for i in U) % Q == s_hat
        m_i = {i: pow(C0, z_hat[i], P) for i in U}                       # eq. (96)
        beta = 1
        for i in U:                                                      # eq. (97)
            beta = beta * pow(m_i[i], w[i], P) % P
        assert beta == e["beta"] == pow(K_hat, e["xi"], P), "beta must equal K_hat^xi of eq. (65)"
        a_i = {i: pow(G, u[i], P) for i in U}                            # eq. (98)
        b_i = {i: pow(C0, u[i], P) for i in U}
        u_label = ", ".join(f"u_{i}={'q-2' if u[i] == Q - 2 else u[i]}" for i in U)
        d = {}
        for i in U:
            b1, d_i, layout = contest_data_decryption_commitment_hash(H_I, ind_c, i, C0, C1, C2,
                                                                       a_i[i], b_i[i], m_i[i], U)
            d[i] = d_i
            v = vec("contest_data_decryption_commitment_hash",
                    "(99) d_i = H(H_I; 0x32, ind_c(Lambda), i, C0, C1, C2, a_i, b_i, m_i, U)",
                    f"contest data d_{i} ind_c={ind_c} b_Lambda={e['b']} U={U}", "H_I", H_I, b1, d_i,
                    {"H_I_hex": hx(H_I), "ind_c": ind_c, "i": i, "U": U, "b_Lambda": e["b"],
                     "C0_hex": hp(C0), "C1_hex": hx(C1), "C2_hex": hx(b_c2(*C2)),
                     "a_i_hex": hp(a_i[i]), "b_i_hex": hp(b_i[i]), "m_i_hex": hp(m_i[i]),
                     "u_i_hex": hq(u[i]), "z_hat_i_hex": hq(z_hat[i]),
                     "U_encoding_hex": hx(b"".join(p_ for p_, _ in b_index_set(U))),
                     "derivation": f"main_chain election (n=3, k=2, K_hat=g^7, s_hat=7); z_hat_i = P_hat(i) from the "
                                   f"n=3,k=2 guardian_record_hash K_hat polynomials; (C0, C1, C2) = the "
                                   f"contest_data_encryption_challenge vector with ind_c = {ind_c}; m_i = C0^z_hat_i "
                                   f"(96); a_i = g^u_i, b_i = C0^u_i (98); {u_label}"},
                    2125 + 32 * e["b"] + 4 * len(U),
                    notes="B0 = H_I per eq. (99) and user decision Q5; the §5.5.4 table (p.77) prints B0 = H_E, "
                          "treated as an erratum (its B1 layout and length are used as printed). U is encoded "
                          "b(#U, 4) || b(j_1, 4) || ... in ascending index (Q10). len(B1) = 2125 + 32*b_Lambda + "
                          "4*#U = 1 + 4 + 4 + 512 + 64 + 3*512 + 4 + 32*b_Lambda + 4*#U. C2 = b(c, 32) || b(v, 32).")
            v["b1_layout"] = layout
            vectors.append(v)
        a_acc, b_acc = 1, 1
        for i in U:                                                      # eq. (100)
            a_acc, b_acc = a_acc * a_i[i] % P, b_acc * b_i[i] % P
        b1, raw_c, layout = contest_data_decryption_challenge(H_I, ind_c, C0, C1, C2, a_acc, b_acc, beta)
        c = int.from_bytes(raw_c, "big") % Q
        c_i = {i: c * w[i] % Q for i in U}
        v_i = {i: (u[i] - c_i[i] * z_hat[i]) % Q for i in U}             # eq. (102)
        v_resp = sum(v_i.values()) % Q                                   # eq. (103)
        # Verification 12: 12.1, 12.2 recompute a, b; 12.A, 12.B; 12.3, 12.4 h and k_i; 12.C D.
        a_ver = pow(G, v_resp, P) * pow(K_hat, c, P) % P
        b_ver = pow(C0, v_resp, P) * pow(beta, c, P) % P
        assert (a_ver, b_ver) == (a_acc, b_acc), "Verification 12.1, 12.2"
        assert 0 <= v_resp < Q, "Verification 12.A"
        assert contest_data_decryption_challenge(H_I, ind_c, C0, C1, C2, a_ver, b_ver, beta)[1] == raw_c, "12.B"
        h_dec = contest_data_secret_key(H_I, ind_c, C0, beta)[1]
        assert h_dec == e["h"], "12.3 h = H(H_I; 0x26, ind_c, C0, beta) must equal eq. (65) h"
        keys_dec = [k for _, k in contest_data_kdf_keys(h_dec, ind_c, e["b"])]
        D_dec = xor_blocks(C1, keys_dec)                                 # eqs. (105), (106)
        assert D_dec == e["D"], "Verification 12.C"
        for i in U:  # per-guardian analogue of Note 3.7: g^z_hat_i from the K_hat_{j,m} commitments
            g_zi = 1
            for j in range(n_t):
                for m in range(k_t):
                    g_zi = g_zi * pow(K_hat_jm[j][m], pow(i, m), P) % P
            assert g_zi == pow(G, z_hat[i], P)
            assert pow(g_zi, c_i[i], P) * pow(G, v_i[i], P) % P == a_i[i]
            assert pow(C0, v_i[i], P) * pow(m_i[i], c_i[i], P) % P == b_i[i]
        v = vec("contest_data_decryption_challenge",
                "(101) c = H_q(H_I; 0x33, ind_c(Lambda), C0, C1, C2, a, b, beta) [= Verification 12.B]",
                f"contest data c ind_c={ind_c} b_Lambda={e['b']} U={U}", "H_I", H_I, b1, raw_c,
                {"H_I_hex": hx(H_I), "ind_c": ind_c, "b_Lambda": e["b"],
                 "C0_hex": hp(C0), "C1_hex": hx(C1), "C2_hex": hx(b_c2(*C2)),
                 "a_hex": hp(a_acc), "b_hex": hp(b_acc), "beta_hex": hp(beta),
                 "proof": {
                     "U": U, "c_hex": hq(c), "v_hex": hq(v_resp),
                     "guardians": [{"i": i, "w_i_hex": hq(w[i]), "z_hat_i_hex": hq(z_hat[i]), "u_i_hex": hq(u[i]),
                                    "m_i_hex": hp(m_i[i]), "a_i_hex": hp(a_i[i]), "b_i_hex": hp(b_i[i]),
                                    "d_i_hex": hx(d[i]), "c_i_hex": hq(c_i[i]), "v_i_hex": hq(v_i[i])}
                                   for i in U]},
                 "decryption": {"h_hex": hx(h_dec), "k_hex": [hx(k) for k in keys_dec],
                                "D_hex": hx(D_dec), "contest_data_string": e["s"]},
                 "derivation": "beta = prod m_i^w_i (97) = K_hat^xi; a = prod a_i, b = prod b_i (100); c_i = c*w_i; "
                               "v_i = u_i - c_i*z_hat_i (102); v = sum v_i (103). The script asserts Verification "
                               "12.1-12.2 recompute exactly a, b from (c, v), 12.A-12.C hold, h of (12.3) equals the "
                               "encryption-side h of (65), and the per-guardian relations a_i = (g^z_hat_i)^c_i g^v_i, "
                               "b_i = m_i^c_i C0^v_i."},
                2117 + 32 * e["b"], hq_out=True,
                notes="B0 = H_I (eq. 101, Verification 12.B and §5.5.4 table, p.77). len(B1) = 2117 + 32*b_Lambda "
                      "= 1 + 4 + 512 + 64 + 3*512 + 32*b_Lambda. No U in B1. b1_layout gives [offset, length, label].")
        v["b1_layout"] = layout
        vectors.append(v)
        cd_dec_summary.append({"ind_c": ind_c, "b_Lambda": e["b"], "U": U, "c_hex": hq(c), "v_hex": hq(v_resp),
                               "beta_hex": hp(beta)})

    # --- §3.3.4 ballot nonce encryption, eqs. (34)-(38); §3.6.7 its decryption, eqs. (107)-(108) -----------
    # Appended after every earlier family so existing vectors keep their positions.
    # The encryption nonce xi_hat_B and the Schnorr nonce u_B are uniform random in Z_q per the spec (no
    # derivation is defined), so they are fixed labelled inputs here. K_hat = g^7; the guardians' K_hat shares
    # z_hat_i are the n=3,k=2 ones the contest data decryption vectors use (s_hat = 7).
    sparse_id_b = int.from_bytes(bytes(range(0x81, 0xA1)), "big")
    sparse_xi_b = int.from_bytes(bytes(range(0x21, 0x41)), "big")
    H_I_sparse = selection_encryption_identifier_hash(H_E, sparse_id_b)[1]
    H_I_q5 = his["id_B=q+5 (>= q, must not be reduced)"]
    bn_ballots = {
        "main_chain ballot": (int.from_bytes(bytes(range(1, 33)), "big"), H_I, xi_b_main),
        "ballot id_B=q+5, xi_B=2^256-1 (>= q, not reduced)": (Q + 5, H_I_q5, 2**256 - 1),
        "sparse ballot (ind_c 2 and 5)": (sparse_id_b, H_I_sparse, sparse_xi_b),
    }
    # (ballot, xi_hat_B, u_B, U)
    bn_cases = [
        ("main_chain ballot", 9001, 9101, [1, 3]),
        ("main_chain ballot", Q - 1, 9102, [1, 2, 3]),
        ("ballot id_B=q+5, xi_B=2^256-1 (>= q, not reduced)", 9003, Q - 2, [2, 3]),
        ("sparse ballot (ind_c 2 and 5)", 9004, 9104, [1, 2]),
    ]

    def lbl(x):
        return "q-1" if x == Q - 1 else "q-2" if x == Q - 2 else str(x)

    bn_summary = []
    bn_decrypted = {}  # ballot name -> xi_B recovered by the guardians (first case of that ballot)
    for bname, xi_hat, u_b, U in bn_cases:
        id_b, h_i_b, xi_b = bn_ballots[bname]
        tag = f"{bname} xi_hat_B={lbl(xi_hat)}"
        alpha_b, beta_b = pow(G, xi_hat, P), pow(K_hat, xi_hat, P)            # eq. (34)
        b1_h, h_b = ballot_nonce_secret_key(h_i_b, alpha_b, beta_b)          # eq. (35)
        msg, k1 = ballot_nonce_kdf_key(h_b)                                  # eq. (36)
        C0, C1 = alpha_b, xor32(b(xi_b, 32), k1)                             # eq. (37)
        a_b = pow(G, u_b, P)
        b1_c, raw_c, layout_c = ballot_nonce_challenge(h_i_b, a_b, C0, C1)  # eq. (38)
        c_b = int.from_bytes(raw_c, "big") % Q
        v_b = (u_b - c_b * xi_hat) % Q
        assert pow(G, v_b, P) * pow(C0, c_b, P) % P == a_b
        common = {"H_I_hex": hx(h_i_b), "id_B_hex": hq(id_b), "K_hat": "g^7", "K_hat_hex": hp(K_hat),
                  "xi_hat_B_hex": hq(xi_hat), "alpha_B_hex": hp(alpha_b), "beta_B_hex": hp(beta_b)}
        vectors.append(vec("ballot_nonce_secret_key", "(35) h = H(H_I; 0x22, alpha_B, beta_B), "
                           "(alpha_B, beta_B) = (g^xi_hat_B, K_hat^xi_hat_B) (34)",
                           f"ballot nonce h {tag}", "H_I", h_i_b, b1_h, h_b,
                           dict(common, derivation=f"H_I = eq. (32) with id_B; alpha_B = g^xi_hat_B, beta_B = "
                                                   f"K_hat^xi_hat_B mod p, K_hat = g^7, xi_hat_B = {lbl(xi_hat)} (fixed; "
                                                   f"the spec draws it uniformly from Z_q)"),
                           1025, notes="§5.5.3 table (p.75): B1 = 0x22 || b(alpha_B, 512) || b(beta_B, 512), "
                                       "len(B1) = 1025, B0 = H_I; matches eq. (35). No contest or option index."))
        vectors.append(vec("ballot_nonce_kdf_key",
                           "(36) k_1 = HMAC(h, 0x01 || Label || 0x00 || Context || 0x0100), "
                           "Label = b(\"ballot_nonce\", 12), Context = b(\"ballot_nonce_encrypt\", 20)",
                           f"ballot nonce k_1 {tag}", "h", h_b, msg, k1,
                           {"h_hex": hx(h_b), "Label_hex": hx(BN_KDF_LABEL), "Context_hex": hx(BN_KDF_CONTEXT),
                            "derivation": "h = the ballot_nonce_secret_key vector with the same name suffix"},
                           None,
                           notes="Not in the §5.5 tables (an HMAC, not a domain-separated H call). The message is "
                                 "always the same 36 bytes: one-byte counter 0x01, Label (12), 0x00, Context (20), "
                                 "two-byte length 0x0100 = 256 bits, read literally from p.30 (the shape of eqs. "
                                 "17/18, footnote 34). Unlike eq. (66) the counter and length are NOT 4-byte fields "
                                 "and the Context has no index. Underscores per the p.30 page image."))
        v = vec("ballot_nonce_encryption_challenge",
                "(38) c_B = H_q(H_I; 0x23, a_B, C_xiB,0, C_xiB,1), C_xiB,0 = g^xi_hat_B, "
                "C_xiB,1 = b(xi_B, 32) xor k_1 (37), C_xiB,2 = (c_B, v_B), v_B = (u_B - c_B*xi_hat_B) mod q",
                f"ballot nonce C {tag}", "H_I", h_i_b, b1_c, raw_c,
                dict(common, xi_B_hex=hq(xi_b), xi_B_ge_q=xi_b >= Q, h_hex=hx(h_b), k_1_hex=hx(k1),
                     u_B_hex=hq(u_b), a_B_hex=hp(a_b),
                     derivation=f"h = eq. (35), k_1 = eq. (36); xi_B is a 256-bit value encoded b(xi_B, 32), never "
                                f"reduced mod q; a_B = g^u_B with u_B = {lbl(u_b)} fixed"),
                1057, hq_out=True,
                notes="§5.5.3 table (p.75): B1 = 0x23 || b(a_B, 512) || b(C_xiB,0, 512) || C_xiB,1, len(B1) = 1057 "
                      "= 1 + 512 + 512 + 32, B0 = H_I; matches eq. (38). ciphertext gives C0, C1 and C2 = (c_B, v_B); "
                      "C2_hex is b(c_B, 32) || b(v_B, 32) (Q20 order). C_xiB is hashed nowhere else (not in eqs. 70 "
                      "or 71), so the C2 byte order is serialization only. The script checks g^v_B * C0^c_B = a_B.")
        v["ciphertext"] = {"C0_hex": hp(C0), "C1_hex": hx(C1), "c_hex": hq(c_b), "v_hex": hq(v_b),
                           "C2_hex": hx(b_c2(c_b, v_b))}
        v["b1_layout"] = layout_c
        vectors.append(v)

        # §3.6.7 p.52: each guardian checks the Schnorr proof, then eqs. (107), (108), (35), (36), xi_B = C1 xor k1.
        a_chk = pow(G, v_b, P) * pow(C0, c_b, P) % P
        assert ballot_nonce_challenge(h_i_b, a_chk, C0, C1)[1] == raw_c, "p.52 Schnorr check of C_xiB,2"
        w = {i: lagrange_coefficient(i, U) for i in U}
        m_i = {i: pow(C0, z_hat[i], P) for i in U}                          # eq. (107)
        beta_dec = 1
        for i in U:                                                         # eq. (108)
            beta_dec = beta_dec * pow(m_i[i], w[i], P) % P
        assert beta_dec == beta_b == pow(K_hat, xi_hat, P), "beta_B = prod m_i^w_i must equal K_hat^xi_hat_B"
        b1_hd, h_dec = ballot_nonce_secret_key(h_i_b, C0, beta_dec)
        assert h_dec == h_b
        k1_dec = ballot_nonce_kdf_key(h_dec)[1]
        xi_b_dec = int.from_bytes(xor32(C1, k1_dec), "big")
        assert xi_b_dec == xi_b, "decrypted ballot nonce must equal xi_B"
        bn_decrypted.setdefault(bname, xi_b_dec)
        vectors.append(vec("ballot_nonce_decryption_secret_key",
                           "(107) m_i = C_xiB,0^z_hat_i, (108) beta_B = prod m_i^w_i, h = H(H_I; 0x22, C_xiB,0, beta_B) "
                           "(35), k_1 (36), xi_B = C_xiB,1 xor k_1",
                           f"ballot nonce decryption h {tag} U={U}", "H_I", h_i_b, b1_hd, h_dec,
                           {"H_I_hex": hx(h_i_b), "U": U, "C0_hex": hp(C0), "C1_hex": hx(C1),
                            "C2_hex": hx(b_c2(c_b, v_b)),
                            "guardians": [{"i": i, "w_i_hex": hq(w[i]), "z_hat_i_hex": hq(z_hat[i]),
                                           "m_i_hex": hp(m_i[i])} for i in U],
                            "beta_B_hex": hp(beta_dec),
                            "decryption": {"k_1_hex": hx(k1_dec), "xi_B_hex": hq(xi_b_dec)},
                            "derivation": "C_xiB = the ballot_nonce_encryption_challenge vector with the same name "
                                          "suffix; z_hat_i = the n=3,k=2 K_hat shares (contest_data.z_hat_i); "
                                          "w_i per eq. (85) over U"},
                           1025,
                           notes="Same B1 layout as eq. (35) (table p.75, len 1025) with (C_xiB,0, beta_B) in place of "
                                 "(alpha_B, beta_B); the script asserts beta_B = K_hat^xi_hat_B, that h equals the "
                                 "encryption-side h, and that C1 xor k_1 = b(xi_B, 32). The spec defines NO proof of "
                                 "correct decryption for the ballot nonce (no commitment or challenge hash, no §5.5.4 "
                                 "row) and says xi_B should not be published; the released xi_{i,j} / xi are checked "
                                 "by Verification 13 instead."))
        bn_summary.append({"ballot": bname, "H_I_hex": hx(h_i_b), "xi_B_hex": hq(xi_b), "xi_hat_B_hex": hq(xi_hat),
                           "U": U, "C0_hex": hp(C0), "C1_hex": hx(C1), "c_B_hex": hq(c_b), "v_B_hex": hq(v_b),
                           "beta_B_hex": hp(beta_dec)})

    # --- §3.6.7 decryption with released nonces (eqs. 109-111) and Verification 13 ---------------------------
    # From the guardians' decrypted xi_B, the released nonces are xi_{i,j} (eq. 33) and xi (eq. 64); the ballot
    # nonce itself is not released. Two challenged ballots:
    #   main_chain ballot: contests 1, 2, 3 with contest data cd[1..3] (the ballot whose chi and H_C are the
    #     earlier contest_hash_with_contest_data / confirmation_code vectors; Verification 13 must reproduce them).
    #   sparse ballot: contests ind_c = 2 (3 options, no contest data) and ind_c = 5 (1 option + contest data,
    #     b_Lambda = 2); positions 1, 2 differ from ind_c, so a consumer that hashes the position fails.
    ch_ballots = []
    # Recorded ciphertexts of the main ballot (what the device produced): the earlier vectors' values.
    main_rec = {"name": "main_chain ballot", "H_I": H_I, "contests": {}, "B_C": bc_none,
                "B_C_desc": "no chaining (73): 0x00000000 || main_chain.H_DI", "H_C_expected": hc_cd}
    for l, votes in cd_contests.items():
        e = cd[l]
        main_rec["contests"][l] = {
            "votes": votes,
            "cts": [(pow(G, nonces[(l, j)], P), pow(K, s_ + nonces[(l, j)], P)) for j, s_ in enumerate(votes, 1)],
            "data": {"C0": e["C0"], "C1": e["C1"], "C2": (e["c"], e["v"]), "D": e["D"], "b": e["b"], "s": e["s"]},
            "chi_expected": chis_cd[l]}
    ch_ballots.append(main_rec)

    # Sparse ballot: encrypt it here (eqs. 31, 33, 64-69) under its own H_I and xi_B.
    sp_rec = {"name": "sparse ballot (ind_c 2 and 5)", "H_I": H_I_sparse, "contests": {},
              "B_C": b_c_simple(h0), "B_C_desc": "simple chaining (76): 0x00000001 || H_0 (chain_init vector)"}
    for l, votes, data in ((2, [0, 1, 0], None), (5, [1], ("Write-in: Ada Lovelace (Countess)", 2, 5105))):
        cts = []
        for j, s_ in enumerate(votes, 1):
            xi_lj = int.from_bytes(encryption_nonce(H_I_sparse, l, j, sparse_xi_b)[1], "big") % Q
            cts.append((pow(G, xi_lj, P), pow(K, s_ + xi_lj, P)))
        rec = {"votes": votes, "cts": cts, "data": None}
        if data:
            s_, b_lambda, u_s = data
            D = encode_contest_data_string(s_, b_lambda)
            xi = int.from_bytes(contest_data_nonce(H_I_sparse, l, sparse_xi_b)[1], "big") % Q
            alpha, beta = pow(G, xi, P), pow(K_hat, xi, P)
            h = contest_data_secret_key(H_I_sparse, l, alpha, beta)[1]
            keys = [k_ for _, k_ in contest_data_kdf_keys(h, l, b_lambda)]
            C0_, C1_ = alpha, xor_blocks(D, keys)
            c_s = int.from_bytes(contest_data_challenge(H_I_sparse, l, pow(G, u_s, P), C0_, C1_)[1], "big") % Q
            v_s = (u_s - c_s * xi) % Q
            rec["data"] = {"C0": C0_, "C1": C1_, "C2": (c_s, v_s), "D": D, "b": b_lambda, "s": s_, "u": u_s}
        sp_rec["contests"][l] = rec
    ch_ballots.append(sp_rec)

    v13_summary = []
    for rec in ch_ballots:
        bname, h_i_b = rec["name"], rec["H_I"]
        xi_b_dec = bn_decrypted[bname]          # from the ballot nonce decryption above
        released, chis_v13 = [], []
        for l in sorted(rec["contests"]):        # manifest order = ascending ind_c
            con = rec["contests"][l]
            cts13, sel = [], []
            for j, s_ in enumerate(con["votes"], 1):
                xi_lj = int.from_bytes(encryption_nonce(h_i_b, l, j, xi_b_dec)[1], "big") % Q   # eq. (33)
                a13, b13 = pow(G, xi_lj, P), pow(K, s_ + xi_lj, P)                             # (13.1), (13.2)
                assert (a13, b13) == con["cts"][j - 1], "13.1/13.2 must reproduce the recorded encryption"
                K_sigma = b13 * pow(pow(K, xi_lj, P), -1, P) % P                                # eq. (109)
                assert small_dlog(K, K_sigma) == s_
                cts13.append((a13, b13))
                sel.append({"ind_o": j, "xi_hex": hq(xi_lj), "sigma": s_, "alpha_hex": hp(a13), "beta_hex": hp(b13),
                            "K_sigma_hex": hp(K_sigma)})
            rel = {"ind_c": l, "selections": sel}
            d = con["data"]
            if d is None:
                b1, layout = _layout([(b"\x28", "0x28"), (b_small(l), "ind_c")]
                                     + [x for j, (a_, bb) in enumerate(cts13, 1)
                                        for x in ((b_p(a_), f"alpha_{j}"), (b_p(bb), f"beta_{j}"))])
                chi = H(h_i_b, b1)
                assert (b1, chi) == contest_hash(h_i_b, l, cts13)
                tl = None
                cnote = ("No contest data on this contest: eq. (70) without C0, C1, C2, len(B1) = 5 + 2m*512 (the "
                         "table prints only the with-contest-data length).")
            else:
                xi = int.from_bytes(contest_data_nonce(h_i_b, l, xi_b_dec)[1], "big") % Q    # eq. (64)
                alpha, beta = pow(G, xi, P), pow(K_hat, xi, P)                               # (13.4), (13.5) / (110)
                assert alpha == d["C0"]
                b1_h, h = contest_data_secret_key(h_i_b, l, alpha, beta)                     # (13.6)
                kdf = contest_data_kdf_keys(h, l, d["b"])                                    # (13.7), 1-based (Q6)
                keys = [k_ for _, k_ in kdf]
                assert xor_blocks(d["D"], keys) == d["C1"], "13.A"
                assert xor_blocks(d["C1"], keys) == d["D"], "eq. (111)"
                rel["contest_data_xi_hex"] = hq(xi)
                vectors.append(vec("challenged_ballot_contest_data_secret_key",
                                   "Verification (13.4)-(13.6): alpha = g^xi, beta = K_hat^xi, "
                                   "h = H(H_I; 0x26, ind_c(Lambda), alpha, beta) [eq. (65)]",
                                   f"V13 h {bname} ind_c={l}", "H_I", h_i_b, b1_h, h,
                                   {"H_I_hex": hx(h_i_b), "ind_c": l, "released_xi_hex": hq(xi),
                                    "alpha_hex": hp(alpha), "beta_hex": hp(beta),
                                    "derivation": "xi = eq. (64) from the decrypted xi_B (released, not xi_B itself)"},
                                   1029, notes="§5.5.3 table (p.76) row for eq. (65): len(B1) = 1029."))
                for i, (msg, k_i) in enumerate(kdf, 1):
                    vectors.append(vec("challenged_ballot_contest_data_kdf_key",
                                       "Verification (13.7) k_l = HMAC(h, b(l, 4) || Label || 0x00 || Context || "
                                       "b(b_Lambda * 256, 4)) [eq. (66)], l 1-based (Q6)",
                                       f"V13 k_{i} {bname} ind_c={l} b_Lambda={d['b']}", "h", h, msg, k_i,
                                       {"h_hex": hx(h), "l": i, "ind_c": l, "b_Lambda": d["b"]}, None,
                                       notes="13.7 prints 0 <= l < b_Lambda; user decision Q6 makes the counter "
                                             "1-based (1 <= l <= b_Lambda) as in eqs. (66), (104) and 12.4. 38-byte "
                                             "message; not a §5.5 table entry."))
                b1, chi, layout = contest_hash_with_data(h_i_b, l, cts13, d["C0"], d["C1"], d["C2"])
                tl = 69 + (2 * len(cts13) + 1) * 512 + 32 * d["b"]
                cnote = ("§5.5.3 table (p.76) eq. (70): len(B1) = 69 + (2m + 1)*512 + 32*b_Lambda; C2 = b(c, 32) || "
                         "b(v, 32) (Q20).")
                rel["contest_data"] = {"C0_hex": hp(d["C0"]), "C1_hex": hx(d["C1"]), "C2_hex": hx(b_c2(*d["C2"])),
                                       "b_Lambda": d["b"], "D_hex": hx(d["D"]), "contest_data_string": d["s"],
                                       "k_hex": [hx(k_) for k_ in keys]}
            if "chi_expected" in con:
                assert chi == con["chi_expected"], "13.3 must reproduce the ballot's contest hash"
            chis_v13.append(chi)
            vv = vec("challenged_ballot_contest_hash",
                     "Verification (13.3) chi_i = H(H_I; 0x28, ind_c(Lambda_i), alpha_i,1, beta_i,1, ..., C0, C1, C2) "
                     "[eq. (70)], (alpha, beta) recomputed by (13.1), (13.2)",
                     f"V13 chi {bname} ind_c={l}", "H_I", h_i_b, b1, chi,
                     {"H_I_hex": hx(h_i_b), "ind_c": l, "position_on_ballot": len(chis_v13),
                      "released": rel,
                      "derivation": "xi_{i,j} = eq. (33) and xi = eq. (64) from the guardians' decrypted xi_B "
                                    "(ballot_nonce_decryption_secret_key); alpha = g^xi_{i,j}, beta = K^(sigma + xi_{i,j}), "
                                    "K = g^5"},
                     tl, notes=cnote + " The field after 0x28 is ind_c(Lambda_i) (13.3), i.e. eq. (70)'s l, not the "
                                       "contest's position on the ballot.")
            vv["b1_layout"] = layout
            vectors.append(vv)
        b1, hc = confirmation_code(h_i_b, chis_v13, rec["B_C"])                               # (13.B)
        if "H_C_expected" in rec:
            assert hc == rec["H_C_expected"], "13.B must reproduce the ballot's confirmation code"
        vectors.append(vec("challenged_ballot_confirmation_code",
                           "Verification (13.B) H_C = H(H_I; 0x29, chi_1, ..., chi_mB, B_C) [eq. (71)]",
                           f"V13 H_C {bname}", "H_I", h_i_b, b1, hc,
                           {"H_I_hex": hx(h_i_b), "contest_hashes_hex": [hx(c_) for c_ in chis_v13],
                            "B_C_hex": hx(rec["B_C"]), "B_C": rec["B_C_desc"],
                            "derivation": "contest hashes = this ballot's challenged_ballot_contest_hash vectors, in "
                                          "manifest (ascending ind_c) order"},
                           37 + 32 * len(chis_v13)))
        v13_summary.append({"ballot": bname, "H_I_hex": hx(h_i_b), "H_C_hex": hx(hc),
                            "contests": sorted(rec["contests"]),
                            "reproduces_earlier_vectors": "H_C_expected" in rec})

    # --- Pre-encrypted ballot chaining, §4.1.4 eqs. (116)-(120), §5.5.5 table, Verification 16.E-16.H ----
    # Appended after all earlier families. Same election (main_chain H_E) and device string as the regular
    # chain above, but H_DI is the pre-encrypted one (eq. 119, 0x43). The contest hashes chi fed to eq. (116)
    # are opaque labelled 32-byte stand-ins: eqs. (113)-(115) are out of scope here, and eq. (116) treats chi as
    # input bytes.
    pre_note_chi = ("chi values are opaque labelled 32-byte stand-ins (eqs. 113-115 are not covered); eq. (116) "
                    "hashes them as raw bytes in sequential contest order.")
    pre_chis_1 = [bytes(range(0x50, 0x70)), bytes(range(0x70, 0x90))]
    pre_chis_2 = [bytes(range(0x90, 0xB0))]
    pre_chi_desc_1 = ["bytes 0x50..0x6F", "bytes 0x70..0x8F"]
    pre_chi_desc_2 = ["bytes 0x90..0xAF"]

    # (16.E) no chaining: B_C = 0x00000000 || H_DI, with the 0x43 H_DI.
    pre_bc_none = b_c_no_chaining(H_DI_pre)
    b1, pre_hc_none = confirmation_code(H_I, pre_chis_1, pre_bc_none, sep=0x42)
    vectors.append(vec("preencrypted_confirmation_code",
                       "(116) H_C = H(H_I; 0x42, chi_1, ..., chi_mB, B_C), B_C = 0x00000000 || H_DI (16.E), "
                       "H_DI per (119)",
                       "pre-encrypted H_C no chaining", "H_I", H_I, b1, pre_hc_none,
                       {"H_I_hex": hx(H_I), "contest_hashes_hex": [hx(c_) for c_ in pre_chis_1],
                        "contest_hashes": pre_chi_desc_1, "H_DI_hex": hx(H_DI_pre),
                        "H_DI": "main_chain.H_DI_preencrypted_hex (eq. 119, 0x43)", "B_C_hex": hx(pre_bc_none)},
                       37 + 32 * len(pre_chis_1), notes=pre_note_chi))

    # (117) chain initialization, B_C,0 = 0x00000001 || H_DI (16.G), H_DI per (119).
    pre_bc0 = b_c0_simple(H_DI_pre)
    b1, pre_h0 = chain_init(H_E, pre_bc0, sep=0x42)
    assert pre_h0 != h0
    vectors.append(vec("preencrypted_chain_init",
                       "(117) H_0 = H(H_E; 0x42, B_C,0), B_C,0 = 0x00000001 || H_DI, H_DI per (119) (16.G)",
                       "pre-encrypted H_0 simple chaining", "H_E", H_E, b1, pre_h0,
                       {"H_E_hex": hx(H_E), "H_DI_hex": hx(H_DI_pre),
                        "H_DI": "main_chain.H_DI_preencrypted_hex (eq. 119, 0x43)", "B_C0_hex": hx(pre_bc0)}, 37,
                       notes="Uses the 0x43 device hash of eq. (119), not the 0x2A one of eq. (72) (§4.1.4)."))

    # (116) with B_C,j = 0x00000001 || H_{j-1} (16.F), j = 1 and j = 2. Ballot 2 is a different ballot
    # (different H_I), as in the regular chain.
    pre_bc1 = b_c_simple(pre_h0)
    b1, pre_h1 = confirmation_code(H_I, pre_chis_1, pre_bc1, sep=0x42)
    vectors.append(vec("preencrypted_confirmation_code",
                       "(116) H_C with B_C,1 = 0x00000001 || H_0 (16.F), simple chaining j=1",
                       "pre-encrypted H_1 simple chaining", "H_I", H_I, b1, pre_h1,
                       {"H_I_hex": hx(H_I), "contest_hashes_hex": [hx(c_) for c_ in pre_chis_1],
                        "contest_hashes": pre_chi_desc_1, "H_prev_hex": hx(pre_h0), "B_C_hex": hx(pre_bc1)},
                       37 + 32 * len(pre_chis_1), notes=pre_note_chi))
    pre_bc2 = b_c_simple(pre_h1)
    b1, pre_h2 = confirmation_code(H_I2, pre_chis_2, pre_bc2, sep=0x42)
    vectors.append(vec("preencrypted_confirmation_code",
                       "(116) H_C with B_C,2 = 0x00000001 || H_1 (16.F), simple chaining j=2",
                       "pre-encrypted H_2 simple chaining (one contest)", "H_I", H_I2, b1, pre_h2,
                       {"H_I_hex": hx(H_I2), "H_I": "H_I of id_B = q + 5 (selection_encryption_identifier_hash)",
                        "contest_hashes_hex": [hx(c_) for c_ in pre_chis_2], "contest_hashes": pre_chi_desc_2,
                        "H_prev_hex": hx(pre_h1), "B_C_hex": hx(pre_bc2)},
                       37 + 32 * len(pre_chis_2), notes=pre_note_chi))

    # (120) and (118) chain close with H_l = H_2, body form per Q4.
    b1_in, pre_inner, pre_bc_bar = chain_close_bc(H_E, pre_h2, pre_bc0, sep=0x44)
    lock_b1 = b"\x44" + b"\x4C\x4F\x43\x4B" + pre_h2 + pre_bc0  # the table's printed layout, NOT used
    assert len(lock_b1) == 73
    lock_inner = H(H_E, lock_b1)
    assert lock_inner != pre_inner
    q4_note = ("User decision Q4: body form B1 = 0x44 || H_l || B_C,0 (eq. 120, §4.1.4 p.59, Verification 16.H). "
               "The §5.5.5 table (p.78) prints B1 = 0x44 || 0x4C4F434B ('LOCK') || H_l || B_C,0, which is an erratum: "
               "that layout is 1 + 4 + 32 + 36 = 73 bytes, but the same table row prints len(B1) = 69, which only "
               "the body form satisfies. lock_form_erratum records the LOCK-layout hash for diagnosis; it is NOT "
               "the expected value.")
    vv = vec("preencrypted_chain_close_inner", "(120) inner H(H_E; 0x44, H_l, B_C,0) [body form, Q4]",
             "pre-encrypted chain close inner hash, H_l = H_2", "H_E", H_E, b1_in, pre_inner,
             {"H_E_hex": hx(H_E), "H_l_hex": hx(pre_h2), "B_C0_hex": hx(pre_bc0), "B_C_bar_hex": hx(pre_bc_bar)},
             69, notes=q4_note)
    vv["lock_form_erratum"] = {"b1_hex": hx(lock_b1), "b1_len": len(lock_b1), "hash_hex": hx(lock_inner),
                               "expected": False}
    vectors.append(vv)
    b1, pre_h_bar = chain_close(H_E, pre_bc_bar, sep=0x42)
    vectors.append(vec("preencrypted_chain_close",
                       "(118) H-bar = H(H_E; 0x42, B-bar_C), B-bar_C = 0x00000001 || H(H_E; 0x44, H_l, B_C,0) (120)",
                       "pre-encrypted chain close H-bar, H_l = H_2", "H_E", H_E, b1, pre_h_bar,
                       {"H_E_hex": hx(H_E), "B_C_bar_hex": hx(pre_bc_bar), "H_l_hex": hx(pre_h2),
                        "B_C0_hex": hx(pre_bc0)}, 37,
                       notes="Table for (118) prints no B0; H_E per the equation. B-bar_C uses the body form of "
                             "(120) (Q4)."))
    pre_summary = {
        "election": "main_chain (H_E = main_chain.H_E_hex)",
        "S_device": devices[1], "H_DI_hex": hx(H_DI_pre), "H_DI": "eq. (119), separator 0x43",
        "separators": {"chain_init_117": "0x42", "confirmation_code_116": "0x42", "chain_close_118": "0x42",
                       "device_info_119": "0x43", "chain_close_inner_120": "0x44"},
        "H_0_hex": hx(pre_h0), "H_1_hex": hx(pre_h1), "H_2_hex": hx(pre_h2),
        "B_C_bar_hex": hx(pre_bc_bar), "H_bar_hex": hx(pre_h_bar),
        "q4_erratum": "§5.5.5 table row for (120) prints 0x44 || 0x4C4F434B || H_l || B_C,0 with len(B1) = 69; the "
                      "body form 0x44 || H_l || B_C,0 is used (user decision Q4), consistent with the printed length.",
        "contest_hashes": "opaque labelled stand-ins; eqs. (113)-(115) are not covered",
    }

    # --- Pre-encrypted ballots, §4.1-4.3, eqs. (112)-(116), (121); Verifications 15-18 ----------------------
    # Appended after all earlier families. Election: main_chain (H_E, K = g^5). Two pre-encrypted ballots, each
    # with its own labelled id_B (-> H_I, eq. 32) and ballot nonce xi_B:
    #   P1 (cast): contests (ind_c, m, L) = (1, 3, 1), (3, 4, 2), (4, 2, 2) at positions 1, 2, 3, so positions 2 and 3
    #     differ from ind_c. The voter selects option 2 / options 1 and 4 / option 2 only (an undervote, padded
    #     with one null vector, see PE_AMBIGUITIES). The recording tool (§4.3) combines the selected vectors and
    #     proves the result with eqs. (59)/(62) (Verification 15, 6, 7).
    #   P2 (uncast): contests (2, 2, 1), (5, 3, 2) at positions 1, 2; xi_B = q + 11 (>= q, never reduced). Its
    #     nonces xi_{i,j,k} are released and Verification 18 recomputes everything from them.
    # Option indices are contiguous 1..m and equal the positions, so the j/k of eq. (121) are unambiguous; null
    # vector l of a contest uses j = m + l (§4.2.1 "the sequence of indices should be extended accordingly").
    PE_AMBIGUITIES = [
        "16.B writes chi_l = H(H_I; 0x41, l, ...) with l the 'context index'/sequence number of the contest on the "
        "ballot, while eq. (115) and the §5.5.5 table write b(ind_c(Lambda_l), 4). The oracle uses ind_c (eq. 115; "
        "precedent: S7 decision on 13.3) and records the position form as a diagnostic where the two differ.",
        "Verification 18 as lettered loops 1 <= j <= m_i and (18.4) hashes psi_{i,pi(1)}..psi_{i,pi(m_i)}: only m_i "
        "selection hashes, no null hashes, while (18.2)/(18.3) make each vector m_i long. Eqs. (114)/(115), the "
        "§5.5.5 table (len 5 + (m + L)*32) and 16.B all include the L null hashes. The oracle follows (115): vectors "
        "of length m, m + L selection hashes per contest.",
        "Eq. (121): i is the contest index and j the selection index (§4.2.1, 'following the manifest'), but §4.1 "
        "defines Psi_{i,m} by position i ('not necessarily identical to its option index') and (18.1) indexes "
        "xi_{i,j,k} by the contest's position i on the ballot (Lambda_i, 1 <= i <= m_B). The oracle uses the contest "
        "index ind_c for i (P1 and P2 have contests whose position differs from ind_c) and uses contiguous option "
        "indices 1..m so that option index = position for j and k.",
        "Null vectors: the oracle numbers null vector l (1 <= l <= L) as j = m + l in eq. (121) (p.61: if null labels "
        "are not in the manifest 'the sequence of indices should be extended accordingly'); k still runs 1..m, so "
        "every component of a null vector encrypts zero.",
        "Undervote combination (§4.3, §4.1.5): the spec does not say whether the recording tool multiplies null "
        "vectors into the combined vector when the voter makes fewer than L selections. The oracle always combines "
        "exactly L vectors, padding with null vectors j = m + 1, ..., because §4.1.5/§4.2 say the null short codes "
        "let the record not reveal undervotes. P1's ind_c = 4 contest (L = 2, one selection) shows it.",
        "§4.4 says the ballot nonce xi_B of each uncast ballot is published, while §4.3 and Verification 18 release "
        "the encryption nonces xi_{i,j,k}. The oracle publishes both for P2 (the nonces are eq. (121) of xi_B).",
        "The challenges of the combined vector's proofs have no pre-encrypted row in §5.5.5: §4.3 says 'as in "
        "standard ElectionGuard section 3.3.7', so they are eqs. (41)/(50)/(59) (per option, R = option selection "
        "limit = 1) and (62) (contest limit L) verbatim, keyed with the pre-encrypted ballot's H_I and using the "
        "combined ciphertexts and the summed nonces.",
        "Omega (short codes, §4.1.5) is manifest-defined. The short codes here use the spec's own examples (last "
        "byte as two hex characters or a three-digit number, and the sorted ordinal of §4.2.2); none is binding.",
    ]
    pe_s_device2 = "kat pre-encrypted ballot printer 2"
    b1, pe_h_di2 = device_info_hash(H_E, pe_s_device2, sep=0x43)
    enc2 = pe_s_device2.encode("utf-8")
    vectors.append(vec("preencrypted_device_info_hash", "(119) H_DI = H(H_E; 0x43, S_device) [pre-encrypted ballots]",
                       f"H_DI 0x43 {pe_s_device2!r}", "H_E", H_E, b1, pe_h_di2,
                       {"H_E_hex": hx(H_E), "S_device": pe_s_device2, "S_device_utf8_hex": hx(enc2),
                        "S_device_utf8_len": len(enc2), "S_device_char_len": len(pe_s_device2)},
                       5 + len(enc2), notes="Device of pre-encrypted ballot P2 (preencrypted_ballots)."))
    pe_bc0_2 = b_c0_simple(pe_h_di2)
    b1, pe_h0_2 = chain_init(H_E, pe_bc0_2, sep=0x42)
    vectors.append(vec("preencrypted_chain_init",
                       "(117) H_0 = H(H_E; 0x42, B_C,0), B_C,0 = 0x00000001 || H_DI, H_DI per (119) (16.G)",
                       f"pre-encrypted H_0 simple chaining, device {pe_s_device2!r}", "H_E", H_E, b1, pe_h0_2,
                       {"H_E_hex": hx(H_E), "H_DI_hex": hx(pe_h_di2), "S_device": pe_s_device2,
                        "B_C0_hex": hx(pe_bc0_2)}, 37,
                       notes="Chain of pre-encrypted ballot P2 (preencrypted_ballots); P2 is ballot j = 1."))

    pe_ballots = [
        {"name": "P1 (cast)", "status": "cast",
         "id_B": int.from_bytes(bytes(range(0xC1, 0xE1)), "big"), "xi_B": int.from_bytes(bytes(range(0x11, 0x31)), "big"),
         "contests": [(1, 3, 1, [2]), (3, 4, 2, [1, 4]), (4, 2, 2, [2])],
         "B_C": pre_bc_none, "S_device": devices[1],
         "B_C_desc": "no chaining (16.E): 0x00000000 || H_DI, H_DI = main_chain.H_DI_preencrypted_hex (eq. 119)"},
        {"name": "P2 (uncast)", "status": "uncast",
         "id_B": int.from_bytes(bytes(range(0xDF, 0xFF)), "big"), "xi_B": Q + 11,
         "contests": [(2, 2, 1, None), (5, 3, 2, None)],
         "B_C": b_c_simple(pe_h0_2), "S_device": pe_s_device2,
         "B_C_desc": f"simple chaining j = 1 (16.F): 0x00000001 || H_0, H_0 = eq. (117) for device {pe_s_device2!r}"},
    ]

    def qlbl(x):
        return "q-1" if x == Q - 1 else "q+11" if x == Q + 11 else hq(x)

    pe_nonce_vecs, pe_sel_vecs, pe_chi_vecs, pe_hc_vecs, pe_rp_vecs, pe_lim_vecs = [], [], [], [], [], []
    pe_summary_ballots = []
    for bal in pe_ballots:
        bname, xi_b = bal["name"], bal["xi_B"]
        h_i_b = selection_encryption_identifier_hash(H_E, bal["id_B"])[1]
        tag = f"{bname}"
        chis_pe, contests_summary = [], []
        for pos, (ind_c, m, L, sel) in enumerate(bal["contests"], start=1):
            psi_vecs = []
            for j in range(1, m + L + 1):
                encs = []
                for k in range(1, m + 1):
                    b1n, rawn = preencrypted_nonce(h_i_b, ind_c, j, k, xi_b)            # eq. (121)
                    xi = int.from_bytes(rawn, "big") % Q
                    sigma = 1 if j == k else 0                                          # eqs. (112), (18.2)
                    encs.append({"k": k, "xi": xi, "sigma": sigma, "alpha": pow(G, xi, P),
                                 "beta": pow(K, sigma + xi, P), "b1": b1n, "raw": rawn})
                cts = [(e["alpha"], e["beta"]) for e in encs]
                b1s, psi, lay = preencrypted_selection_hash(h_i_b, cts)                 # eqs. (113), (114)
                psi_vecs.append({"j": j, "null": j > m, "encs": encs, "cts": cts, "b1": b1s, "psi": psi, "layout": lay})
            psis = [pv["psi"] for pv in psi_vecs]
            b1c, chi, layc, pi = preencrypted_contest_hash(h_i_b, ind_c, psis)          # eq. (115)
            chis_pe.append(chi)
            # Short codes (spec-example Omegas): must be unique within the contest (§4.1.5).
            assert len({short_code_hex(x) for x in psis}) == len(psis), f"short-code collision {bname} ind_c={ind_c}"
            short_codes = [{"j": pv["j"], "null": pv["null"], "psi_hex": hx(pv["psi"]),
                            "omega_last_byte_hex": short_code_hex(pv["psi"]),
                            "omega_last_byte_dec3": short_code_dec3(pv["psi"]),
                            "omega_sorted_ordinal": short_code_ordinal(pv["psi"], psis)} for pv in psi_vecs]

            # Verification 18 (uncast): recompute (18.1), (18.2) from the released nonces, (18.3), (18.4).
            if bal["status"] == "uncast":
                for pv in psi_vecs:
                    for e in pv["encs"]:
                        xi_rel = int.from_bytes(preencrypted_nonce(h_i_b, ind_c, pv["j"], e["k"], xi_b)[1], "big") % Q
                        delta = 1 if pv["j"] == e["k"] else 0
                        assert (pow(G, xi_rel, P), pow(K, delta + xi_rel, P)) == (e["alpha"], e["beta"]), "18.1/18.2"
                        assert small_dlog(K, e["beta"] * pow(pow(K, xi_rel, P), -1, P) % P) == e["sigma"]
                    assert preencrypted_selection_hash(h_i_b, pv["cts"])[1] == pv["psi"], "18.3"
                assert preencrypted_contest_hash(h_i_b, ind_c, psis)[1] == chi, "18.4 (with the L null hashes, eq. 115)"

            # Eq. (121) vectors: every released nonce of the uncast ballot (V18), and three P1 nonces.
            for pv in psi_vecs:
                for e in pv["encs"]:
                    if bal["status"] == "uncast" or (ind_c, pv["j"], e["k"]) in ((1, 1, 1), (1, 2, 3), (3, 5, 2)):
                        pe_nonce_vecs.append(vec(
                            "preencrypted_encryption_nonce", "(121) xi_{i,j,k} = H_q(H_I; 0x45, i, j, k, xi_B)",
                            f"xi_{{{ind_c},{pv['j']},{e['k']}}} {tag}", "H_I", h_i_b, e["b1"], e["raw"],
                            {"H_I_hex": hx(h_i_b), "i": ind_c, "j": pv["j"], "k": e["k"], "xi_B_hex": hq(xi_b),
                             "xi_B_ge_q": xi_b >= Q, "m": m, "L": L, "null_vector": pv["null"],
                             "encrypts": e["sigma"],
                             "derivation": f"pre-encrypted ballot {bname}: H_I = eq. (32) of its id_B; i = ind_c, "
                                           f"j = selection vector index (null vector l is j = m + l), k = position "
                                           f"in the vector; encrypts 1 iff j = k"},
                            45, hq_out=True,
                            notes="§5.5.5 table (p.78): B1 = 0x45 || b(i, 4) || b(j, 4) || b(k, 4) || b(xi_B, 32), "
                                  "len(B1) = 45. xi_B is a 256-bit value, never reduced mod q."
                                  + (" Released for this uncast ballot (Verification 18)." if bal["status"] == "uncast"
                                     else "")))

            # Eqs. (113)/(114) vectors: every selection vector of both ballots.
            for pv in psi_vecs:
                null = pv["null"]
                pe_sel_vecs.append(vec(
                    "preencrypted_null_selection_hash" if null else "preencrypted_selection_hash",
                    ("(114) psi_{m+l} = H(H_I; 0x40, alpha_1, beta_1, ..., alpha_m, beta_m), every E_k = Enc(0; "
                     "xi_{i,m+l,k})") if null else
                    ("(113) psi_j = H(H_I; 0x40, alpha_1, beta_1, ..., alpha_m, beta_m), E_j = Enc(1; xi_{i,j,j}), "
                     "E_k = Enc(0; xi_{i,j,k}) for k != j [= Verification 16.A, 18.3]"),
                    f"psi {tag} ind_c={ind_c} j={pv['j']}{' (null l=' + str(pv['j'] - m) + ')' if null else ''}",
                    "H_I", h_i_b, pv["b1"], pv["psi"],
                    {"H_I_hex": hx(h_i_b), "ind_c": ind_c, "position_on_ballot": pos, "m": m, "L": L, "j": pv["j"],
                     "xi_B_hex": hq(xi_b),
                     "encryptions": [{"k": e["k"], "xi_hex": hq(e["xi"]), "sigma": e["sigma"],
                                      "alpha_hex": hp(e["alpha"]), "beta_hex": hp(e["beta"])} for e in pv["encs"]],
                     "derivation": "xi = eq. (121) with (i, j, k) = (ind_c, j, k); alpha_k = g^xi, beta_k = "
                                   "K^(sigma_k + xi), K = g^5 (main_chain)"},
                    1 + 2 * m * 512,
                    notes="§5.5.5 table (p.78): B1 = 0x40 || b(alpha_1, 512) || b(beta_1, 512) || ... || b(beta_m, 512), "
                          "len(B1) = 1 + 2m*512. Same layout for (113) and (114)."))

            # Eq. (115) vector, with diagnostics for the unsorted and the position-index forms.
            srt = sorted(psis)
            diags = []
            if srt != psis:
                b1u = b"\x41" + b_small(ind_c) + b"".join(psis)
                diags.append({"form": "selection hashes unsorted, in generation order j = 1..m+L", "b1_hex": hx(b1u),
                              "hash_hex": hx(H(h_i_b, b1u)), "expected": False})
            if pos != ind_c:
                b1l = b"\x41" + b_small(pos) + b"".join(srt)
                diags.append({"form": "b(l, 4) with l = position on the ballot (Verification 16.B's literal 'l') "
                                      "instead of ind_c(Lambda_l)", "b1_hex": hx(b1l),
                              "hash_hex": hx(H(h_i_b, b1l)), "expected": False})
            cv = vec("preencrypted_contest_hash",
                     "(115) chi_l = H(H_I; 0x41, ind_c(Lambda_l), psi_pi(1), ..., psi_pi(m+L)), psi_pi(1) < ... < "
                     "psi_pi(m+L) as big-endian integers [= Verification 16.B, 18.4]",
                     f"chi {tag} ind_c={ind_c} position={pos} m={m} L={L}", "H_I", h_i_b, b1c, chi,
                     {"H_I_hex": hx(h_i_b), "ind_c": ind_c, "position_on_ballot": pos, "m": m, "L": L,
                      "selection_hashes_generation_order_hex": [hx(x) for x in psis],
                      "pi": pi, "selection_hashes_sorted_hex": [hx(x) for x in srt],
                      "derivation": "selection hashes = this contest's preencrypted_selection_hash (j = 1..m) and "
                                    "preencrypted_null_selection_hash (j = m+1..m+L) vectors; pi[r-1] = generation "
                                    "index j of the r-th smallest hash"},
                     5 + (m + L) * 32,
                     notes="§5.5.5 table (p.78): B1 = 0x41 || b(ind_c(Lambda_l), 4) || psi_pi(1) || ... || psi_pi(m+L), "
                           "len(B1) = 5 + (m + L)*32. All m + L hashes, including the L null hashes, are sorted "
                           "ascending as big-endian integers (= lexicographic byte order) (§4.1.2, footnote 50). The "
                           "index field is ind_c(Lambda_l) per eq. (115); Verification 16.B writes l (the contest's "
                           "sequence number) there: ambiguity recorded, ind_c used per the S7 13.3 precedent. Verification "
                           "18.4 hashes only m_i hashes; eq. (115) (m + L) is followed. 'diagnostics' hold hashes of "
                           "wrong forms, NOT expected values.")
            cv["b1_layout"] = layc
            if diags:
                cv["diagnostics"] = diags
            pe_chi_vecs.append(cv)

            csum = {"ind_c": ind_c, "position_on_ballot": pos, "m": m, "L": L, "chi_hex": hx(chi),
                    "selection_hashes_generation_order_hex": [hx(x) for x in psis], "pi": pi,
                    "short_codes": short_codes}

            # §4.3 recording tool for the cast ballot: combine the selected vectors (padded to L with null vectors),
            # sum the nonces, prove each component (eq. 59, R = 1) and the contest limit (eq. 62).
            if bal["status"] == "cast":
                chosen = list(sel) + [m + l for l in range(1, L - len(sel) + 1)]
                assert len(chosen) == L and len(set(chosen)) == L
                comb = []
                for k in range(1, m + 1):
                    a_, b_, xi_, s_ = 1, 1, 0, 0
                    for j in chosen:
                        e = psi_vecs[j - 1]["encs"][k - 1]
                        a_, b_, xi_, s_ = a_ * e["alpha"] % P, b_ * e["beta"] % P, (xi_ + e["xi"]) % Q, s_ + e["sigma"]
                    assert (a_, b_) == (pow(G, xi_, P), pow(K, xi_ + s_, P)), "Verification 15.A / summed nonce"
                    assert pow(a_, Q, P) == 1 and pow(b_, Q, P) == 1, "6.A"
                    comb.append({"k": k, "alpha": a_, "beta": b_, "xi": xi_, "sigma": s_})
                if L == 1:
                    assert [(c_["alpha"], c_["beta"]) for c_ in comb] == psi_vecs[chosen[0] - 1]["cts"]
                for c_ in comb:
                    k = c_["k"]
                    u = [0x50000000 + ind_c * 0x10000 + k * 0x100 + j for j in range(2)]
                    if (ind_c, k) == (1, 1):
                        u[0] = Q - 1
                    cf = [0x60000000 + ind_c * 0x10000 + k * 0x100 + j for j in range(2)]
                    pr = make_range_proof(lambda cm, ic=ind_c, ko=k, al=c_["alpha"], be=c_["beta"]:
                                          range_proof_challenge(h_i_b, ic, ko, al, be, cm),
                                          K, c_["alpha"], c_["beta"], c_["xi"], c_["sigma"], 1, u, cf)
                    v = vec("preencrypted_range_proof_challenge",
                            "(59) with R = 1 [= (41)/(50)] c = H_q(H_I; 0x24, ind_c(Lambda), ind_o(lambda), alpha, beta, "
                            "a_0, b_0, a_1, b_1) on the recording tool's combined selection vector (§4.3) "
                            "[= Verification 6.3]",
                            f"range proof {tag} ind_c={ind_c} ind_o={k} sigma={c_['sigma']}", "H_I", h_i_b,
                            pr["b1"], pr["raw"],
                            {"H_I_hex": hx(h_i_b), "ind_c": ind_c, "ind_o": k, "R": 1,
                             "combined_from_j": chosen, "alpha_hex": hp(c_["alpha"]), "beta_hex": hp(c_["beta"]),
                             "xi_hex": hq(c_["xi"]), "sigma": c_["sigma"],
                             "u_hex": [hq(x) for x in u],
                             "c_fake_hex": {str(j): hq(cf[j]) for j in range(2) if j != c_["sigma"]},
                             "commitments": [{"j": j, "a_hex": hp(a_j), "b_hex": hp(b_j)}
                                             for j, (a_j, b_j) in enumerate(pr["commits"])],
                             "proof": {"c_hex": hq(pr["c"]), "c_j_hex": [hq(x) for x in pr["cs"]],
                                       "v_j_hex": [hq(x) for x in pr["vs"]]},
                             "derivation": "alpha = prod_j alpha_{j,k}, beta = prod_j beta_{j,k} over the chosen "
                                           "vectors j (Verification 15.A); xi = sum_j xi_{ind_c,j,k} mod q (§4.3); "
                                           "commitments by eqs. (57)/(58) with the fixed u_j and c_j (j != sigma); "
                                           "c_sigma by (60), v_j by (61). The script runs Verification 6.1-6.3 and "
                                           "6.A-6.D on the result."},
                            9 + (2 * 1 + 4) * 512, hq_out=True,
                            notes="No pre-encrypted row in §5.5.5: §4.3 says proofs are made 'as in standard "
                                  "ElectionGuard section 3.3.7', so this is the §5.5.3 (p.75) row for (41)/(50)/(59): "
                                  "B1 = 0x24 || b(ind_c, 4) || b(ind_o, 4) || b(alpha, 512) || b(beta, 512) || b(a_0, "
                                  "512) || b(b_0, 512) || b(a_1, 512) || b(b_1, 512), len(B1) = 9 + (2R + 4)*512 = 3081, "
                                  "B0 = the pre-encrypted ballot's H_I. ind_o = option index = position k.")
                    v["b1_layout"] = pr["layout"]
                    pe_rp_vecs.append(v)
                a_bar, b_bar, xi_bar, ell = 1, 1, 0, 0
                for c_ in comb:                                                          # (7.1), (7.2)
                    a_bar, b_bar = a_bar * c_["alpha"] % P, b_bar * c_["beta"] % P
                    xi_bar, ell = (xi_bar + c_["xi"]) % Q, ell + c_["sigma"]
                assert ell == len(sel) <= L
                u = [0x70000000 + ind_c * 0x100 + j for j in range(L + 1)]
                cf = [0x80000000 + ind_c * 0x100 + j for j in range(L + 1)]
                pr = make_range_proof(lambda cm, ic=ind_c, al=a_bar, be=b_bar:
                                      selection_limit_challenge(h_i_b, ic, al, be, cm),
                                      K, a_bar, b_bar, xi_bar, ell, L, u, cf)
                v = vec("preencrypted_selection_limit_challenge",
                        "(62) c = H_q(H_I; 0x24, ind_c(Lambda), alpha-bar, beta-bar, a_0, b_0, ..., a_L, b_L) on the "
                        "recording tool's combined selection vector (§4.3) [= Verification 7.5]",
                        f"selection limit proof {tag} ind_c={ind_c} L={L} total={ell}", "H_I", h_i_b,
                        pr["b1"], pr["raw"],
                        {"H_I_hex": hx(h_i_b), "ind_c": ind_c, "L": L, "selected_options": sel,
                         "combined_from_j": chosen,
                         "alpha_bar_hex": hp(a_bar), "beta_bar_hex": hp(b_bar), "xi_bar_hex": hq(xi_bar), "total": ell,
                         "u_hex": [hq(x) for x in u],
                         "c_fake_hex": {str(j): hq(cf[j]) for j in range(L + 1) if j != ell},
                         "commitments": [{"j": j, "a_hex": hp(a_j), "b_hex": hp(b_j)}
                                         for j, (a_j, b_j) in enumerate(pr["commits"])],
                         "proof": {"c_hex": hq(pr["c"]), "c_j_hex": [hq(x) for x in pr["cs"]],
                                   "v_j_hex": [hq(x) for x in pr["vs"]]},
                         "derivation": "alpha-bar = prod_k alpha_k, beta-bar = prod_k beta_k over the m components of "
                                       "the combined vector (7.1, 7.2); xi-bar = sum_k xi_k; commitments by (57)/(58) "
                                       "with R = L; the script runs Verification 7.3-7.5 and 7.A-7.D."},
                        5 + (2 * L + 4) * 512, hq_out=True,
                        notes="No pre-encrypted row in §5.5.5; this is the §5.5.3 (p.75) row for (62): B1 = 0x24 || "
                              "b(ind_c, 4) || b(alpha-bar, 512) || b(beta-bar, 512) || b(a_0, 512) || ... || b(b_L, 512), "
                              "len(B1) = 5 + (2L + 4)*512, no ind_o. B0 = the pre-encrypted ballot's H_I.")
                v["b1_layout"] = pr["layout"]
                pe_lim_vecs.append(v)
                csum["recording"] = {
                    "selected_options": sel, "combined_from_j": chosen,
                    "selected_short_codes_last_byte_hex": [short_code_hex(psi_vecs[j - 1]["psi"]) for j in chosen],
                    "combined_vector": [{"k": c_["k"], "alpha_hex": hp(c_["alpha"]), "beta_hex": hp(c_["beta"]),
                                         "xi_hex": hq(c_["xi"]), "sigma": c_["sigma"]} for c_ in comb],
                    "verification_15": "combined vector = componentwise product of the chosen Psi_j (asserted)"}
            contests_summary.append(csum)

        b1, hc = confirmation_code(h_i_b, chis_pe, bal["B_C"], sep=0x42)                 # eq. (116), 16.C, 18.A
        pe_hc_vecs.append(vec("preencrypted_confirmation_code",
                              "(116) H_C = H(H_I; 0x42, chi_1, ..., chi_mB, B_C) [= Verification 16.C, 18.A], chi from "
                              "eq. (115)",
                              f"pre-encrypted H_C {tag}", "H_I", h_i_b, b1, hc,
                              {"H_I_hex": hx(h_i_b), "contest_hashes_hex": [hx(c_) for c_ in chis_pe],
                               "contest_ind_c": [c[0] for c in bal["contests"]], "B_C_hex": hx(bal["B_C"]),
                               "B_C": bal["B_C_desc"],
                               "derivation": "contest hashes = this ballot's preencrypted_contest_hash vectors in "
                                             "ballot (ascending ind_c) order"},
                              37 + 32 * len(chis_pe),
                              notes="§5.5.5 table (p.78): len(B1) = 37 + m_B*32. Real eq. (115) contest hashes (the "
                                    "earlier preencrypted_confirmation_code vectors use opaque stand-ins)."))
        pe_summary_ballots.append({"ballot": bname, "status": bal["status"], "id_B_hex": hq(bal["id_B"]),
                                   "H_I_hex": hx(h_i_b), "xi_B_hex": hq(xi_b), "xi_B_label": qlbl(xi_b),
                                   "S_device": bal["S_device"], "B_C_hex": hx(bal["B_C"]), "B_C": bal["B_C_desc"],
                                   "H_C_hex": hx(hc), "contests": contests_summary})

    # Extra eq. (121) edge case: maximal small indices and xi_B = 2^256 - 1 under P1's H_I.
    h_i_p1 = selection_encryption_identifier_hash(H_E, pe_ballots[0]["id_B"])[1]
    b1, raw = preencrypted_nonce(h_i_p1, 2147483647, 2147483647, 2147483647, 2**256 - 1)
    pe_nonce_vecs.append(vec("preencrypted_encryption_nonce", "(121) xi_{i,j,k} = H_q(H_I; 0x45, i, j, k, xi_B)",
                       "xi_{2^31-1,2^31-1,2^31-1} xi_B=2^256-1 P1 (cast)", "H_I", h_i_p1, b1, raw,
                       {"H_I_hex": hx(h_i_p1), "i": 2147483647, "j": 2147483647, "k": 2147483647,
                        "xi_B_hex": hq(2**256 - 1), "xi_B_ge_q": True},
                       45, hq_out=True, notes="Edge case: largest small integers (§5.1.3) and xi_B = 2^256 - 1."))

    for group in (pe_nonce_vecs, pe_sel_vecs, pe_chi_vecs, pe_hc_vecs, pe_rp_vecs, pe_lim_vecs):
        vectors.extend(group)

    pe_ballots_summary = {
        "election": "main_chain (H_E = main_chain.H_E_hex, K = g^5)",
        "ballots": pe_summary_ballots,
        "short_codes": "Omega is manifest-defined (§4.1.5); omega_last_byte_hex (two uppercase hex chars of the last "
                       "byte), omega_last_byte_dec3 (last byte as 000-255) and omega_sorted_ordinal (1-based rank in "
                       "the contest's sorted hashes, §4.2.2) are spec examples, not binding. The script asserts the "
                       "last-byte codes are unique within each contest.",
        "combined_vector_proofs": "eqs. (59) with R = 1 (= (41)/(50)) per option and (62) per contest, unchanged, keyed "
                                  "with the pre-encrypted ballot's H_I (no §5.5.5 row; §4.3 'as in standard "
                                  "ElectionGuard section 3.3.7')",
        "stand_ins": "the earlier preencrypted_confirmation_code vectors (preencrypted_chain) use opaque contest-hash "
                     "stand-ins and predate this family; their values are unchanged",
        "spec_ambiguities": PE_AMBIGUITIES,
    }

    # The Q7 helper's rejection boundary (not spec; recorded, not a hash vector).
    cd_rejections = []
    for b_lambda, s in ((1, full1 + "!"), (3, full3 + "x"), (1, "Write-in: Grace Hopper (US)é")):
        try:
            encode_contest_data_string(s, b_lambda)
            raise AssertionError("must be rejected")
        except ValueError:
            cd_rejections.append({"b_Lambda": b_lambda, "string": s, "utf8_len": len(s.encode("utf-8")),
                                  "capacity_utf8_bytes": 32 * b_lambda - 4})

    doc = {
        "description": "ElectionGuard v2.1.0 hash-chain KAT vectors, generated by test/kat/eg_kat.py "
                       "from the specification only (not from the C# implementation).",
        "spec_version": "v2.1.0",
        "conventions": {
            "hex": "uppercase, big-endian; Z_p values are 512 bytes, Z_q / 256-bit values 32 bytes",
            "H": "HMAC-SHA-256(key=B0, msg=B1)",
            "H_q": "H mod q; such vectors carry expected_hmac_hex (raw) and expected_hex (reduced, 32 bytes)",
            "indices": "1-based, 4-byte big-endian",
            "strings_files": "b(len, 4) || bytes, len = UTF-8 byte length",
        },
        "parameters": {"p_hex": hx(b(P, LP)), "q_hex": hq(Q), "g_hex": hp(G), "r_hex": format(R, "X")},
        "main_chain": {
            "n": 3, "k": 2, "manifest_hex": hx(b'{"election":"kat"}'),
            "H_P_hex": hx(hps[(3, 2)]), "H_B_hex": hx(hbs[(3, 2, "kat manifest")]),
            "K": "g^5", "K_hat": "g^7", "H_E_hex": hx(H_E),
            "id_B_hex": hq(int.from_bytes(bytes(range(1, 33)), "big")), "H_I_hex": hx(H_I),
            "xi_B_hex": hq(xi_b_main), "S_device": devices[1], "H_DI_hex": hx(H_DI),
            "H_DI_preencrypted_hex": hx(H_DI_pre),
        },
        "vectors": vectors,
        "tally_decryption": {
            "election": "main_chain (n=3, k=2, K=g^5, H_E = main_chain.H_E_hex)",
            "guardian_polynomials": "a_{i,j} of the n=3,k=2 guardian_record_hash vector: a_{i,0} = (10, 20, q-25), "
                                    "a_{i,1} = 100i + 11; s = 5",
            "z_i": [{"i": i, "hex": hq(z[i])} for i in sorted(z)],
            "U_encoding": "b(#U, 4) || b(j_1, 4) || ... || b(j_#U, 4), j ascending (order not stated by the spec)",
            "proofs": tally_summary,
        },
        "contest_data": {
            "election": "main_chain ballot (H_I = main_chain.H_I_hex, xi_B = main_chain.xi_B_hex, K_hat = g^7)",
            "kdf": {"Label_hex": hx(KDF_LABEL), "Label": "data_enc_keys",
                    "Context_prefix_hex": hx(KDF_CONTEXT_STR), "Context_prefix": "contest_data",
                    "message": "b(i, 4) || Label || 0x00 || Context || b(b_Lambda * 256, 4), 1 <= i <= b_Lambda"},
            "C2_encoding": "b(C2, 64) = b(c, 32) || b(v, 32) (order c then v, per C2 = (c, v); not spelled out)",
            "string_helper": "NOT SPEC (user decision Q7): D = b(len_utf8(s), 4) || UTF-8(s) || 0x00 padding, exactly "
                             "32*b_Lambda bytes; rejected when 4 + len_utf8(s) > 32*b_Lambda",
            "string_helper_rejections": cd_rejections,
            "guardian_polynomials": "ahat_{i,j} of the n=3,k=2 guardian_record_hash vector: ahat_{i,0} = (30, 40, "
                                    "q-63), ahat_{i,1} = 100i + 15; s_hat = 7",
            "z_hat_i": [{"i": i, "hex": hq(z_hat[i])} for i in sorted(z_hat)],
            "decryption_proofs": cd_dec_summary,
        },
        "challenged_ballots": {
            "election": "main_chain (H_E = main_chain.H_E_hex, K = g^5, K_hat = g^7); guardian K_hat shares = "
                        "contest_data.z_hat_i",
            "ballot_nonce_kdf": {"Label_hex": hx(BN_KDF_LABEL), "Label": "ballot_nonce",
                                 "Context_hex": hx(BN_KDF_CONTEXT), "Context": "ballot_nonce_encrypt",
                                 "message_hex": hx(ballot_nonce_kdf_message()),
                                 "message": "0x01 || Label || 0x00 || Context || 0x0100 (36 bytes; 1-byte counter, "
                                            "2-byte bit length, as eqs. 17/18)"},
            "C2_encoding": "b(c_B, 32) || b(v_B, 32) (Q20 order); C_xiB is not hashed into any contest hash or "
                           "confirmation code",
            "sparse_ballot": {"id_B_hex": hq(sparse_id_b), "H_I_hex": hx(H_I_sparse), "xi_B_hex": hq(sparse_xi_b)},
            "ballot_nonce_encryptions": bn_summary,
            "no_decryption_proof": "§3.6.7 defines no NIZK proof (no commitment/challenge hash, no §5.5.4 row) for the "
                                   "decryption of the ballot nonce; correctness rests on Verification 13 over the "
                                   "released nonces. Verification 14 computes no hash.",
            "verification_13": v13_summary,
        },
        "preencrypted_chain": pre_summary,
        "preencrypted_ballots": pe_ballots_summary,
    }
    return doc


def main():
    doc = build()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    hp32 = next(v for v in doc["vectors"] if v["name"] == "H_P n=3 k=2")["expected_hex"]
    print(f"wrote {len(doc['vectors'])} vectors to {out}")
    print(f"H_P (n=3, k=2) = {hp32}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
