#!/usr/bin/env python3
"""ElectionGuard v2.1.0 hash-chain known-answer-test (KAT) oracle.

Written from the ElectionGuard Design Specification v2.1.0 ONLY (sections 3.1-3.4, 3.6.2-3.6.5,
4.1.4 and 5, and Verification 10), without reference to the C# implementation in this repository,
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


def chain_close_bc(h_e, h_last, b_c0):
    """Eq. (78): B-bar_C = 0x00000001 || H(H_E; 0x2B, H_l, B_{C,0}). Returns (inner B1, inner hash, B-bar_C)."""
    b1 = b"\x2B" + h_last + b_c0
    assert len(b1) == 69
    inner = H(h_e, b1)
    return b1, inner, b"\x00\x00\x00\x01" + inner


def chain_close(h_e, b_c_bar):
    """Eq. (77): H-bar = H(H_E; 0x29, B-bar_C)."""
    b1 = b"\x29" + b_c_bar
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
