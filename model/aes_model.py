#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
# AES golden model — pure-Python, no external crypto libraries required.
# Supports AES-128, AES-192, AES-256 (ECB, CBC, CTR).
#
# Usage:
#   from aes_model import AESModel
#   m = AESModel(key_bits=128)
#   m.set_key(key_bytes)
#   ct = m.encrypt_block_ecb(pt)
#   pt = m.decrypt_block_ecb(ct)
#
# All inputs/outputs are bytes objects of length 16.
# key_bytes must be 16, 24, or 32 bytes for AES-128/192/256.
# =============================================================================

from __future__ import annotations
import os
import struct
from typing import List, Tuple


# ---------------------------------------------------------------------------
# AES constants
# ---------------------------------------------------------------------------

SBOX_FWD = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

SBOX_INV = [0] * 256
for i, v in enumerate(SBOX_FWD):
    SBOX_INV[v] = i

RCON = [
    0x00,  # unused (1-indexed)
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91,
]


# ---------------------------------------------------------------------------
# GF(2^8) arithmetic
# ---------------------------------------------------------------------------

def xtime(b: int) -> int:
    """Multiply by 2 in GF(2^8)."""
    result = (b << 1) & 0xFF
    if b & 0x80:
        result ^= 0x1B
    return result


def gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result


# ---------------------------------------------------------------------------
# State helpers (4×4 column-major bytes)
# ---------------------------------------------------------------------------

def bytes_to_state(data: bytes) -> List[List[int]]:
    """Convert 16 bytes to 4×4 state[col][row]."""
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i // 4][i % 4] = data[i]
    return state


def state_to_bytes(state: List[List[int]]) -> bytes:
    """Convert 4×4 state back to 16 bytes."""
    out = []
    for col in range(4):
        for row in range(4):
            out.append(state[col][row])
    return bytes(out)


# ---------------------------------------------------------------------------
# AES transformations
# ---------------------------------------------------------------------------

def sub_bytes(state: List[List[int]], inv: bool = False) -> List[List[int]]:
    sbox = SBOX_INV if inv else SBOX_FWD
    return [[sbox[state[c][r]] for r in range(4)] for c in range(4)]


def shift_rows(state: List[List[int]]) -> List[List[int]]:
    """ShiftRows — rotate row r left by r positions."""
    out = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            out[c][r] = state[(c + r) % 4][r]
    return out


def inv_shift_rows(state: List[List[int]]) -> List[List[int]]:
    """InvShiftRows — rotate row r right by r positions."""
    out = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            out[c][r] = state[(c - r) % 4][r]
    return out


def mix_columns(state: List[List[int]]) -> List[List[int]]:
    """MixColumns — multiply each column by the MDS matrix."""
    out = [[0]*4 for _ in range(4)]
    for c in range(4):
        s = state[c]
        out[c][0] = gmul(0x02, s[0]) ^ gmul(0x03, s[1]) ^ s[2] ^ s[3]
        out[c][1] = s[0] ^ gmul(0x02, s[1]) ^ gmul(0x03, s[2]) ^ s[3]
        out[c][2] = s[0] ^ s[1] ^ gmul(0x02, s[2]) ^ gmul(0x03, s[3])
        out[c][3] = gmul(0x03, s[0]) ^ s[1] ^ s[2] ^ gmul(0x02, s[3])
    return out


def inv_mix_columns(state: List[List[int]]) -> List[List[int]]:
    """InvMixColumns."""
    out = [[0]*4 for _ in range(4)]
    for c in range(4):
        s = state[c]
        out[c][0] = gmul(0x0e, s[0]) ^ gmul(0x0b, s[1]) ^ gmul(0x0d, s[2]) ^ gmul(0x09, s[3])
        out[c][1] = gmul(0x09, s[0]) ^ gmul(0x0e, s[1]) ^ gmul(0x0b, s[2]) ^ gmul(0x0d, s[3])
        out[c][2] = gmul(0x0d, s[0]) ^ gmul(0x09, s[1]) ^ gmul(0x0e, s[2]) ^ gmul(0x0b, s[3])
        out[c][3] = gmul(0x0b, s[0]) ^ gmul(0x0d, s[1]) ^ gmul(0x09, s[2]) ^ gmul(0x0e, s[3])
    return out


def add_round_key(state: List[List[int]], rk: bytes) -> List[List[int]]:
    """XOR state with 128-bit round key (column-major order)."""
    rk_state = bytes_to_state(rk)
    return [[state[c][r] ^ rk_state[c][r] for r in range(4)] for c in range(4)]


# ---------------------------------------------------------------------------
# Key schedule
# ---------------------------------------------------------------------------

def _sub_word(w: int) -> int:
    return (SBOX_FWD[(w >> 24) & 0xFF] << 24 |
            SBOX_FWD[(w >> 16) & 0xFF] << 16 |
            SBOX_FWD[(w >>  8) & 0xFF] <<  8 |
            SBOX_FWD[ w        & 0xFF])


def _rot_word(w: int) -> int:
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def key_schedule(key: bytes) -> List[bytes]:
    """
    Expand key into N_ROUNDS+1 round keys, each 16 bytes.
    Returns list of bytes objects: round_keys[0..N_ROUNDS]
    """
    n = len(key)
    assert n in (16, 24, 32), f"Invalid key length {n}"
    nkw = n // 4
    n_rounds = {16: 10, 24: 12, 32: 14}[n]
    total_words = 4 * (n_rounds + 1)

    W = []
    for i in range(nkw):
        W.append(int.from_bytes(key[4*i:4*i+4], 'big'))

    for i in range(nkw, total_words):
        temp = W[i - 1]
        if i % nkw == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[i // nkw] << 24)
        elif nkw > 6 and i % nkw == 4:
            temp = _sub_word(temp)
        W.append(W[i - nkw] ^ temp)

    round_keys = []
    for k in range(n_rounds + 1):
        rk = b''.join(W[4*k + j].to_bytes(4, 'big') for j in range(4))
        round_keys.append(rk)
    return round_keys


# ---------------------------------------------------------------------------
# Block cipher (ECB)
# ---------------------------------------------------------------------------

def aes_encrypt_block(plaintext: bytes, round_keys: List[bytes]) -> bytes:
    """Encrypt a single 16-byte block."""
    assert len(plaintext) == 16
    n_rounds = len(round_keys) - 1
    state = bytes_to_state(plaintext)
    state = add_round_key(state, round_keys[0])

    for r in range(1, n_rounds):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])

    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[n_rounds])

    return state_to_bytes(state)


def aes_decrypt_block(ciphertext: bytes, round_keys: List[bytes]) -> bytes:
    """Decrypt a single 16-byte block."""
    assert len(ciphertext) == 16
    n_rounds = len(round_keys) - 1
    state = bytes_to_state(ciphertext)
    state = add_round_key(state, round_keys[n_rounds])

    for r in range(n_rounds - 1, 0, -1):
        state = inv_shift_rows(state)
        state = sub_bytes(state, inv=True)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)

    # Final round (no InvMixColumns)
    state = inv_shift_rows(state)
    state = sub_bytes(state, inv=True)
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)


# ---------------------------------------------------------------------------
# AESModel — stateful, matches aes_top RTL behaviour
# ---------------------------------------------------------------------------

class AESModel:
    """
    Stateful AES model that matches the aes_top RTL interface:
      - set_key(): trigger key expansion (like s_key_expand pulse)
      - set_iv():  latch IV (like s_iv_load pulse)
      - encrypt/decrypt per mode
    """

    def __init__(self, key_bits: int = 128):
        assert key_bits in (128, 192, 256)
        self.key_bits  = key_bits
        self.n_rounds  = {128: 10, 192: 12, 256: 14}[key_bits]
        self.round_keys: List[bytes] = []
        self.key_ready  = False
        self.iv: bytes  = b'\x00' * 16
        self.iv_ready   = False
        self.cbc_prev: bytes = b'\x00' * 16
        self.ctr: int   = 0  # integer counter (big-endian 128-bit)

    def set_key(self, key: bytes) -> None:
        """Expand key (equivalent to writing key registers + asserting key_expand)."""
        assert len(key) == self.key_bits // 8
        self.round_keys = key_schedule(key)
        self.key_ready  = True

    def set_iv(self, iv: bytes) -> None:
        """Latch IV (equivalent to writing IV registers + asserting iv_load)."""
        assert len(iv) == 16
        self.iv       = iv
        self.iv_ready = True
        # RTL resets cbc_prev and ctr on iv_load
        self.cbc_prev = iv  # CBC first block XORs with IV
        self.ctr      = int.from_bytes(iv, 'big')

    # ── Single-block operations ───────────────────────────────────────────────

    def encrypt_ecb(self, pt: bytes) -> bytes:
        assert self.key_ready, "Key not expanded"
        return aes_encrypt_block(pt, self.round_keys)

    def decrypt_ecb(self, ct: bytes) -> bytes:
        assert self.key_ready, "Key not expanded"
        return aes_decrypt_block(ct, self.round_keys)

    def encrypt_cbc(self, pt: bytes) -> bytes:
        assert self.key_ready, "Key not expanded"
        xored = bytes(a ^ b for a, b in zip(pt, self.cbc_prev))
        ct = aes_encrypt_block(xored, self.round_keys)
        self.cbc_prev = ct
        return ct

    def decrypt_cbc(self, ct: bytes) -> bytes:
        assert self.key_ready, "Key not expanded"
        dec = aes_decrypt_block(ct, self.round_keys)
        pt = bytes(a ^ b for a, b in zip(dec, self.cbc_prev))
        self.cbc_prev = ct
        return pt

    def encrypt_ctr(self, data: bytes) -> bytes:
        assert self.key_ready, "Key not expanded"
        ctr_bytes = self.ctr.to_bytes(16, 'big')
        keystream = aes_encrypt_block(ctr_bytes, self.round_keys)
        result = bytes(a ^ b for a, b in zip(data, keystream))
        self.ctr = (self.ctr + 1) & ((1 << 128) - 1)
        return result

    # CTR decrypt = CTR encrypt (symmetric)
    decrypt_ctr = encrypt_ctr

    # ── Multi-block helpers ───────────────────────────────────────────────────

    def encrypt_blocks(self, data: bytes, mode: str = 'ECB') -> bytes:
        """Encrypt arbitrary-length data (must be multiple of 16 bytes)."""
        assert len(data) % 16 == 0
        enc_fn = {'ECB': self.encrypt_ecb, 'CBC': self.encrypt_cbc,
                  'CTR': self.encrypt_ctr}[mode.upper()]
        return b''.join(enc_fn(data[i:i+16]) for i in range(0, len(data), 16))

    def decrypt_blocks(self, data: bytes, mode: str = 'ECB') -> bytes:
        """Decrypt arbitrary-length data (must be multiple of 16 bytes)."""
        assert len(data) % 16 == 0
        dec_fn = {'ECB': self.decrypt_ecb, 'CBC': self.decrypt_cbc,
                  'CTR': self.decrypt_ctr}[mode.upper()]
        return b''.join(dec_fn(data[i:i+16]) for i in range(0, len(data), 16))

    # ── RTL-matching single transaction ──────────────────────────────────────
    def process(self, data: bytes, mode: str, direction: str) -> bytes:
        """
        Single block: mode in ('ECB','CBC','CTR'), direction in ('enc','dec').
        Mirrors the aes_top s_valid→m_valid interface.
        """
        m = mode.upper()
        d = direction.lower()
        if m == 'ECB':
            return self.encrypt_ecb(data) if d == 'enc' else self.decrypt_ecb(data)
        elif m == 'CBC':
            return self.encrypt_cbc(data) if d == 'enc' else self.decrypt_cbc(data)
        elif m == 'CTR':
            return self.encrypt_ctr(data)  # CTR is symmetric
        else:
            raise ValueError(f"Unknown mode: {mode}")


# ---------------------------------------------------------------------------
# NIST test vectors (for self-test)
# ---------------------------------------------------------------------------

NIST_VECTORS = [
    # (key_bits, key_hex, pt_hex, ct_hex)
    # AES-128 ECB — FIPS 197 Appendix B
    (128,
     '2b7e151628aed2a6abf7158809cf4f3c',
     '3243f6a8885a308d313198a2e0370734',
     '3925841d02dc09fbdc118597196a0b32'),
    # AES-192 ECB — FIPS 197 Appendix C.2
    (192,
     '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
     '6bc1bee22e409f96e93d7e117393172a',
     'bd334f1d6e45f25ff712a214571fa5cc'),
    # AES-256 ECB — FIPS 197 Appendix C.3
    (256,
     '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
     '6bc1bee22e409f96e93d7e117393172a',
     'f3eed1bdb5d2a03c064b5a7e3db181f8'),
    # AES-128 CBC — NIST SP 800-38A F.2.1
    # (tested separately via model below)
]


def self_test() -> bool:
    """Run NIST test vectors. Returns True if all pass."""
    ok = True
    for key_bits, key_hex, pt_hex, ct_hex in NIST_VECTORS:
        key = bytes.fromhex(key_hex)
        pt  = bytes.fromhex(pt_hex)
        ct  = bytes.fromhex(ct_hex)
        m = AESModel(key_bits=key_bits)
        m.set_key(key)
        enc = m.encrypt_ecb(pt)
        dec = m.decrypt_ecb(ct)
        enc_ok = (enc == ct)
        dec_ok = (dec == pt)
        status = 'PASS' if enc_ok and dec_ok else 'FAIL'
        if not (enc_ok and dec_ok):
            ok = False
        print(f"[AES-{key_bits} ECB] {status}  enc={enc.hex()}  dec={dec.hex()}")

    # CBC test — NIST SP 800-38A F.2.1 (first block only)
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    ct_expected = bytes.fromhex('7649abac8119b246cee98e9b12e9197d')
    m = AESModel(key_bits=128)
    m.set_key(key)
    m.set_iv(iv)
    ct = m.encrypt_cbc(pt)
    cbc_ok = (ct == ct_expected)
    if not cbc_ok:
        ok = False
    print(f"[AES-128 CBC] {'PASS' if cbc_ok else 'FAIL'}  ct={ct.hex()}")

    # CTR test — NIST SP 800-38A F.5.1
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv  = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    ct_expected = bytes.fromhex('874d6191b620e3261bef6864990db6ce')
    m = AESModel(key_bits=128)
    m.set_key(key)
    m.set_iv(iv)
    ct = m.encrypt_ctr(pt)
    ctr_ok = (ct == ct_expected)
    if not ctr_ok:
        ok = False
    print(f"[AES-128 CTR] {'PASS' if ctr_ok else 'FAIL'}  ct={ct.hex()}")

    return ok


# ---------------------------------------------------------------------------
# Utility: generate random test vector
# ---------------------------------------------------------------------------

def random_vector(key_bits: int = 128, mode: str = 'ECB',
                  direction: str = 'enc', seed: bytes | None = None
                  ) -> Tuple[bytes, bytes, bytes, bytes | None, bytes]:
    """
    Returns (key, iv_or_None, plaintext, ciphertext) ready for RTL comparison.
    direction: 'enc' → returns (key, iv, pt, ct); 'dec' → swapped
    """
    key = os.urandom(key_bits // 8)
    iv  = os.urandom(16)
    pt  = os.urandom(16)
    m = AESModel(key_bits=key_bits)
    m.set_key(key)
    m.set_iv(iv)
    ct = m.process(pt, mode, 'enc')
    return key, iv, pt, ct


# ---------------------------------------------------------------------------
# CLI: run self-test or generate vectors
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    if '--vectors' in sys.argv:
        import argparse
        parser = argparse.ArgumentParser(description='AES golden model')
        parser.add_argument('--key-bits', type=int, default=128, choices=[128, 192, 256])
        parser.add_argument('--mode',     default='ECB', choices=['ECB', 'CBC', 'CTR'])
        parser.add_argument('--count',    type=int, default=10)
        args = parser.parse_args()
        print(f"# AES-{args.key_bits} {args.mode} test vectors")
        print("# key, iv, pt, ct")
        for _ in range(args.count):
            key, iv, pt, ct = random_vector(args.key_bits, args.mode)
            print(f"{key.hex()} {iv.hex()} {pt.hex()} {ct.hex()}")
    else:
        passed = self_test()
        sys.exit(0 if passed else 1)
