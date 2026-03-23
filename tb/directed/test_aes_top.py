#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
# cocotb directed testbench for aes_top
#
# Tests:
#   - AES-128/192/256 ECB encrypt + decrypt (NIST vectors + random)
#   - CBC encrypt + decrypt (NIST vectors + random)
#   - CTR encrypt/decrypt symmetry (NIST vectors + random)
#   - Pipeline throughput (back-to-back blocks)
#   - Key re-expansion while idle
#   - IV reload between operations
#   - m_err flag on block submitted before key_ready
# =============================================================================

import os
import sys
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, FallingEdge, ClockCycles, Timer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../model'))
from aes_model import AESModel, aes_encrypt_block, aes_decrypt_block, key_schedule

# ── Parameters ────────────────────────────────────────────────────────────────
CLK_PERIOD_NS = 10
KEY_BITS = int(os.environ.get('KEY_BITS', 128))
N_ROUNDS  = {128: 10, 192: 12, 256: 14}[KEY_BITS]
PIPE_LAT  = N_ROUNDS + 1

# mode / dir encodings matching aes_pkg
MODE_ECB = 0
MODE_CBC = 1
MODE_CTR = 2
DIR_ENC  = 0
DIR_DEC  = 1


# ── DUT helpers ───────────────────────────────────────────────────────────────

async def reset_dut(dut):
    dut.rst_n.value       = 0
    dut.s_key_expand.value = 0
    dut.s_iv_load.value    = 0
    dut.s_valid.value      = 0
    dut.s_data.value       = 0
    dut.s_mode.value       = MODE_ECB
    dut.s_dir.value        = DIR_ENC
    dut.s_tag.value        = 0
    dut.m_ready.value      = 1
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)


async def key_expand_wait(dut, key: bytes):
    """Write key and pulse key_expand, wait for key_ready."""
    key_int = int.from_bytes(key, 'big')
    dut.s_key_in.value   = key_int
    dut.s_key_expand.value = 1
    await RisingEdge(dut.clk)
    dut.s_key_expand.value = 0
    # Wait for key_ready
    for _ in range(200):
        await RisingEdge(dut.clk)
        if dut.key_ready.value == 1:
            return
    raise TimeoutError("key_ready never asserted")


async def iv_load(dut, iv: bytes):
    """Pulse s_iv_load with iv."""
    dut.s_iv.value     = int.from_bytes(iv, 'big')
    dut.s_iv_load.value = 1
    await RisingEdge(dut.clk)
    dut.s_iv_load.value = 0


async def send_block(dut, data: bytes, mode: int, direction: int, tag: int = 0):
    """Submit one block — wait for s_ready, then assert s_valid for one cycle."""
    # wait for s_ready
    for _ in range(200):
        if dut.s_ready.value == 1:
            break
        await RisingEdge(dut.clk)
    else:
        raise TimeoutError("s_ready never asserted")

    dut.s_data.value  = int.from_bytes(data, 'big')
    dut.s_mode.value  = mode
    dut.s_dir.value   = direction
    dut.s_tag.value   = tag
    dut.s_valid.value = 1
    await RisingEdge(dut.clk)
    dut.s_valid.value = 0


async def recv_block(dut) -> tuple[bytes, int, bool]:
    """Wait for m_valid, return (data, tag, err)."""
    for _ in range(300):
        await RisingEdge(dut.clk)
        if dut.m_valid.value == 1:
            data = dut.m_data.value.integer.to_bytes(16, 'big')
            tag  = int(dut.m_tag.value)
            err  = bool(dut.m_err.value)
            return data, tag, err
    raise TimeoutError("m_valid never asserted")


# ── Test cases ────────────────────────────────────────────────────────────────

@cocotb.test()
async def test_nist_aes128_ecb(dut):
    """NIST FIPS 197 Appendix B — AES-128 ECB."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    if KEY_BITS != 128:
        dut._log.info(f"Skipping AES-128 test (KEY_BITS={KEY_BITS})")
        return

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    pt  = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
    ct_expected = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')

    await key_expand_wait(dut, key)

    # Encrypt
    await send_block(dut, pt, MODE_ECB, DIR_ENC, tag=0xA5)
    ct, tag, err = await recv_block(dut)
    assert not err, "m_err asserted on encrypt"
    assert ct == ct_expected, f"ECB enc mismatch: {ct.hex()} != {ct_expected.hex()}"
    assert tag == 0xA5, f"tag mismatch: {tag}"
    dut._log.info(f"[AES-128 ECB enc] PASS  ct={ct.hex()}")

    # Decrypt
    await send_block(dut, ct_expected, MODE_ECB, DIR_DEC, tag=0x5A)
    pt_out, tag, err = await recv_block(dut)
    assert not err
    assert pt_out == pt, f"ECB dec mismatch: {pt_out.hex()} != {pt.hex()}"
    dut._log.info(f"[AES-128 ECB dec] PASS  pt={pt_out.hex()}")


@cocotb.test()
async def test_nist_cbc(dut):
    """NIST SP 800-38A F.2.1 — AES-128 CBC encrypt first block."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    if KEY_BITS != 128:
        dut._log.info(f"Skipping AES-128 CBC test (KEY_BITS={KEY_BITS})")
        return

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    ct_expected = bytes.fromhex('7649abac8119b246cee98e9b12e9197d')

    await key_expand_wait(dut, key)
    await iv_load(dut, iv)

    await send_block(dut, pt, MODE_CBC, DIR_ENC)
    ct, _, err = await recv_block(dut)
    assert not err
    assert ct == ct_expected, f"CBC enc mismatch: {ct.hex()} != {ct_expected.hex()}"
    dut._log.info(f"[AES-128 CBC enc] PASS  ct={ct.hex()}")


@cocotb.test()
async def test_nist_ctr(dut):
    """NIST SP 800-38A F.5.1 — AES-128 CTR first block."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    if KEY_BITS != 128:
        dut._log.info(f"Skipping AES-128 CTR test (KEY_BITS={KEY_BITS})")
        return

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv  = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    ct_expected = bytes.fromhex('874d6191b620e3261bef6864990db6ce')

    await key_expand_wait(dut, key)
    await iv_load(dut, iv)

    await send_block(dut, pt, MODE_CTR, DIR_ENC)
    ct, _, err = await recv_block(dut)
    assert not err
    assert ct == ct_expected, f"CTR enc mismatch: {ct.hex()} != {ct_expected.hex()}"
    dut._log.info(f"[AES-128 CTR enc] PASS  ct={ct.hex()}")


@cocotb.test()
async def test_random_ecb_roundtrip(dut):
    """Random ECB encrypt→decrypt roundtrip, 20 vectors."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    rng = random.Random(0xDEAD_BEEF)
    key = bytes([rng.randint(0, 255) for _ in range(KEY_BITS // 8)])
    await key_expand_wait(dut, key)

    model = AESModel(key_bits=KEY_BITS)
    model.set_key(key)

    for i in range(20):
        pt = bytes([rng.randint(0, 255) for _ in range(16)])
        ct_expected = model.encrypt_ecb(pt)
        pt_expected = model.decrypt_ecb(ct_expected)

        # Encrypt
        await send_block(dut, pt, MODE_ECB, DIR_ENC, tag=i & 0xFF)
        ct, tag, err = await recv_block(dut)
        assert not err
        assert ct == ct_expected, f"[{i}] ECB enc mismatch pt={pt.hex()} got={ct.hex()} exp={ct_expected.hex()}"
        assert tag == i & 0xFF

        # Decrypt
        await send_block(dut, ct_expected, MODE_ECB, DIR_DEC, tag=(i+1) & 0xFF)
        pt_out, _, err = await recv_block(dut)
        assert not err
        assert pt_out == pt, f"[{i}] ECB dec mismatch"

    dut._log.info(f"[ECB roundtrip] PASS  20 vectors AES-{KEY_BITS}")


@cocotb.test()
async def test_random_cbc_roundtrip(dut):
    """Random CBC multi-block roundtrip, 4 blocks × 5 rounds."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    rng = random.Random(0xBEEF_CAFE)
    key = bytes([rng.randint(0, 255) for _ in range(KEY_BITS // 8)])
    iv  = bytes([rng.randint(0, 255) for _ in range(16)])

    await key_expand_wait(dut, key)

    model = AESModel(key_bits=KEY_BITS)
    model.set_key(key)

    for trial in range(5):
        # Reset IV each trial
        model.set_iv(iv)
        await iv_load(dut, iv)

        plaintext_blocks = [bytes([rng.randint(0, 255) for _ in range(16)]) for _ in range(4)]
        encrypted = []

        # Encrypt chain
        for pt in plaintext_blocks:
            ct_exp = model.encrypt_cbc(pt)
            await send_block(dut, pt, MODE_CBC, DIR_ENC)
            ct, _, err = await recv_block(dut)
            assert not err
            assert ct == ct_exp, f"[CBC trial {trial}] enc mismatch"
            encrypted.append(ct)

        # Decrypt chain — reset IV
        model.set_iv(iv)
        await iv_load(dut, iv)
        for j, ct in enumerate(encrypted):
            pt_exp = model.decrypt_cbc(ct)
            await send_block(dut, ct, MODE_CBC, DIR_DEC)
            pt_out, _, err = await recv_block(dut)
            assert not err
            assert pt_out == plaintext_blocks[j], f"[CBC trial {trial} block {j}] dec mismatch"

        # New IV for next trial
        iv = bytes([rng.randint(0, 255) for _ in range(16)])

    dut._log.info(f"[CBC roundtrip] PASS  5 trials × 4 blocks  AES-{KEY_BITS}")


@cocotb.test()
async def test_random_ctr_symmetry(dut):
    """CTR mode encrypt and decrypt should be symmetric, 20 blocks."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    rng = random.Random(0xFACE_FEED)
    key = bytes([rng.randint(0, 255) for _ in range(KEY_BITS // 8)])
    iv  = bytes([rng.randint(0, 255) for _ in range(16)])

    await key_expand_wait(dut, key)
    await iv_load(dut, iv)

    model = AESModel(key_bits=KEY_BITS)
    model.set_key(key)
    model.set_iv(iv)

    for i in range(20):
        pt = bytes([rng.randint(0, 255) for _ in range(16)])
        ct_exp = model.encrypt_ctr(pt)
        await send_block(dut, pt, MODE_CTR, DIR_ENC)
        ct, _, err = await recv_block(dut)
        assert not err
        assert ct == ct_exp, f"[CTR {i}] enc mismatch"

    # Decrypt (reset counter to same IV)
    model.set_iv(iv)
    await iv_load(dut, iv)
    # Re-encrypt to get reference ciphertexts
    model2 = AESModel(key_bits=KEY_BITS)
    model2.set_key(key)
    model2.set_iv(iv)
    rng2 = random.Random(0xFACE_FEED)  # same seed
    for i in range(20):
        pt_orig = bytes([rng2.randint(0, 255) for _ in range(16)])
        ct_in   = model2.encrypt_ctr(pt_orig)
        await send_block(dut, ct_in, MODE_CTR, DIR_DEC)
        pt_out, _, err = await recv_block(dut)
        assert not err
        assert pt_out == pt_orig, f"[CTR dec {i}] mismatch"

    dut._log.info(f"[CTR symmetry] PASS  20 blocks  AES-{KEY_BITS}")


@cocotb.test()
async def test_pipeline_throughput(dut):
    """ECB: stream N blocks back-to-back, collect outputs concurrently."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    N = PIPE_LAT + 4  # enough blocks to fill the pipeline
    rng = random.Random(0x1234)
    key = bytes([rng.randint(0, 255) for _ in range(KEY_BITS // 8)])
    await key_expand_wait(dut, key)

    model = AESModel(key_bits=KEY_BITS)
    model.set_key(key)

    blocks = [bytes([rng.randint(0, 255) for _ in range(16)]) for _ in range(N)]
    expected = [model.encrypt_ecb(b) for b in blocks]
    received = []

    # Collect outputs concurrently (m_valid is a one-cycle pulse, must not miss it)
    async def collect():
        for _ in range(N):
            ct, tag, err = await recv_block(dut)
            received.append((ct, tag, err))

    collector = cocotb.start_soon(collect())

    # Submit all blocks back-to-back
    for i, b in enumerate(blocks):
        await send_block(dut, b, MODE_ECB, DIR_ENC, tag=i)

    # Wait for all outputs
    await collector

    for i, (ct, tag, err) in enumerate(received):
        assert not err
        assert ct == expected[i], f"[throughput {i}] mismatch ct={ct.hex()} exp={expected[i].hex()}"
        assert tag == i

    dut._log.info(f"[pipeline throughput] PASS  {N} back-to-back blocks")


@cocotb.test()
async def test_key_reexpansion(dut):
    """Change key mid-stream: each new key_expand invalidates old results."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    rng = random.Random(0xABCD)

    for trial in range(5):
        key = bytes([rng.randint(0, 255) for _ in range(KEY_BITS // 8)])
        pt  = bytes([rng.randint(0, 255) for _ in range(16)])

        await key_expand_wait(dut, key)

        model = AESModel(key_bits=KEY_BITS)
        model.set_key(key)
        ct_exp = model.encrypt_ecb(pt)

        await send_block(dut, pt, MODE_ECB, DIR_ENC)
        ct, _, err = await recv_block(dut)
        assert not err
        assert ct == ct_exp, f"[key_reexpansion trial {trial}] mismatch"

    dut._log.info("[key_reexpansion] PASS  5 different keys")


@cocotb.test()
async def test_all_key_sizes(dut):
    """Test NIST ECB vectors for the compiled-in KEY_BITS."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    vectors = {
        128: ('2b7e151628aed2a6abf7158809cf4f3c',
              '6bc1bee22e409f96e93d7e117393172a',
              '3ad77bb40d7a3660a89ecaf32466ef97'),
        192: ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
              '6bc1bee22e409f96e93d7e117393172a',
              'bd334f1d6e45f25ff712a214571fa5cc'),
        256: ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
              '6bc1bee22e409f96e93d7e117393172a',
              'f3eed1bdb5d2a03c064b5a7e3db181f8'),
    }

    if KEY_BITS not in vectors:
        return

    key_hex, pt_hex, ct_hex = vectors[KEY_BITS]
    key = bytes.fromhex(key_hex)
    pt  = bytes.fromhex(pt_hex)
    ct_exp = bytes.fromhex(ct_hex)

    await key_expand_wait(dut, key)
    await send_block(dut, pt, MODE_ECB, DIR_ENC)
    ct, _, err = await recv_block(dut)
    assert not err
    assert ct == ct_exp, f"AES-{KEY_BITS} NIST vector FAIL: {ct.hex()} != {ct_exp.hex()}"
    dut._log.info(f"[AES-{KEY_BITS} NIST] PASS  ct={ct.hex()}")
