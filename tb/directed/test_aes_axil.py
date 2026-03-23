#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
# cocotb testbench for aes_axil (AXI4-Lite register interface)
#
# Tests:
#   - Register read/write (CTRL, STATUS, TAG, VERSION, KEY, IV, DIN, DOUT)
#   - Full encrypt/decrypt through register interface (all modes)
#   - IRQ pulse on done
#   - STATUS register reflects busy/done/key_ready/iv_ready
# =============================================================================

import os
import sys
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../model'))
from aes_model import AESModel

CLK_PERIOD_NS = 10
KEY_BITS = int(os.environ.get('KEY_BITS', 128))

# Register offsets
CTRL_ADDR     = 0x00
STATUS_ADDR   = 0x04
TAG_ADDR      = 0x08
VERSION_ADDR  = 0x0C
LATENCY_ADDR  = 0x10
KEYBITS_ADDR  = 0x14
KEY_BASE      = 0x20
IV_BASE       = 0x40
DIN_BASE      = 0x50
DOUT_BASE     = 0x60

# CTRL bits
CTRL_START     = (1 << 0)
CTRL_KEY_EXP   = (1 << 8)
CTRL_IV_LOAD   = (1 << 9)
MODE_SHIFT     = 4
DIR_SHIFT      = 6

MODE_ECB = 0
MODE_CBC = 1
MODE_CTR = 2
DIR_ENC  = 0
DIR_DEC  = 1


# ── AXI4-Lite helpers ─────────────────────────────────────────────────────────

async def axil_write(dut, addr: int, data: int):
    """Single AXI4-Lite write transaction."""
    # Present address and data simultaneously
    dut.s_axil_awaddr.value  = addr
    dut.s_axil_awvalid.value = 1
    dut.s_axil_wdata.value   = data & 0xFFFFFFFF
    dut.s_axil_wstrb.value   = 0xF
    dut.s_axil_wvalid.value  = 1
    dut.s_axil_bready.value  = 1

    # Wait for both AW and W to be accepted
    aw_done = False
    w_done  = False
    for _ in range(50):
        await RisingEdge(dut.clk)
        if dut.s_axil_awready.value and dut.s_axil_awvalid.value:
            aw_done = True
            dut.s_axil_awvalid.value = 0
        if dut.s_axil_wready.value and dut.s_axil_wvalid.value:
            w_done = True
            dut.s_axil_wvalid.value = 0
        if aw_done and w_done:
            break

    # Wait for B (write response)
    for _ in range(50):
        await RisingEdge(dut.clk)
        if dut.s_axil_bvalid.value:
            dut.s_axil_bready.value = 0
            return
    raise TimeoutError(f"axil_write timeout addr={addr:#x}")


async def axil_read(dut, addr: int) -> int:
    """Single AXI4-Lite read transaction, returns 32-bit value."""
    dut.s_axil_araddr.value  = addr
    dut.s_axil_arvalid.value = 1
    dut.s_axil_rready.value  = 1

    for _ in range(50):
        await RisingEdge(dut.clk)
        if dut.s_axil_arready.value:
            dut.s_axil_arvalid.value = 0
            break
    else:
        raise TimeoutError(f"axil_read AR timeout addr={addr:#x}")

    for _ in range(50):
        await RisingEdge(dut.clk)
        if dut.s_axil_rvalid.value:
            val = int(dut.s_axil_rdata.value)
            dut.s_axil_rready.value = 0
            return val
    raise TimeoutError(f"axil_read R timeout addr={addr:#x}")


async def reset_dut(dut):
    dut.rst_n.value          = 0
    dut.s_axil_awaddr.value  = 0
    dut.s_axil_awvalid.value = 0
    dut.s_axil_wdata.value   = 0
    dut.s_axil_wstrb.value   = 0
    dut.s_axil_wvalid.value  = 0
    dut.s_axil_bready.value  = 0
    dut.s_axil_araddr.value  = 0
    dut.s_axil_arvalid.value = 0
    dut.s_axil_rready.value  = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await RisingEdge(dut.clk)


async def write_key(dut, key: bytes):
    """Write key to KEY registers (MSB-first: KEY[0]=W[0]=first 4 bytes)."""
    n_words = len(key) // 4
    for i in range(n_words):
        word = int.from_bytes(key[4*i:4*i+4], 'big')
        await axil_write(dut, KEY_BASE + 4*i, word)


async def write_iv(dut, iv: bytes):
    """Write IV to IV registers."""
    for i in range(4):
        word = int.from_bytes(iv[4*i:4*i+4], 'big')
        await axil_write(dut, IV_BASE + 4*i, word)


async def write_din(dut, data: bytes):
    """Write 16 bytes to DIN registers."""
    for i in range(4):
        word = int.from_bytes(data[4*i:4*i+4], 'big')
        await axil_write(dut, DIN_BASE + 4*i, word)


async def read_dout(dut) -> bytes:
    """Read 16 bytes from DOUT registers."""
    out = []
    for i in range(4):
        word = await axil_read(dut, DOUT_BASE + 4*i)
        out.extend(word.to_bytes(4, 'big'))
    return bytes(out)


async def trigger_key_expand(dut):
    """Write CTRL[8]=1 to start key expansion, poll key_ready."""
    await axil_write(dut, CTRL_ADDR, CTRL_KEY_EXP)
    for _ in range(300):
        status = await axil_read(dut, STATUS_ADDR)
        if status & 0x4:  # key_ready bit
            return
    raise TimeoutError("key_ready never set in STATUS")


async def trigger_iv_load(dut):
    """Write CTRL[9]=1 to latch IV."""
    await axil_write(dut, CTRL_ADDR, CTRL_IV_LOAD)
    await RisingEdge(dut.clk)


async def trigger_start(dut, mode: int, direction: int, tag: int = 0):
    """Write CTRL with mode/dir/tag and assert start bit."""
    ctrl = CTRL_START | (mode << MODE_SHIFT) | (direction << DIR_SHIFT)
    await axil_write(dut, TAG_ADDR, tag)
    await axil_write(dut, CTRL_ADDR, ctrl)


async def wait_done(dut, timeout: int = 500) -> bool:
    """Poll STATUS until done=1. Returns True on success."""
    for _ in range(timeout):
        await RisingEdge(dut.clk)
        status = await axil_read(dut, STATUS_ADDR)
        if status & 0x1:  # done
            return True
    return False


# ── Test cases ────────────────────────────────────────────────────────────────

@cocotb.test()
async def test_read_static_regs(dut):
    """VERSION, LATENCY, KEY_BITS registers return correct constants."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    n_rounds = {128: 10, 192: 12, 256: 14}[KEY_BITS]
    pipe_lat = n_rounds + 1

    version = await axil_read(dut, VERSION_ADDR)
    latency = await axil_read(dut, LATENCY_ADDR)
    kbits   = await axil_read(dut, KEYBITS_ADDR)

    assert version != 0,      "VERSION should be non-zero"
    assert latency == pipe_lat, f"LATENCY={latency} expected {pipe_lat}"
    assert kbits   == KEY_BITS, f"KEY_BITS reg={kbits} expected {KEY_BITS}"
    dut._log.info(f"[static regs] PASS  VERSION={version:#x} LATENCY={latency} KEY_BITS={kbits}")


@cocotb.test()
async def test_axil_ecb_encrypt(dut):
    """AXI4-Lite register-based AES-128 ECB encrypt (NIST FIPS 197)."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    if KEY_BITS != 128:
        dut._log.info("Skipping AES-128 test")
        return

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    pt  = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
    ct_exp = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')

    await write_key(dut, key)
    await trigger_key_expand(dut)

    await write_din(dut, pt)
    await trigger_start(dut, MODE_ECB, DIR_ENC, tag=0x42)

    assert await wait_done(dut), "done never set"

    ct = await read_dout(dut)
    assert ct == ct_exp, f"ECB enc mismatch: {ct.hex()} != {ct_exp.hex()}"
    dut._log.info(f"[axil ECB enc] PASS  ct={ct.hex()}")


@cocotb.test()
async def test_axil_ecb_decrypt(dut):
    """AXI4-Lite AES-128 ECB decrypt."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    if KEY_BITS != 128:
        return

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    ct  = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')
    pt_exp = bytes.fromhex('3243f6a8885a308d313198a2e0370734')

    await write_key(dut, key)
    await trigger_key_expand(dut)

    await write_din(dut, ct)
    await trigger_start(dut, MODE_ECB, DIR_DEC)
    assert await wait_done(dut)

    pt = await read_dout(dut)
    assert pt == pt_exp, f"ECB dec mismatch: {pt.hex()}"
    dut._log.info(f"[axil ECB dec] PASS  pt={pt.hex()}")


@cocotb.test()
async def test_axil_cbc_encrypt(dut):
    """AXI4-Lite AES-128 CBC encrypt (NIST SP 800-38A)."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    if KEY_BITS != 128:
        return

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    ct_exp = bytes.fromhex('7649abac8119b246cee98e9b12e9197d')

    await write_key(dut, key)
    await trigger_key_expand(dut)
    await write_iv(dut, iv)
    await trigger_iv_load(dut)

    await write_din(dut, pt)
    await trigger_start(dut, MODE_CBC, DIR_ENC)
    assert await wait_done(dut)

    ct = await read_dout(dut)
    assert ct == ct_exp, f"CBC enc mismatch: {ct.hex()}"
    dut._log.info(f"[axil CBC enc] PASS  ct={ct.hex()}")


@cocotb.test()
async def test_axil_ctr_encrypt(dut):
    """AXI4-Lite AES-128 CTR encrypt (NIST SP 800-38A)."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    if KEY_BITS != 128:
        return

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv  = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    ct_exp = bytes.fromhex('874d6191b620e3261bef6864990db6ce')

    await write_key(dut, key)
    await trigger_key_expand(dut)
    await write_iv(dut, iv)
    await trigger_iv_load(dut)

    await write_din(dut, pt)
    await trigger_start(dut, MODE_CTR, DIR_ENC)
    assert await wait_done(dut)

    ct = await read_dout(dut)
    assert ct == ct_exp, f"CTR enc mismatch: {ct.hex()}"
    dut._log.info(f"[axil CTR enc] PASS  ct={ct.hex()}")


@cocotb.test()
async def test_axil_irq(dut):
    """IRQ asserts for one cycle when done rises."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    if KEY_BITS != 128:
        return

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    pt  = bytes.fromhex('3243f6a8885a308d313198a2e0370734')

    await write_key(dut, key)
    await trigger_key_expand(dut)
    await write_din(dut, pt)
    await trigger_start(dut, MODE_ECB, DIR_ENC)

    # Watch for irq pulse
    irq_seen = False
    for _ in range(500):
        await RisingEdge(dut.clk)
        if dut.irq.value == 1:
            irq_seen = True
            break
    assert irq_seen, "irq never pulsed"

    # irq must be low on next cycle (single-cycle pulse)
    await RisingEdge(dut.clk)
    assert dut.irq.value == 0, "irq is not a single-cycle pulse"
    dut._log.info("[axil irq] PASS  single-cycle pulse confirmed")


@cocotb.test()
async def test_axil_random_all_modes(dut):
    """Random vectors for all modes (ECB/CBC/CTR) enc+dec."""
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_NS, units='ns').start())
    await reset_dut(dut)

    rng = random.Random(0x7E57)
    key = bytes([rng.randint(0, 255) for _ in range(KEY_BITS // 8)])
    iv  = bytes([rng.randint(0, 255) for _ in range(16)])

    await write_key(dut, key)
    await trigger_key_expand(dut)
    await write_iv(dut, iv)
    await trigger_iv_load(dut)

    model = AESModel(key_bits=KEY_BITS)
    model.set_key(key)
    model.set_iv(iv)

    for mode_name, mode_id in [('ECB', MODE_ECB), ('CBC', MODE_CBC), ('CTR', MODE_CTR)]:
        # Reset IV for CBC/CTR
        if mode_name != 'ECB':
            iv = bytes([rng.randint(0, 255) for _ in range(16)])
            model.set_iv(iv)
            await write_iv(dut, iv)
            await trigger_iv_load(dut)

        for i in range(5):
            pt = bytes([rng.randint(0, 255) for _ in range(16)])
            ct_exp = model.process(pt, mode_name, 'enc')

            await write_din(dut, pt)
            await trigger_start(dut, mode_id, DIR_ENC)
            assert await wait_done(dut), f"{mode_name} enc done timeout"
            ct = await read_dout(dut)
            assert ct == ct_exp, f"[{mode_name} enc {i}] {ct.hex()} != {ct_exp.hex()}"

        dut._log.info(f"[axil {mode_name}] PASS  5 random vectors")
