# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
AES LiteX Module
=================
Directly instantiates aes_top.sv and wires it to LiteX CSR registers.

Supports AES-128/192/256, ECB/CBC/CTR, encrypt/decrypt.
Key, IV, and data are exposed as 32-bit CSR words (big-endian packing).

CSR registers:
  ctrl        [0]=start [8]=key_expand [9]=iv_load [5:4]=mode [6]=dir (WO)
  status      [0]=done  [1]=busy [2]=key_ready [3]=iv_ready (RO)
  tag         [7:0] transaction tag
  key0..key7  Key words [31:0]..[255:224] (WO, key7 only if AES-256)
  iv0..iv3    IV  words [31:0]..[127:96]  (WO)
  din0..din3  Plaintext/ciphertext in     (WO)
  dout0..dout3 Ciphertext/plaintext out   (RO, valid when done=1)
  version     IP version (RO)
  pipe_lat    Pipeline latency = N_ROUNDS+1 (RO)
  key_size    Key size in bits (RO)
"""

from migen import *
from litex.soc.interconnect.csr import *
import os

AES_RTL_DIR = os.path.join(os.path.dirname(__file__), '../rtl')

# Must match aes_pkg.sv defaults
MODE_ECB = 0
MODE_CBC = 1
MODE_CTR = 2
DIR_ENC  = 0
DIR_DEC  = 1

IP_VERSION = 0x00010000


def _n_rounds(key_bits: int) -> int:
    return {128: 10, 192: 12, 256: 14}[key_bits]


class AES(Module, AutoCSR):
    def __init__(self, platform, key_bits: int = 128, sys_clk_freq: float = 100e6):
        assert key_bits in (128, 192, 256)
        self.key_bits = key_bits
        n_rounds = _n_rounds(key_bits)
        pipe_lat = n_rounds + 1
        n_key_words = key_bits // 32

        # ── Add RTL sources ───────────────────────────────────────────────
        for f in ['aes_pkg.sv', 'aes_key_expand.sv', 'aes_core.sv', 'aes_top.sv']:
            platform.add_source(os.path.join(AES_RTL_DIR, f))

        # Pass KEY_BITS define so aes_pkg.sv computes N_ROUNDS/N_KEY_WORDS correctly
        # Note: LiteX calls .format() on platform_commands, so {{{{ }}}} → {{ }} → { }
        platform.add_platform_command(
            f"set_property verilog_define {{{{AES_KEY_BITS={key_bits}}}}} [get_filesets sources_1]"
        )

        # ── Control CSRs (write-only from software perspective) ──────────
        self.ctrl    = CSRStorage(10, name="ctrl",
                                  description="[0]=start [8]=key_expand [9]=iv_load [6]=dir [5:4]=mode")
        self.tag     = CSRStorage(8,  name="tag",  description="Transaction tag")

        # Key words (MSB first; key0=[31:0])
        self.key0 = CSRStorage(32, name="key0")
        self.key1 = CSRStorage(32, name="key1")
        self.key2 = CSRStorage(32, name="key2")
        self.key3 = CSRStorage(32, name="key3")
        if key_bits >= 192:
            self.key4 = CSRStorage(32, name="key4")
            self.key5 = CSRStorage(32, name="key5")
        if key_bits >= 256:
            self.key6 = CSRStorage(32, name="key6")
            self.key7 = CSRStorage(32, name="key7")

        # IV words
        self.iv0 = CSRStorage(32, name="iv0")
        self.iv1 = CSRStorage(32, name="iv1")
        self.iv2 = CSRStorage(32, name="iv2")
        self.iv3 = CSRStorage(32, name="iv3")

        # Data in words
        self.din0 = CSRStorage(32, name="din0")
        self.din1 = CSRStorage(32, name="din1")
        self.din2 = CSRStorage(32, name="din2")
        self.din3 = CSRStorage(32, name="din3")

        # Status / output CSRs
        self.status = CSRStatus(4,  name="status",
                                description="[0]=done [1]=busy [2]=key_ready [3]=iv_ready")
        self.dout0  = CSRStatus(32, name="dout0")
        self.dout1  = CSRStatus(32, name="dout1")
        self.dout2  = CSRStatus(32, name="dout2")
        self.dout3  = CSRStatus(32, name="dout3")

        # Constant info CSRs
        self.version  = CSRStatus(32, name="version",  description="IP version")
        self.pipe_lat = CSRStatus(32, name="pipe_lat", description="Pipeline latency")
        self.key_size = CSRStatus(32, name="key_size", description="Key size in bits")

        self.comb += [
            self.version.status.eq(IP_VERSION),
            self.pipe_lat.status.eq(pipe_lat),
            self.key_size.status.eq(key_bits),
        ]

        # ── Internal signals ──────────────────────────────────────────────
        key_val = Signal(key_bits)
        iv_val  = Signal(128)
        din_val = Signal(128)
        dout_val = Signal(128)

        key_expand_pulse = Signal()
        iv_load_pulse    = Signal()
        start_pulse      = Signal()
        key_ready        = Signal()
        s_ready          = Signal()
        m_valid          = Signal()
        m_data           = Signal(128)
        m_tag            = Signal(8)
        m_err            = Signal()

        # Pack key CSR words → big-endian 128/192/256-bit key
        # key0 = bits [31:0], key1 = bits [63:32], ...
        # aes_top expects key_in[KEY_BITS-1:0] packed MSB-first for first 32b
        # BUT aes_key_expand loads W[0] = key_in[KEY_BITS-1 -: 32]
        # So key_in[KEY_BITS-1:KEY_BITS-32] = first 32-bit key word
        # We store key0 = bits[31:0] → it is the LAST 32 bits of key_in
        # key_in = {key0, key1, key2, key3, ...} → No, let's keep LSB at bottom
        # aes_key_expand: W[i] = key_in[KEY_BITS-1 - 32*i -: 32]
        # So W[0] = key_in[KEY_BITS-1:KEY_BITS-32]  ← MSB end
        #    W[1] = key_in[KEY_BITS-33:KEY_BITS-64]
        # We want key0 CSR to correspond to key bytes 0..3 (most significant)
        # So key_in = {key0, key1, key2, key3} for AES-128
        if key_bits == 128:
            self.comb += key_val.eq(Cat(self.key3.storage, self.key2.storage,
                                        self.key1.storage, self.key0.storage))
        elif key_bits == 192:
            self.comb += key_val.eq(Cat(self.key5.storage, self.key4.storage,
                                        self.key3.storage, self.key2.storage,
                                        self.key1.storage, self.key0.storage))
        else:  # 256
            self.comb += key_val.eq(Cat(self.key7.storage, self.key6.storage,
                                        self.key5.storage, self.key4.storage,
                                        self.key3.storage, self.key2.storage,
                                        self.key1.storage, self.key0.storage))

        self.comb += iv_val.eq( Cat(self.iv3.storage,  self.iv2.storage,
                                    self.iv1.storage,  self.iv0.storage))
        self.comb += din_val.eq(Cat(self.din3.storage, self.din2.storage,
                                    self.din1.storage, self.din0.storage))

        # ── Pulse generation from CSR writes ─────────────────────────────
        done     = Signal()
        busy     = Signal()
        iv_ready = Signal()

        self.sync += [
            key_expand_pulse.eq(0),
            iv_load_pulse.eq(0),
            start_pulse.eq(0),
            If(self.ctrl.re,
                If(self.ctrl.storage[8], key_expand_pulse.eq(1)),
                If(self.ctrl.storage[9], iv_load_pulse.eq(1)),
                If(self.ctrl.storage[0], start_pulse.eq(1)),
            ),
            If(iv_load_pulse, iv_ready.eq(1)),
        ]

        # ── AES core instance ─────────────────────────────────────────────
        params = {
            'p_KEY_BITS'   : key_bits,
            'i_clk'        : ClockSignal(),
            'i_rst_n'      : ~ResetSignal(),
            'i_s_key_in'   : key_val,
            'i_s_key_expand': key_expand_pulse,
            'o_key_ready'  : key_ready,
            'i_s_iv'       : iv_val,
            'i_s_iv_load'  : iv_load_pulse,
            'i_s_valid'    : start_pulse,
            'o_s_ready'    : s_ready,
            'i_s_data'     : din_val,
            'i_s_mode'     : self.ctrl.storage[4:6],
            'i_s_dir'      : self.ctrl.storage[6],
            'i_s_tag'      : self.tag.storage,
            'o_m_valid'    : m_valid,
            'i_m_ready'    : 1,
            'o_m_data'     : m_data,
            'o_m_tag'      : m_tag,
            'o_m_err'      : m_err,
        }
        self.specials += Instance("aes_top", **params)

        # ── Latch output when m_valid pulses ──────────────────────────────
        self.sync += [
            If(start_pulse,
                done.eq(0),
                busy.eq(1),
            ),
            If(m_valid,
                done.eq(1),
                busy.eq(0),
                self.dout0.status.eq(m_data[96:128]),
                self.dout1.status.eq(m_data[64:96]),
                self.dout2.status.eq(m_data[32:64]),
                self.dout3.status.eq(m_data[0:32]),
            ),
        ]

        self.comb += self.status.status.eq(
            Cat(done, busy, key_ready, iv_ready)
        )

        # ── IRQ (optional) ────────────────────────────────────────────────
        self.irq = Signal()
        done_prev = Signal()
        self.sync += [
            done_prev.eq(done),
            self.irq.eq(done & ~done_prev),
        ]
